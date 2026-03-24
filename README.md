# Cloudflare Real-Client-IP Middleware

A Traefik middleware plugin that securely derives the **real client IP** when Cloudflare (or another trusted reverse proxy) sits in front of Traefik, or when clients connect directly. It prevents header spoofing and aligns **`X-Forwarded-For`** and **`X-Real-IP`** so downstream middlewares such as `ipAllowList` see one consistent address.

## What Problem Does This Solve?

1. **IP spoofing**: Untrusted clients cannot forge forwarded headers; only peers in your trusted CIDRs are allowed to supply them.
2. **Wrong “real IP” behind Cloudflare**: Traefik may otherwise treat the last proxy hop as the client. This plugin prefers **`CF-Connecting-IP`** when the TCP peer is a trusted Cloudflare (or other) proxy.
3. **`ipAllowList` / `depth: 1`**: After normalization, the first (and only) `X-Forwarded-For` value is the intended client IP for allow/deny rules.

## How It Works

**Trusted peer** (`RemoteAddr` is inside the merged trusted CIDR list):

1. Resolve client IP: valid **`CF-Connecting-IP`** first, else the **leftmost** parseable IP in **`X-Forwarded-For`**.
2. If a client IP was resolved, set **`X-Forwarded-For`** and **`X-Real-IP`** to that value (single hop).
3. If nothing could be resolved, headers are not modified.

**Untrusted peer**: set **`X-Forwarded-For`** and **`X-Real-IP`** to the TCP client address (anti-spoofing).

**Trusted CIDR list** is built from:

- **`trustedProxyRanges`** (always merged in), plus
- If **`fetchCloudflareRanges: true`**, the IPv4/IPv6 CIDRs from Cloudflare’s public API (`https://api.cloudflare.com/client/v4/ips`).

If the fetch fails and **`cloudflareRangesFetchRequired`** is `false` (default), a warning is logged and an **embedded** snapshot of Cloudflare ranges is used so Traefik still starts. If fetch is **required**, initialization fails instead.

## Upgrading from v1.x

v2 **normalizes** headers for trusted proxies by default. For the old behavior (leave `X-Forwarded-For` unchanged when the peer is trusted), set:

```yaml
preserveForwardedForWhenTrusted: true
```

See [CHANGELOG.md](CHANGELOG.md) for details.

## Installation

### Building the Plugin

```bash
git clone https://github.com/danielbjornadal/traefik-cloudflare-plugin.git
cd traefik-cloudflare-plugin
go build -buildmode=plugin -o traefik_cloudflare_plugin.so
```

### Traefik static config

```yaml
experimental:
  plugins:
    traefik_cloudflare_plugin:
      moduleName: github.com/danielbjornadal/traefik-cloudflare-plugin
      version: v2.0.0
```

## Configuration

### Recommended: fetch Cloudflare ranges + extra CIDRs

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: traefik-cloudflare-plugin
spec:
  plugin:
    traefik_cloudflare_plugin:
      fetchCloudflareRanges: true
      cloudflareRangesHTTPTimeout: 5s
      trustedProxyRanges:
        - 198.51.100.0/29
      directRanges:
        - 0.0.0.0/0
        - ::/0
      header: X-Forwarded-For
```

- **`trustedProxyRanges`**: extra trusted proxies (load balancers, corporate ingress, etc.) **in addition** to Cloudflare when fetch is enabled.
- **`cloudflareRangesFetchRequired: true`**: fail plugin init if the Cloudflare API cannot be read (no embedded fallback for that path).
- **`preserveForwardedForWhenTrusted: true`**: v1-compatible trusted path (no normalization).

### Fully static list (no HTTP fetch)

Same as before: set **`fetchCloudflareRanges: false`** (or omit it) and list all CIDRs under **`trustedProxyRanges`**.

### Legacy `header` field

If **`header`** is set to something other than `X-Forwarded-For` or `X-Real-IP`, that header is **also** set to the resolved client IP when normalizing.

**Note:** **`directRanges`** is accepted for compatibility but is not used at runtime yet.

## Usage

Attach this middleware **before** `ipAllowList`:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: myapp
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`example.com`)
      kind: Rule
      services:
        - name: myapp
          port: 80
      middlewares:
        - name: traefik-cloudflare-plugin
        - name: allowlist
```

### With IP allow list

Use **`ipStrategy.depth: 1`**; the first `X-Forwarded-For` entry is the normalized client IP.

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: allowlist
spec:
  ipAllowList:
    ipStrategy:
      depth: 1
    sourceRange:
      - 10.0.0.0/8
      - 192.168.0.0/16
```

## Security notes

### 1. Headers are trusted only for trusted TCP peers

The plugin uses the **immediate TCP client** (`RemoteAddr`) to decide whether `CF-Connecting-IP` and `X-Forwarded-For` may influence the resolved IP.

**Safe (typical Cloudflare path):** The connection to Traefik comes from `162.158.x.x` (inside your Cloudflare trusted ranges). Cloudflare sets `CF-Connecting-IP: 203.0.113.5`. The plugin normalizes to `203.0.113.5`.

**Safe (typical direct path):** A browser connects from `198.51.100.10` (not in trusted ranges). The client may send `CF-Connecting-IP: 10.0.0.1` or a forged `X-Forwarded-For`; those are **ignored**. Headers are set to `198.51.100.10`.

**Middleware order:** This middleware must run **before** `ipAllowList` (or any rule that reads `X-Forwarded-For` / `X-Real-IP`). Otherwise another layer may trust spoofed headers first.

### 2. Keep trusted CIDRs minimal

Anyone who can open a TCP connection **from** an address inside your trusted list can supply headers that the plugin will treat like a real proxy.

**Risky:** `trustedProxyRanges: [0.0.0.0/0, ::/0]` (or an enormous corporate supernet attackers can reach) makes **every** client “trusted,” so forged `CF-Connecting-IP` / leftmost `X-Forwarded-For` can impersonate any IP and **bypass an allowlist** that uses the normalized headers.

**Better:** Cloudflare’s published ranges (via **`fetchCloudflareRanges`** or a static list) plus **only** the CIDRs of **your** load balancers or ingress that legitimately terminate in front of Traefik (for example a small VIP range like `198.51.100.0/29`).

### 3. Optional fetch and dependencies

When **`fetchCloudflareRanges: true`**, the plugin calls Cloudflare’s public API **once at middleware init** using Go’s **`net/http`** only—no extra Go modules. That request does not run per request; it only builds the trusted CIDR list at startup (or on dynamic reload, depending on Traefik).

## FAQ

### Do I still need Traefik `forwardedHeaders.trustedIPs` if I use this plugin?

**Yes.** They are not obsolete.

| Mechanism | Role |
|-----------|------|
| **Entrypoint `forwardedHeaders.trustedIPs`** (e.g. on `websecure`) | Traefik’s **own** HTTP layer: when the **TCP peer** is in this list, Traefik may trust incoming `X-Forwarded-For` / `X-Real-IP` / `Forwarded` for **access logs**, built-in client detection, and how it handles those headers in the pipeline. |
| **This plugin’s `trustedProxyRanges`** (+ optional `fetchCloudflareRanges`) | Your middleware: decides whether `CF-Connecting-IP` / `X-Forwarded-For` may set the **normalized** client IP for **`ipAllowList`** and backends. |

The plugin does **not** reconfigure the entrypoint. Keep **`trustedIPs`** and the plugin’s trusted list **aligned** with the same real topology so Traefik core and your allowlists agree on who is a proxy.

**Ideally they should list the same kind of addresses** (see below)—not identical YAML if one side uses fetch and the other is static, but the **meaning** should match.

### What should “trusted proxy” CIDRs contain?

These lists answer: *“Which **source IPs** (as seen by Traefik on the socket) belong to **infrastructure that is allowed to speak for the real client** via headers?”*

**Include:**

1. **Cloudflare** – All published egress ranges if traffic is **Client → Cloudflare → Traefik**. Use Cloudflare’s official lists or enable **`fetchCloudflareRanges`** in the plugin and mirror the same ranges in **`trustedIPs`** (static or generated).
2. **Your own reverse proxies / load balancers** – The CIDR(s) or single IPs from which **your** LB, ingress controller, or corporate proxy connects **to Traefik** (VIP subnet, node subnet as seen by the pod, health-check sources if they forward traffic—only if they actually proxy and set headers correctly).

Example (documentation-only range, not a real network): if your public LB always appears as `198.51.100.0/29` to Traefik pods, add that **in addition** to Cloudflare ranges.

**Do not include:**

1. **End-user / “local client” ranges** – Visitor home IPs, mobile networks, or “everyone in our company” are **not** trusted proxies. Putting huge public or RFC1918 ranges here because “our users are internal” makes **anyone** who can reach Traefik from those addresses able to **forge** `CF-Connecting-IP` / `X-Forwarded-For` and **bypass** an `ipAllowList` that trusts the normalized headers.
2. **`0.0.0.0/0` or `::/0`** – Never as “trusted proxy” unless you intend **every** TCP client to be treated as a trusted header source (effectively disabling spoofing protection).
3. **Arbitrary RFC1918 supernets** (e.g. all of `10.0.0.0/8`) – Only if **every** address in that range can **only** reach Traefik through **controlled** proxies you list separately; otherwise you widen who can spoof headers.

**Where “allowed clients” go:** Restrict **who may access the app** with **`ipAllowList`** (or similar) using **`sourceRange`** on the **normalized** client IP—**after** this middleware. That is separate from “who is a proxy.”

### Quick checklist

- **Trusted proxy lists** (Traefik `trustedIPs` + plugin `trustedProxyRanges` / fetch): Cloudflare (if used) + **narrow** CIDRs for **your** L7/L4 front ends.
- **Allowlist / denylist** (`ipAllowList`, firewalls, app logic): **Real client** IPs or networks you want to permit or block **after** normalization.

## Cloudflare IP ranges

- API used when **`fetchCloudflareRanges: true`**: [Cloudflare API /ips](https://api.cloudflare.com/client/v4/ips)
- Human-readable lists: [IPv4](https://www.cloudflare.com/ips-v4), [IPv6](https://www.cloudflare.com/ips-v6)

## License

Released under MIT License.

## Contributing

Contributions are welcome. Please open a Pull Request.

## Inspiration

Inspired by Traefik’s demo plugin pattern. See [Traefik Plugin Documentation](https://plugins.traefik.io/plugins/628c9ee2108ecc83915d7764/demo-plugin).
