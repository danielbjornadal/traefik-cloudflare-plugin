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
        - 193.53.88.88/29
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

1. **`CF-Connecting-IP` / `X-Forwarded-For` are only trusted when `RemoteAddr` is in your trusted CIDRs.**
2. Keep trusted ranges accurate; overly wide lists weaken spoofing protection.
3. Optional fetch uses the Go standard library HTTP client only (no extra modules).

## Cloudflare IP ranges

- API used when **`fetchCloudflareRanges: true`**: [Cloudflare API /ips](https://api.cloudflare.com/client/v4/ips)
- Human-readable lists: [IPv4](https://www.cloudflare.com/ips-v4), [IPv6](https://www.cloudflare.com/ips-v6)

## License

Released under MIT License.

## Contributing

Contributions are welcome. Please open a Pull Request.

## Inspiration

Inspired by Traefik’s demo plugin pattern. See [Traefik Plugin Documentation](https://plugins.traefik.io/plugins/628c9ee2108ecc83915d7764/demo-plugin).
