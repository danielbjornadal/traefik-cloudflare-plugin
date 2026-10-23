# Changelog

## v1.2.0

No configuration change is required. For Cloudflare → Traefik, Cloudflare → your load balancer → Traefik, and clients connecting directly, the resolved client IP is the same as in v1.1.0. See [Upgrading to v1.2.0](README.md#upgrading-to-v120) for each topology and how to verify it.

### Security

- A client can no longer choose its IP by sending `CF-Connecting-IP` through a trusted proxy that is not Cloudflare (for example your load balancer). `CF-Connecting-IP` is used only when the request came through a Cloudflare address, or when every hop is a trusted proxy (for example a load balancer that strips `X-Forwarded-For`).
- A client can no longer choose its IP by putting addresses at the start of `X-Forwarded-For`. The plugin reads `X-Forwarded-For` from right to left and takes the first address that is not a trusted proxy, which is the address your rightmost trusted proxy saw.
- Additional `X-Forwarded-For` header lines are read together with the first one, so a second header line cannot hide the real hop.
- Clients connecting directly can no longer pass forged `CF-Connecting-IP`, `CF-Connecting-IPv6`, `True-Client-IP` or `Forwarded` headers to backends; they are removed.
- On a trusted path, `True-Client-IP` is set to the resolved client, and `CF-Connecting-IP` is set to the resolved client (with `CF-Connecting-IPv6` removed) when the client did not come from Cloudflare.
- A trusted proxy that writes a non-address such as `unknown` into `X-Forwarded-For` no longer lets an entry to its left become the client; the client is that proxy.
- Requests whose peer address cannot be parsed no longer pass client IP headers through; they are removed.
- The Cloudflare range fetch validates the response and refuses redirects, so a malformed or redirected response cannot make very broad networks trusted.

### Behavior changes

- **Clients connecting directly to Traefik:** `X-Forwarded-For` and `X-Real-IP` are unchanged. Client-supplied `CF-Connecting-IP`, `CF-Connecting-IPv6`, `True-Client-IP` and `Forwarded` are removed. If a backend reads those headers on direct traffic, make it fall back to `X-Real-IP`.
- **Cloudflare peers missing from the trusted list:** treated as untrusted clients as before, and their `CF-Connecting-IP`, `CF-Connecting-IPv6` and `True-Client-IP` are removed. Enable `fetchCloudflareRanges` or list Cloudflare’s ranges in `trustedProxyRanges`.
- **Load balancer in front of Traefik without Cloudflare:** the client is the address the load balancer saw, not the leftmost `X-Forwarded-For` entry. Clients behind another proxy (for example a corporate proxy) resolve to that proxy unless it is added to `trustedProxyRanges`. Make sure the load balancer appends to `X-Forwarded-For` and is listed in the entrypoint’s `forwardedHeaders.trustedIPs`.
- **Requests from a trusted proxy without any client information** (no `X-Forwarded-For`, no valid `CF-Connecting-IP`, such as load balancer health checks): resolve to that proxy’s address instead of leaving headers unchanged. No action needed.
- **Proxies writing `unknown` or another non-address into `X-Forwarded-For`:** the client is the trusted proxy to the right of that entry instead of the leftmost parseable entry. Configure the trusted proxy that writes the entry to append the real address.
- **Zones using Cloudflare’s “Remove visitor IP headers”:** without `CF-Connecting-IP`, the client is the rightmost untrusted `X-Forwarded-For` entry instead of the leftmost. No action needed.
- **Backends reading `CF-Connecting-IP` or `CF-Connecting-IPv6` on a path that does not come through Cloudflare:** they see the resolved client in `CF-Connecting-IP` and no `CF-Connecting-IPv6`. Read `X-Real-IP` instead.
- **`preserveForwardedForWhenTrusted: true`:** trusted requests still pass through unchanged; untrusted requests also lose the forged headers listed above. A warning is logged at startup.

### Added

- `legacyClientIPResolution`: runs the v1.1.0 request handling unchanged, for operators who need time to adapt. It is spoofable and logs a warning; use it only temporarily.
- `allowedWorkerZones`: optional list of your Cloudflare zones. When set, a request whose `CF-Worker` header names another zone resolves to the Cloudflare address instead of `CF-Connecting-IP`. Off by default.
- Cloudflare range fetch: the response must contain only CIDRs no wider than IPv4 `/8` or IPv6 `/16`, otherwise it counts as a failed fetch. Redirects are refused. A successful fetch is reused for one hour by every router and reload in the same Traefik process; after a failure the API is not called again for one minute; when a refresh fails, the last good list is reused, which also satisfies `cloudflareRangesFetchRequired`.
- Cloudflare hops are recognized by the fetched list or, without one, by the embedded snapshot, also when they appear in `X-Forwarded-For` behind your load balancer. This recognition never adds addresses to the trusted list.
- `X-Forwarded-For` entries with a port (`192.0.2.1:5678`, `[2001:db8::1]:443`), as written by Azure Application Gateway, are accepted.
- Startup warnings, logged once per Traefik process, for `legacyClientIPResolution`, `preserveForwardedForWhenTrusted`, and trusted ranges wider than IPv4 `/8` or IPv6 `/16`. Warnings never stop Traefik.
- A warning, logged once per Traefik process on the first such request, when a trusted proxy that is not Cloudflare sends `CF-Connecting-IP` without `X-Forwarded-For`. This usually means the proxy is missing from the entrypoint's `forwardedHeaders.trustedIPs`, and clients that reach that proxy directly could set `CF-Connecting-IP`.

### Notes

- No configuration changes are required; v1.0.2 and v1.1.0 configurations load unchanged.
- `directRanges` is still accepted and ignored. It no longer appears in the examples.
- To roll back, pin `version: v1.1.0` in the static configuration, remove `legacyClientIPResolution` and `allowedWorkerZones` from the middleware configuration, and restart Traefik.

## v1.1.0

### Breaking changes

- When the immediate client is in **trusted proxy ranges** (e.g. Cloudflare), the middleware now **normalizes** `X-Forwarded-For` and `X-Real-IP` to a single canonical client IP:
  - Prefers `CF-Connecting-IP` when present and valid.
  - Otherwise uses the **leftmost** parseable address in `X-Forwarded-For`.
- If neither yields a valid IP, headers are left unchanged for that request.

To keep **v1 behavior** (leave `X-Forwarded-For` untouched for trusted proxies, do not set `X-Real-IP`), set:

```yaml
preserveForwardedForWhenTrusted: true
```

### Added

- `fetchCloudflareRanges`: if `true`, load Cloudflare CIDRs from `https://api.cloudflare.com/client/v4/ips` at middleware init and merge with `trustedProxyRanges`.
- `trustedProxyRanges`: always **additional** CIDRs (e.g. corporate LB) merged with fetched or manual lists.
- `cloudflareRangesHTTPTimeout`: HTTP timeout for the fetch (default `5s`).
- `cloudflareRangesFetchRequired`: if `true` with `fetchCloudflareRanges`, init **fails** when the API is unreachable or invalid.
- On fetch failure when not required: log a warning and use an **embedded** snapshot of Cloudflare ranges so Traefik still starts.
- Untrusted requests still reset spoofed headers; both `X-Forwarded-For` and `X-Real-IP` are set to the TCP client IP.

### Notes

- `directRanges` is accepted in config but remains unused at runtime (unchanged from v1).
- `header`: when set to a name other than `X-Forwarded-For` / `X-Real-IP`, that header is also set to the resolved client IP when normalizing (legacy compatibility).
