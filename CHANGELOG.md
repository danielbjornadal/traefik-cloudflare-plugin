# Changelog

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
