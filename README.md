# Cloudflare Real-Client-IP Middleware

A Traefik middleware plugin that securely handles X-Forwarded-For headers when using Cloudflare as a reverse proxy. This plugin prevents IP spoofing attacks while ensuring proper IP detection for downstream middlewares like `ipAllowList`.

## What Problem Does This Solve?

When using Cloudflare as a reverse proxy in front of Traefik, you face a common security challenge:

1. **IP Spoofing Risk**: Malicious clients can forge `X-Forwarded-For` headers to appear to come from trusted IPs
2. **Incorrect IP Detection**: Downstream middlewares like `ipAllowList` may block legitimate traffic or allow malicious traffic
3. **Security Middleware Failures**: IP-based security rules become unreliable when headers can be spoofed

This plugin implements a secure model that:

- **Trusts only Cloudflare IPs** to set `X-Forwarded-For` headers
- **Overwrites spoofed headers** with the actual remote IP for untrusted sources
- **Ensures downstream middlewares** receive accurate client IP information

## How It Works

The plugin follows a simple but effective security model:

1. **Trusted Proxy Check**: If the request comes from a Cloudflare IP range, leave `X-Forwarded-For` untouched
2. **Untrusted Source Handling**: For all other sources, override `X-Forwarded-For` with the immediate remote address
3. **Header Injection**: If `X-Forwarded-For` is empty and the remote isn't trusted, inject the remote address

This prevents header spoofing while ensuring downstream middlewares always have accurate client IP information to work with.

## Installation

### Building the Plugin

```bash
# Clone the repository
git clone https://github.com/danielbjornadal/traefik-cloudflare-plugin.git
cd traefik-cloudflare-plugin

# Build the plugin
go build -buildmode=plugin -o traefik_cloudflare_plugin.so
```

### Traefik Configuration

Add the plugin to your Traefik configuration:

```yaml
# traefik.yml or dynamic configuration
experimental:
  plugins:
    traefik_cloudflare_plugin:
      moduleName: github.com/danielbjornadal/traefik-cloudflare-plugin
      version: v0.0.5
```

## Configuration

### Basic Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: traefik-cloudflare-plugin
spec:
  plugin:
    traefik_cloudflare_plugin:
      trustedProxyRanges:
        - 173.245.48.0/20 # Cloudflare IPv4
        - 103.21.244.0/22 # Cloudflare IPv4
        - 103.22.200.0/22 # Cloudflare IPv4
        - 103.31.4.0/22 # Cloudflare IPv4
        - 141.101.64.0/18 # Cloudflare IPv4
        - 108.162.192.0/18 # Cloudflare IPv4
        - 190.93.240.0/20 # Cloudflare IPv4
        - 188.114.96.0/20 # Cloudflare IPv4
        - 197.234.240.0/22 # Cloudflare IPv4
        - 198.41.128.0/17 # Cloudflare IPv4
        - 162.158.0.0/15 # Cloudflare IPv4
        - 104.16.0.0/13 # Cloudflare IPv4
        - 104.24.0.0/14 # Cloudflare IPv4
        - 172.64.0.0/13 # Cloudflare IPv4
        - 131.0.72.0/22 # Cloudflare IPv4
        - 2400:cb00::/32 # Cloudflare IPv6
        - 2606:4700::/32 # Cloudflare IPv6
        - 2803:f800::/32 # Cloudflare IPv6
        - 2405:b500::/32 # Cloudflare IPv6
        - 2405:8100::/32 # Cloudflare IPv6
        - 2a06:98c0::/29 # Cloudflare IPv6
        - 2c0f:f248::/32 # Cloudflare IPv6
      directRanges:
        - 0.0.0.0/0 # Allow any non-Cloudflare source to be treated as direct
      header: X-Forwarded-For
```

### Advanced Configuration

You can customize which IP ranges are treated as direct connections:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: traefik-cloudflare-plugin
spec:
  plugin:
    traefik_cloudflare_plugin:
      trustedProxyRanges:
        - 173.245.48.0/20 # Cloudflare IPv4
        - 103.21.244.0/22 # Cloudflare IPv4
        # ... other Cloudflare ranges
      directRanges:
        - 10.0.0.0/8 # Your internal network
        - 192.168.0.0/16 # Your internal network
        - 172.16.0.0/12 # Your internal network
      header: X-Forwarded-For # Optional, defaults to X-Forwarded-For
```

## Usage

### Router Configuration

Attach the middleware **before** your `ipAllowList` middleware:

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
        - name: traefik-cloudflare-plugin # Order matters!
        - name: allowlist
```

### With IP Allow List

Now your `ipAllowList` can safely use `ipStrategy.depth: 1`:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: allowlist
spec:
  ipAllowList:
    ipStrategy:
      depth: 1 # Safe to use depth 1 after traefik_cloudflare_plugin
    sourceRange:
      - 10.0.0.0/8
      - 192.168.0.0/16
```

## Security Benefits

1. **Prevents IP Spoofing**: Malicious clients cannot forge `X-Forwarded-For` headers
2. **Accurate IP Detection**: Downstream middlewares receive the real client IP
3. **Trusted Proxy Support**: Legitimate Cloudflare traffic is preserved
4. **No External Dependencies**: Uses only Go standard library for CIDR parsing

## Cloudflare IP Ranges

The plugin includes all current Cloudflare IP ranges. You can find the latest ranges at:

- [Cloudflare IPv4 Ranges](https://www.cloudflare.com/ips-v4)
- [Cloudflare IPv6 Ranges](https://www.cloudflare.com/ips-v6)

## License

Released under MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Inspiration

This plugin is inspired by Traefik's demo plugin pattern. See [Traefik Plugin Documentation](https://plugins.traefik.io/plugins/628c9ee2108ecc83915d7764/demo-plugin) for more information.
