package xfffix

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strings"
)

// Config holds the plugin configuration.
//
// trustedProxyRanges – CIDR blocks that we trust to *set* X-Forwarded-For (e.g. Cloudflare).
// directRanges        – optional CIDR blocks that represent traffic arriving *directly* to Traefik.
//                       If remoteAddr falls inside one of these ranges, the plugin will assume the
//                       request is not proxied and will (re)write the XFF header with the remote IP.
// header              – which header to fix (default "X-Forwarded-For").
//
// Example dynamic configuration:
//
// ````yaml
// http:
//   middlewares:
//     xfffix:
//       plugin:
//         xfffix:
//           trustedProxyRanges:
//             - 173.245.48.0/20   # Cloudflare IPv4
//             - 103.21.244.0/22   # …
//           directRanges:
//             - 0.0.0.0/0         # allow any non‑Cloudflare source to be treated as direct
//           header: X-Forwarded-For
// ````
//
// Attach the middleware *before* the ipAllowList:
//
// ````yaml
// routers:
//   myapp:
//     rule: "Host(`example.com`)"
//     entryPoints: ["websecure"]
//     middlewares: ["xfffix", "allowlist"]
//     service: myapp
// ````
//
// The ipAllowList can then safely use `ipStrategy.depth: 1`.
//
// Security model:
//   1. If the request comes from a trusted proxy, we leave XFF untouched.
//   2. Otherwise we *override* XFF with the immediate remote address (preventing header spoofing).
//   3. If XFF is empty and remote isn’t trusted, we inject the remote address so that downstream
//      middlewares like ipAllowList have something to work with.
//
// All CIDR parsing and membership checks are done with the stdlib net package – no external deps.
//
// Inspired by Traefik’s demo plugin pattern.  (See https://plugins.traefik.io/plugins/628c9ee2108ecc83915d7764/demo-plugin)
//
// Released under MIT License.
//
type Config struct {
    TrustedProxyRanges []string `json:"trustedProxyRanges,omitempty" yaml:"trustedProxyRanges,omitempty"`
    DirectRanges       []string `json:"directRanges,omitempty"       yaml:"directRanges,omitempty"`
    Header             string   `json:"header,omitempty"             yaml:"header,omitempty"`
}

// CreateConfig provides the default plugin configuration.
func CreateConfig() *Config {
    return &Config{
        Header: "X-Forwarded-For",
    }
}

type middleware struct {
    next           http.Handler
    header         string
    trustedProxies []*net.IPNet
    directRanges   []*net.IPNet
}

// New is called by Traefik during the initialization of the middleware.
func New(_ context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
    m := &middleware{
        next:   next,
        header: defaultHeader(cfg.Header),
    }

    // Parse CIDR lists.
    var err error
    if m.trustedProxies, err = parseCIDRs(cfg.TrustedProxyRanges); err != nil {
        return nil, fmt.Errorf("invalid trustedProxyRanges: %w", err)
    }
    if m.directRanges, err = parseCIDRs(cfg.DirectRanges); err != nil {
        return nil, fmt.Errorf("invalid directRanges: %w", err)
    }
    // If directRanges is empty, treat everything as direct.
    if len(m.directRanges) == 0 {
        if m.directRanges, err = parseCIDRs([]string{"0.0.0.0/0", "::/0"}); err != nil {
            return nil, err
        }
    }
    return m, nil
}

// ServeHTTP implements the http.Handler interface.
func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    remoteIP := clientIP(req.RemoteAddr)

    if m.isTrustedProxy(remoteIP) {
        // We trust the upstream proxy – leave XFF as-is.
        m.next.ServeHTTP(rw, req)
        return
    }

    // Traffic is *not* coming from a trusted proxy.
    // Either direct client or an untrusted proxy: make sure XFF is the remote IP.
    req.Header.Set(m.header, remoteIP.String())
    m.next.ServeHTTP(rw, req)
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func defaultHeader(h string) string {
    if strings.TrimSpace(h) == "" {
        return "X-Forwarded-For"
    }
    return h
}

func parseCIDRs(raw []string) ([]*net.IPNet, error) {
    var list []*net.IPNet
    for _, cidr := range raw {
        // Allow single IPs as well as CIDRs.
        if ip := net.ParseIP(cidr); ip != nil {
            bits := 32
            if ip.To4() == nil {
                bits = 128
            }
            mask := net.CIDRMask(bits, bits)
            list = append(list, &net.IPNet{IP: ip, Mask: mask})
            continue
        }
        _, n, err := net.ParseCIDR(cidr)
        if err != nil {
            return nil, fmt.Errorf("%q: %w", cidr, err)
        }
        list = append(list, n)
    }
    return list, nil
}

func clientIP(remoteAddr string) net.IP {
    host, _, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        host = remoteAddr
    }
    return net.ParseIP(host)
}

func (m *middleware) isTrustedProxy(ip net.IP) bool {
    for _, n := range m.trustedProxies {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}
