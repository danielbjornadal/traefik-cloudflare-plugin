// headerdump.go
package headerdump

import (
	"context"
	"log"
	"net/http"
)

// Config holds your single toggle.
type Config struct {
	Enabled bool `json:"enabled,omitempty"` // default = true
}

// CreateConfig lets Traefik instantiate default config.
func CreateConfig() *Config { return &Config{Enabled: true} }

// headerDump stores runtime data.
type headerDump struct {
	next    http.Handler
	enabled bool
	name    string
}

// New is called by Traefik when it wires the middleware.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &headerDump{
		next:    next,
		enabled: cfg.Enabled,
		name:    name,
	}, nil
}

// ServeHTTP is the actual middleware.
func (h *headerDump) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if h.enabled {
		log.Printf("[headerdump %s] incoming headers: %+v\n", h.name, req.Header)
	}
	h.next.ServeHTTP(rw, req)
}
