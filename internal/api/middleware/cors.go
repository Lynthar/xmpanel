package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/xmpanel/xmpanel/internal/config"
)

// CORSMiddleware handles Cross-Origin Resource Sharing
type CORSMiddleware struct {
	allowedOrigins   map[string]bool
	allowAllOrigins  bool
	allowedMethods   string
	allowedHeaders   string
	allowCredentials bool
	maxAge           string
}

// NewCORSMiddleware creates a new CORS middleware
func NewCORSMiddleware(cfg config.CORSConfig) *CORSMiddleware {
	origins := make(map[string]bool)
	allowAll := false

	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			allowAll = true
			break
		}
		origins[origin] = true
	}

	return &CORSMiddleware{
		allowedOrigins:   origins,
		allowAllOrigins:  allowAll,
		allowedMethods:   strings.Join(cfg.AllowedMethods, ", "),
		allowedHeaders:   strings.Join(cfg.AllowedHeaders, ", "),
		allowCredentials: cfg.AllowCredentials,
		maxAge:           strconv.Itoa(cfg.MaxAge),
	}
}

// Handle adds CORS headers to responses
func (m *CORSMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		if origin != "" {
			if m.allowAllOrigins {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if m.allowedOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}

		// Always set Vary header for proper caching
		w.Header().Add("Vary", "Origin")

		if m.allowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", m.allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", m.allowedHeaders)
			w.Header().Set("Access-Control-Max-Age", m.maxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
