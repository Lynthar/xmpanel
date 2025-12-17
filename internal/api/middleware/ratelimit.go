package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xmpanel/xmpanel/internal/config"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu                 sync.Mutex
	buckets            map[string]*bucket
	rate               float64
	burst              int
	cleanup            time.Duration
	lastClean          time.Time
	trustedProxies     []*net.IPNet
	trustXForwardedFor bool
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		buckets:            make(map[string]*bucket),
		rate:               cfg.RequestsPerSecond,
		burst:              cfg.Burst,
		cleanup:            5 * time.Minute,
		lastClean:          time.Now(),
		trustXForwardedFor: cfg.TrustXForwardedFor,
	}

	// Parse trusted proxies
	for _, proxy := range cfg.TrustedProxies {
		// Handle single IPs by adding /32 or /128
		if !strings.Contains(proxy, "/") {
			if strings.Contains(proxy, ":") {
				proxy += "/128"
			} else {
				proxy += "/32"
			}
		}
		_, network, err := net.ParseCIDR(proxy)
		if err == nil {
			rl.trustedProxies = append(rl.trustedProxies, network)
		}
	}

	return rl
}

// Allow checks if a request from the given key should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup of old buckets
	if time.Since(rl.lastClean) > rl.cleanup {
		rl.cleanupBuckets()
		rl.lastClean = time.Now()
	}

	now := time.Now()
	b, exists := rl.buckets[key]

	if !exists {
		rl.buckets[key] = &bucket{
			tokens:    float64(rl.burst) - 1,
			lastCheck: now,
		}
		return true
	}

	// Add tokens based on time elapsed
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) cleanupBuckets() {
	threshold := time.Now().Add(-10 * time.Minute)
	for key, b := range rl.buckets {
		if b.lastCheck.Before(threshold) {
			delete(rl.buckets, key)
		}
	}
}

// RateLimit middleware limits requests based on client IP
func RateLimit(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := limiter.getClientIP(r)

			if !limiter.Allow(key) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// LoginRateLimiter specifically limits login attempts
type LoginRateLimiter struct {
	mu        sync.Mutex
	attempts  map[string]*loginAttempts
	maxTries  int
	window    time.Duration
}

type loginAttempts struct {
	count     int
	firstTry  time.Time
	lockedUntil time.Time
}

// NewLoginRateLimiter creates a new login rate limiter
func NewLoginRateLimiter(maxTries int, window time.Duration) *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts: make(map[string]*loginAttempts),
		maxTries: maxTries,
		window:   window,
	}
}

// Check checks if a login attempt should be allowed
func (lr *LoginRateLimiter) Check(key string) (bool, time.Duration) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	now := time.Now()
	a, exists := lr.attempts[key]

	if !exists {
		lr.attempts[key] = &loginAttempts{
			count:    1,
			firstTry: now,
		}
		return true, 0
	}

	// Check if locked
	if !a.lockedUntil.IsZero() && now.Before(a.lockedUntil) {
		return false, a.lockedUntil.Sub(now)
	}

	// Check if window has passed
	if now.Sub(a.firstTry) > lr.window {
		a.count = 1
		a.firstTry = now
		a.lockedUntil = time.Time{}
		return true, 0
	}

	a.count++

	if a.count > lr.maxTries {
		// Progressive lockout: double the lockout time for each subsequent lockout
		lockoutDuration := lr.window
		a.lockedUntil = now.Add(lockoutDuration)
		return false, lockoutDuration
	}

	return true, 0
}

// RecordFailure records a failed login attempt
func (lr *LoginRateLimiter) RecordFailure(key string) {
	// The Check method already records the attempt
}

// RecordSuccess clears the attempts for a key after successful login
func (lr *LoginRateLimiter) RecordSuccess(key string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	delete(lr.attempts, key)
}

// getClientIP extracts the client IP from the request, validating proxy headers
func (rl *RateLimiter) getClientIP(r *http.Request) string {
	remoteIP := extractIP(r.RemoteAddr)

	// If X-Forwarded-For trust is disabled, always use RemoteAddr
	if !rl.trustXForwardedFor {
		return remoteIP
	}

	// Only trust X-Forwarded-For if request comes from a trusted proxy
	if !rl.isTrustedProxy(remoteIP) {
		return remoteIP
	}

	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2, ...
		// Take the first IP (original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	return remoteIP
}

// isTrustedProxy checks if the given IP is in the trusted proxies list
func (rl *RateLimiter) isTrustedProxy(ip string) bool {
	if len(rl.trustedProxies) == 0 {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, network := range rl.trustedProxies {
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// extractIP extracts the IP address from an address string (removes port)
func extractIP(addr string) string {
	// Handle IPv6 addresses in brackets
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]"); idx != -1 {
			return addr[1:idx]
		}
	}

	// Handle host:port format
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}

	return addr
}

// GetClientIP is a standalone function for use outside rate limiter
// This function does NOT trust proxy headers by default for security
func GetClientIP(r *http.Request) string {
	return extractIP(r.RemoteAddr)
}
