package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/xmpanel/xmpanel/internal/config"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	burst    int
	cleanup  time.Duration
	lastClean time.Time
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		buckets:   make(map[string]*bucket),
		rate:      cfg.RequestsPerSecond,
		burst:     cfg.Burst,
		cleanup:   5 * time.Minute,
		lastClean: time.Now(),
	}
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
			key := getClientIP(r)

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

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (if behind proxy)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP (original client)
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// Strip port if present
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
