package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Security SecurityConfig `yaml:"security"`
	XMPP     XMPPConfig     `yaml:"xmpp"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver          string `yaml:"driver"` // sqlite or postgres
	DSN             string `yaml:"dsn"`
	EncryptionKey   string `yaml:"encryption_key"`    // Base64 encoded 32-byte key
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	JWT      JWTConfig      `yaml:"jwt"`
	MFA      MFAConfig      `yaml:"mfa"`
	Password PasswordConfig `yaml:"password"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	CORS     CORSConfig     `yaml:"cors"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret           string        `yaml:"secret"`
	AccessTokenTTL   time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `yaml:"refresh_token_ttl"`
	Issuer           string        `yaml:"issuer"`
}

// MFAConfig holds MFA configuration
type MFAConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Issuer     string `yaml:"issuer"`
	Required   bool   `yaml:"required"` // If true, all users must enable MFA
}

// PasswordConfig holds password policy configuration
type PasswordConfig struct {
	MinLength       int           `yaml:"min_length"`
	RequireUpper    bool          `yaml:"require_upper"`
	RequireLower    bool          `yaml:"require_lower"`
	RequireNumber   bool          `yaml:"require_number"`
	RequireSpecial  bool          `yaml:"require_special"`
	Argon2Time      uint32        `yaml:"argon2_time"`
	Argon2Memory    uint32        `yaml:"argon2_memory"`
	Argon2Threads   uint8         `yaml:"argon2_threads"`
	MaxLoginAttempts int          `yaml:"max_login_attempts"`
	LockoutDuration time.Duration `yaml:"lockout_duration"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled       bool          `yaml:"enabled"`
	RequestsPerSecond float64   `yaml:"requests_per_second"`
	Burst         int           `yaml:"burst"`
	LoginAttempts int           `yaml:"login_attempts"`
	LoginWindow   time.Duration `yaml:"login_window"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`
}

// XMPPConfig holds XMPP servers configuration
type XMPPConfig struct {
	Servers []XMPPServerConfig `yaml:"servers"`
}

// XMPPServerConfig holds individual XMPP server configuration
type XMPPServerConfig struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // prosody or ejabberd
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	APIKey   string `yaml:"api_key"` // Will be encrypted at rest
	TLS      bool   `yaml:"tls"`
	Enabled  bool   `yaml:"enabled"`
}

// Load loads configuration from file
func Load() (*Config, error) {
	configPath := os.Getenv("XMPANEL_CONFIG")
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults for missing values
	applyDefaults(&cfg)

	return &cfg, nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.Address == "" {
		cfg.Server.Address = ":8080"
	}

	// Database defaults
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "sqlite"
	}
	if cfg.Database.DSN == "" {
		cfg.Database.DSN = "xmpanel.db"
	}
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 25
	}
	if cfg.Database.MaxIdleConns == 0 {
		cfg.Database.MaxIdleConns = 5
	}
	if cfg.Database.ConnMaxLifetime == "" {
		cfg.Database.ConnMaxLifetime = "5m"
	}

	// JWT defaults
	if cfg.Security.JWT.AccessTokenTTL == 0 {
		cfg.Security.JWT.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.Security.JWT.RefreshTokenTTL == 0 {
		cfg.Security.JWT.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if cfg.Security.JWT.Issuer == "" {
		cfg.Security.JWT.Issuer = "xmpanel"
	}

	// MFA defaults
	if cfg.Security.MFA.Issuer == "" {
		cfg.Security.MFA.Issuer = "XMPanel"
	}

	// Password defaults
	if cfg.Security.Password.MinLength == 0 {
		cfg.Security.Password.MinLength = 12
	}
	if cfg.Security.Password.Argon2Time == 0 {
		cfg.Security.Password.Argon2Time = 3
	}
	if cfg.Security.Password.Argon2Memory == 0 {
		cfg.Security.Password.Argon2Memory = 64 * 1024 // 64MB
	}
	if cfg.Security.Password.Argon2Threads == 0 {
		cfg.Security.Password.Argon2Threads = 4
	}
	if cfg.Security.Password.MaxLoginAttempts == 0 {
		cfg.Security.Password.MaxLoginAttempts = 5
	}
	if cfg.Security.Password.LockoutDuration == 0 {
		cfg.Security.Password.LockoutDuration = 15 * time.Minute
	}

	// Rate limit defaults
	if cfg.Security.RateLimit.RequestsPerSecond == 0 {
		cfg.Security.RateLimit.RequestsPerSecond = 100
	}
	if cfg.Security.RateLimit.Burst == 0 {
		cfg.Security.RateLimit.Burst = 200
	}
	if cfg.Security.RateLimit.LoginAttempts == 0 {
		cfg.Security.RateLimit.LoginAttempts = 5
	}
	if cfg.Security.RateLimit.LoginWindow == 0 {
		cfg.Security.RateLimit.LoginWindow = 15 * time.Minute
	}

	// CORS defaults
	if len(cfg.Security.CORS.AllowedMethods) == 0 {
		cfg.Security.CORS.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(cfg.Security.CORS.AllowedHeaders) == 0 {
		cfg.Security.CORS.AllowedHeaders = []string{"Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"}
	}
	if cfg.Security.CORS.MaxAge == 0 {
		cfg.Security.CORS.MaxAge = 86400
	}
}
