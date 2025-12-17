package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xmpanel/xmpanel/internal/api/middleware"
	"github.com/xmpanel/xmpanel/internal/auth"
	"github.com/xmpanel/xmpanel/internal/security/crypto"
	"github.com/xmpanel/xmpanel/internal/store"
	"github.com/xmpanel/xmpanel/internal/store/models"

	"go.uber.org/zap"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	db           *store.DB
	jwtManager   *auth.JWTManager
	hasher       *crypto.Argon2Hasher
	totpManager  *auth.TOTPManager
	loginLimiter *middleware.LoginRateLimiter
	logger       *zap.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	db *store.DB,
	jwtManager *auth.JWTManager,
	hasher *crypto.Argon2Hasher,
	loginLimiter *middleware.LoginRateLimiter,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		db:           db,
		jwtManager:   jwtManager,
		hasher:       hasher,
		totpManager:  auth.NewTOTPManager("XMPanel"),
		loginLimiter: loginLimiter,
		logger:       logger,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check rate limit
	clientIP := r.RemoteAddr
	allowed, lockDuration := h.loginLimiter.Check(clientIP + ":" + req.Username)
	if !allowed {
		w.Header().Set("Retry-After", lockDuration.String())
		writeError(w, http.StatusTooManyRequests, "Too many login attempts. Please try again later.")
		return
	}

	// Get user from database
	var user models.User
	err := h.db.QueryRow(`
		SELECT id, username, email, password_hash, role, mfa_enabled, mfa_secret,
		       failed_login_attempts, locked_until, last_login_at, last_login_ip,
		       created_at, updated_at
		FROM users WHERE username = ?
	`, req.Username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role,
		&user.MFAEnabled, &user.MFASecret, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.LastLoginAt, &user.LastLoginIP, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if err != nil {
		h.logger.Error("failed to query user", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Check if account is locked
	if user.IsLocked() {
		writeError(w, http.StatusForbidden, "Account is temporarily locked")
		return
	}

	// Verify password
	valid, err := h.hasher.Verify(req.Password, user.PasswordHash)
	if err != nil || !valid {
		// Record failed attempt
		h.db.Exec(`
			UPDATE users SET failed_login_attempts = failed_login_attempts + 1,
			       locked_until = CASE WHEN failed_login_attempts >= 4 THEN datetime('now', '+15 minutes') ELSE locked_until END
			WHERE id = ?
		`, user.ID)
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.TOTPCode == "" {
			// MFA required but not provided
			writeJSON(w, http.StatusOK, models.LoginResponse{
				MFARequired: true,
			})
			return
		}

		// Verify TOTP code
		if user.MFASecret.Valid {
			valid, err := h.totpManager.ValidateCode(user.MFASecret.String, req.TOTPCode)
			if err != nil || !valid {
				writeError(w, http.StatusUnauthorized, "Invalid MFA code")
				return
			}
		}
	}

	// Generate session ID
	sessionID, err := crypto.GenerateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate session ID", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Generate tokens
	tokenPair, err := h.jwtManager.GenerateTokenPair(
		user.ID,
		user.Username,
		string(user.Role),
		sessionID,
		"", // Device ID (optional)
	)
	if err != nil {
		h.logger.Error("failed to generate tokens", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Create session record
	_, err = h.db.Exec(`
		INSERT INTO sessions (user_id, session_id, ip_address, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, user.ID, sessionID, r.RemoteAddr, r.UserAgent(), tokenPair.ExpiresAt.Add(7*24*time.Hour))
	if err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
	}

	// Update login info and reset failed attempts
	h.db.Exec(`
		UPDATE users SET last_login_at = ?, last_login_ip = ?, failed_login_attempts = 0, locked_until = NULL
		WHERE id = ?
	`, time.Now(), r.RemoteAddr, user.ID)

	// Clear rate limiter on success
	h.loginLimiter.RecordSuccess(clientIP + ":" + req.Username)

	// Return response
	user.PasswordHash = ""
	user.MFASecret = sql.NullString{}
	user.RecoveryCodes = sql.NullString{}

	writeJSON(w, http.StatusOK, models.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
		TokenType:    tokenPair.TokenType,
		User:         &user,
	})
}

// Refresh handles token refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	tokenPair, err := h.jwtManager.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		switch err {
		case auth.ErrExpiredToken:
			writeError(w, http.StatusUnauthorized, "Refresh token has expired")
		default:
			writeError(w, http.StatusUnauthorized, "Invalid refresh token")
		}
		return
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Delete session
	_, err := h.db.Exec(`DELETE FROM sessions WHERE session_id = ?`, claims.SessionID)
	if err != nil {
		h.logger.Error("failed to delete session", zap.Error(err))
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// Me returns the current user info
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var user models.User
	err := h.db.QueryRow(`
		SELECT id, username, email, role, mfa_enabled, last_login_at, last_login_ip, created_at, updated_at
		FROM users WHERE id = ?
	`, claims.UserID).Scan(
		&user.ID, &user.Username, &user.Email, &user.Role, &user.MFAEnabled,
		&user.LastLoginAt, &user.LastLoginIP, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// SetupMFA initiates MFA setup
func (h *AuthHandler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Generate TOTP secret
	secret, err := h.totpManager.GenerateSecret(claims.Username)
	if err != nil {
		h.logger.Error("failed to generate TOTP secret", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Store secret temporarily (not enabled yet)
	_, err = h.db.Exec(`UPDATE users SET mfa_secret = ? WHERE id = ?`, secret.Secret, claims.UserID)
	if err != nil {
		h.logger.Error("failed to store MFA secret", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	writeJSON(w, http.StatusOK, secret)
}

// VerifyMFA verifies and enables MFA
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get user's MFA secret
	var secret sql.NullString
	err := h.db.QueryRow(`SELECT mfa_secret FROM users WHERE id = ?`, claims.UserID).Scan(&secret)
	if err != nil || !secret.Valid {
		writeError(w, http.StatusBadRequest, "MFA not set up")
		return
	}

	// Verify code
	valid, err := h.totpManager.ValidateCode(secret.String, req.Code)
	if err != nil || !valid {
		writeError(w, http.StatusBadRequest, "Invalid verification code")
		return
	}

	// Enable MFA
	_, err = h.db.Exec(`UPDATE users SET mfa_enabled = 1 WHERE id = ?`, claims.UserID)
	if err != nil {
		h.logger.Error("failed to enable MFA", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Generate recovery codes
	recoveryManager := auth.NewRecoveryCodeManager()
	codes, err := recoveryManager.GenerateCodes()
	if err != nil {
		h.logger.Error("failed to generate recovery codes", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Hash and store recovery codes
	hashedCodes, err := recoveryManager.HashCodes(codes, h.hasher)
	if err != nil {
		h.logger.Error("failed to hash recovery codes", zap.Error(err))
	} else {
		codesJSON, _ := json.Marshal(hashedCodes)
		h.db.Exec(`UPDATE users SET recovery_codes = ? WHERE id = ?`, string(codesJSON), claims.UserID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":        "MFA enabled successfully",
		"recovery_codes": codes,
	})
}

// DisableMFA disables MFA for the current user
func (h *AuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Verify password
	var passwordHash string
	var mfaSecret sql.NullString
	err := h.db.QueryRow(`SELECT password_hash, mfa_secret FROM users WHERE id = ?`, claims.UserID).
		Scan(&passwordHash, &mfaSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	valid, err := h.hasher.Verify(req.Password, passwordHash)
	if err != nil || !valid {
		writeError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	// Verify TOTP code
	if mfaSecret.Valid {
		valid, err := h.totpManager.ValidateCode(mfaSecret.String, req.Code)
		if err != nil || !valid {
			writeError(w, http.StatusBadRequest, "Invalid MFA code")
			return
		}
	}

	// Disable MFA
	_, err = h.db.Exec(`UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, recovery_codes = NULL WHERE id = ?`, claims.UserID)
	if err != nil {
		h.logger.Error("failed to disable MFA", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA disabled successfully"})
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate new password
	if len(req.NewPassword) < 12 {
		writeError(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}

	// Get current password hash
	var currentHash string
	err := h.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, claims.UserID).Scan(&currentHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Verify current password
	valid, err := h.hasher.Verify(req.CurrentPassword, currentHash)
	if err != nil || !valid {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	// Hash new password
	newHash, err := h.hasher.Hash(req.NewPassword)
	if err != nil {
		h.logger.Error("failed to hash password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Update password
	_, err = h.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		newHash, time.Now(), claims.UserID)
	if err != nil {
		h.logger.Error("failed to update password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Invalidate all other sessions
	_, err = h.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND session_id != ?`,
		claims.UserID, claims.SessionID)
	if err != nil {
		h.logger.Error("failed to invalidate sessions", zap.Error(err))
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
