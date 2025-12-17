package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/xmpanel/xmpanel/internal/adapter"
	"github.com/xmpanel/xmpanel/internal/security/crypto"
	"github.com/xmpanel/xmpanel/internal/store"
	"github.com/xmpanel/xmpanel/internal/store/models"

	"go.uber.org/zap"
)

// XMPPHandler handles XMPP operations endpoints
type XMPPHandler struct {
	db      *store.DB
	keyRing *crypto.KeyRing
	logger  *zap.Logger
}

// NewXMPPHandler creates a new XMPP handler
func NewXMPPHandler(db *store.DB, keyRing *crypto.KeyRing, logger *zap.Logger) *XMPPHandler {
	return &XMPPHandler{
		db:      db,
		keyRing: keyRing,
		logger:  logger,
	}
}

// ListUsers lists all users on an XMPP server
func (h *XMPPHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	users, err := xmppAdapter.ListUsers(ctx, domain)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to list users")
		return
	}

	writeJSON(w, http.StatusOK, users)
}

// GetUser gets a specific user on an XMPP server
func (h *XMPPHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	user, err := xmppAdapter.GetUser(ctx, username, domain)
	if err != nil {
		if err == adapter.ErrUserNotFound {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("failed to get user", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to get user")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// CreateUser creates a new user on an XMPP server
func (h *XMPPHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	var req models.CreateXMPPUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "Username is required")
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.CreateUser(ctx, req)
	if err != nil {
		if err == adapter.ErrUserExists {
			writeError(w, http.StatusConflict, "User already exists")
			return
		}
		h.logger.Error("failed to create user", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "User created successfully",
		"jid":     req.Username + "@" + req.Domain,
	})
}

// DeleteUser deletes a user from an XMPP server
func (h *XMPPHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.DeleteUser(ctx, username, domain)
	if err != nil {
		if err == adapter.ErrUserNotFound {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("failed to delete user", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to delete user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// KickUser kicks a user from an XMPP server
func (h *XMPPHandler) KickUser(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.KickUser(ctx, username, domain)
	if err != nil {
		h.logger.Error("failed to kick user", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to kick user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "User kicked successfully"})
}

// ListSessions lists all online sessions
func (h *XMPPHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	sessions, err := xmppAdapter.GetOnlineSessions(ctx)
	if err != nil {
		h.logger.Error("failed to list sessions", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to list sessions")
		return
	}

	writeJSON(w, http.StatusOK, sessions)
}

// KickSession kicks a specific session
func (h *XMPPHandler) KickSession(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	jid := r.PathValue("jid")

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.KickSession(ctx, jid)
	if err != nil {
		h.logger.Error("failed to kick session", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to kick session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Session kicked successfully"})
}

// ListRooms lists all MUC rooms
func (h *XMPPHandler) ListRooms(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	mucDomain := r.URL.Query().Get("muc_domain")
	if mucDomain == "" {
		writeError(w, http.StatusBadRequest, "MUC domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	rooms, err := xmppAdapter.ListRooms(ctx, mucDomain)
	if err != nil {
		h.logger.Error("failed to list rooms", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to list rooms")
		return
	}

	writeJSON(w, http.StatusOK, rooms)
}

// GetRoom gets a specific room
func (h *XMPPHandler) GetRoom(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	room := r.PathValue("room")
	mucDomain := r.URL.Query().Get("muc_domain")
	if mucDomain == "" {
		writeError(w, http.StatusBadRequest, "MUC domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	roomInfo, err := xmppAdapter.GetRoom(ctx, room, mucDomain)
	if err != nil {
		if err == adapter.ErrRoomNotFound {
			writeError(w, http.StatusNotFound, "Room not found")
			return
		}
		h.logger.Error("failed to get room", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to get room")
		return
	}

	writeJSON(w, http.StatusOK, roomInfo)
}

// CreateRoom creates a new MUC room
func (h *XMPPHandler) CreateRoom(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	var req models.CreateXMPPRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Room name is required")
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "MUC domain is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.CreateRoom(ctx, req)
	if err != nil {
		if err == adapter.ErrRoomExists {
			writeError(w, http.StatusConflict, "Room already exists")
			return
		}
		h.logger.Error("failed to create room", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to create room")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "Room created successfully",
		"jid":     req.Name + "@" + req.Domain,
	})
}

// DeleteRoom deletes a MUC room
func (h *XMPPHandler) DeleteRoom(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(r.PathValue("serverId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid server ID")
		return
	}

	room := r.PathValue("room")
	mucDomain := r.URL.Query().Get("muc_domain")
	if mucDomain == "" {
		writeError(w, http.StatusBadRequest, "MUC domain parameter is required")
		return
	}

	xmppAdapter, err := h.getAdapter(serverID)
	if err != nil {
		h.handleAdapterError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = xmppAdapter.DeleteRoom(ctx, room, mucDomain)
	if err != nil {
		if err == adapter.ErrRoomNotFound {
			writeError(w, http.StatusNotFound, "Room not found")
			return
		}
		h.logger.Error("failed to delete room", zap.Error(err))
		writeError(w, http.StatusBadGateway, "Failed to delete room")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Room deleted successfully"})
}

// getAdapter creates an adapter for the given server ID
func (h *XMPPHandler) getAdapter(serverID int64) (adapter.XMPPAdapter, error) {
	var server models.XMPPServer
	var encryptedAPIKey sql.NullString

	err := h.db.QueryRow(`
		SELECT id, name, type, host, port, api_key_encrypted, tls_enabled, enabled
		FROM xmpp_servers WHERE id = ?
	`, serverID).Scan(
		&server.ID, &server.Name, &server.Type, &server.Host, &server.Port,
		&encryptedAPIKey, &server.TLSEnabled, &server.Enabled,
	)
	if err != nil {
		return nil, err
	}

	// Decrypt API key
	var apiKey string
	if encryptedAPIKey.Valid && h.keyRing != nil {
		decrypted, err := h.keyRing.DecryptString(encryptedAPIKey.String)
		if err != nil {
			return nil, err
		}
		apiKey = decrypted
	}

	return newAdapter(&server, apiKey)
}

func (h *XMPPHandler) handleAdapterError(w http.ResponseWriter, err error) {
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "Server not found")
		return
	}
	h.logger.Error("failed to get adapter", zap.Error(err))
	writeError(w, http.StatusInternalServerError, "Internal server error")
}
