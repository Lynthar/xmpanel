package prosody

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xmpanel/xmpanel/internal/store/models"
	apperrors "github.com/xmpanel/xmpanel/pkg/errors"
	"github.com/xmpanel/xmpanel/pkg/types"
)

// Adapter implements XMPPAdapter for Prosody servers
// It uses mod_http_admin_api or mod_admin_rest for communication
type Adapter struct {
	server     *models.XMPPServer
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewAdapter creates a new Prosody adapter
func NewAdapter(server *models.XMPPServer, apiKey string) *Adapter {
	scheme := "http"
	if server.TLSEnabled {
		scheme = "https"
	}

	return &Adapter{
		server: server,
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: fmt.Sprintf("%s://%s:%d", scheme, server.Host, server.Port),
	}
}

// Connect tests the connection to the Prosody server
func (a *Adapter) Connect(ctx context.Context) error {
	return a.Ping(ctx)
}

// Disconnect closes the connection (no-op for HTTP)
func (a *Adapter) Disconnect() error {
	return nil
}

// Ping checks if the server is reachable
func (a *Adapter) Ping(ctx context.Context) error {
	_, err := a.doRequest(ctx, http.MethodGet, "/admin_api", nil)
	return err
}

// GetServerInfo retrieves server information
func (a *Adapter) GetServerInfo(ctx context.Context) (*types.ServerInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin_api/server", nil)
	if err != nil {
		return nil, err
	}

	var info struct {
		Version  string   `json:"version"`
		Hostname string   `json:"hostname"`
		Hosts    []string `json:"hosts"`
	}

	if err := json.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("failed to parse server info: %w", err)
	}

	return &types.ServerInfo{
		Type:     types.ServerTypeProsody,
		Version:  info.Version,
		Hostname: info.Hostname,
		Domains:  info.Hosts,
	}, nil
}

// GetStats retrieves server statistics
func (a *Adapter) GetStats(ctx context.Context) (*models.ServerStats, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin_api/statistics", nil)
	if err != nil {
		return nil, err
	}

	var rawStats map[string]interface{}
	if err := json.Unmarshal(resp, &rawStats); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %w", err)
	}

	stats := &models.ServerStats{
		Extra: rawStats,
	}

	// Map common fields
	if v, ok := rawStats["c2s_sessions"].(float64); ok {
		stats.OnlineUsers = int(v)
	}
	if v, ok := rawStats["total_users"].(float64); ok {
		stats.RegisteredUsers = int(v)
	}
	if v, ok := rawStats["total_c2s"].(float64); ok {
		stats.ActiveSessions = int(v)
	}
	if v, ok := rawStats["total_s2s"].(float64); ok {
		stats.S2SConnections = int(v)
	}

	return stats, nil
}

// ListUsers lists all users in a domain
func (a *Adapter) ListUsers(ctx context.Context, domain string) ([]models.XMPPUser, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, fmt.Sprintf("/admin_api/users/%s", domain), nil)
	if err != nil {
		return nil, err
	}

	var usernames []string
	if err := json.Unmarshal(resp, &usernames); err != nil {
		return nil, fmt.Errorf("failed to parse users: %w", err)
	}

	users := make([]models.XMPPUser, len(usernames))
	for i, username := range usernames {
		users[i] = models.XMPPUser{
			Username: username,
			Domain:   domain,
			JID:      fmt.Sprintf("%s@%s", username, domain),
		}
	}

	return users, nil
}

// GetUser retrieves information about a specific user
func (a *Adapter) GetUser(ctx context.Context, username, domain string) (*models.XMPPUser, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, fmt.Sprintf("/admin_api/users/%s/%s", domain, username), nil)
	if err != nil {
		return nil, err
	}

	var userInfo struct {
		Username  string   `json:"username"`
		Resources []string `json:"resources,omitempty"`
	}

	if err := json.Unmarshal(resp, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}

	return &models.XMPPUser{
		Username:  username,
		Domain:    domain,
		JID:       fmt.Sprintf("%s@%s", username, domain),
		Online:    len(userInfo.Resources) > 0,
		Resources: userInfo.Resources,
	}, nil
}

// CreateUser creates a new user
func (a *Adapter) CreateUser(ctx context.Context, req models.CreateXMPPUserRequest) error {
	body := map[string]string{
		"password": req.Password,
	}

	_, err := a.doRequest(ctx, http.MethodPut,
		fmt.Sprintf("/admin_api/users/%s/%s", req.Domain, req.Username), body)
	return err
}

// DeleteUser deletes a user
func (a *Adapter) DeleteUser(ctx context.Context, username, domain string) error {
	_, err := a.doRequest(ctx, http.MethodDelete,
		fmt.Sprintf("/admin_api/users/%s/%s", domain, username), nil)
	return err
}

// ChangePassword changes a user's password
func (a *Adapter) ChangePassword(ctx context.Context, username, domain, newPassword string) error {
	body := map[string]string{
		"password": newPassword,
	}

	_, err := a.doRequest(ctx, http.MethodPatch,
		fmt.Sprintf("/admin_api/users/%s/%s", domain, username), body)
	return err
}

// GetOnlineSessions retrieves all online sessions
func (a *Adapter) GetOnlineSessions(ctx context.Context) ([]models.XMPPSession, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin_api/sessions", nil)
	if err != nil {
		return nil, err
	}

	var rawSessions []struct {
		JID      string `json:"jid"`
		Resource string `json:"resource"`
		IP       string `json:"ip"`
		Priority int    `json:"priority"`
		Status   string `json:"status"`
	}

	if err := json.Unmarshal(resp, &rawSessions); err != nil {
		return nil, fmt.Errorf("failed to parse sessions: %w", err)
	}

	sessions := make([]models.XMPPSession, len(rawSessions))
	for i, s := range rawSessions {
		sessions[i] = models.XMPPSession{
			JID:       s.JID,
			Resource:  s.Resource,
			IPAddress: s.IP,
			Priority:  s.Priority,
			Status:    s.Status,
		}
	}

	return sessions, nil
}

// GetUserSessions retrieves sessions for a specific user
func (a *Adapter) GetUserSessions(ctx context.Context, username, domain string) ([]models.XMPPSession, error) {
	jid := fmt.Sprintf("%s@%s", username, domain)
	resp, err := a.doRequest(ctx, http.MethodGet, fmt.Sprintf("/admin_api/sessions/%s", jid), nil)
	if err != nil {
		return nil, err
	}

	var sessions []models.XMPPSession
	if err := json.Unmarshal(resp, &sessions); err != nil {
		return nil, fmt.Errorf("failed to parse sessions: %w", err)
	}

	return sessions, nil
}

// KickSession disconnects a specific session
func (a *Adapter) KickSession(ctx context.Context, jid string) error {
	_, err := a.doRequest(ctx, http.MethodDelete, fmt.Sprintf("/admin_api/sessions/%s", jid), nil)
	return err
}

// KickUser disconnects all sessions for a user
func (a *Adapter) KickUser(ctx context.Context, username, domain string) error {
	jid := fmt.Sprintf("%s@%s", username, domain)
	return a.KickSession(ctx, jid)
}

// ListRooms lists all MUC rooms
func (a *Adapter) ListRooms(ctx context.Context, mucDomain string) ([]models.XMPPRoom, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, fmt.Sprintf("/admin_api/muc/%s/rooms", mucDomain), nil)
	if err != nil {
		return nil, err
	}

	var rawRooms []struct {
		JID         string `json:"jid"`
		Name        string `json:"name"`
		Occupants   int    `json:"occupants"`
		Public      bool   `json:"public"`
		Persistent  bool   `json:"persistent"`
		MembersOnly bool   `json:"members_only"`
	}

	if err := json.Unmarshal(resp, &rawRooms); err != nil {
		return nil, fmt.Errorf("failed to parse rooms: %w", err)
	}

	rooms := make([]models.XMPPRoom, len(rawRooms))
	for i, r := range rawRooms {
		rooms[i] = models.XMPPRoom{
			JID:         r.JID,
			Name:        r.Name,
			Occupants:   r.Occupants,
			Public:      r.Public,
			Persistent:  r.Persistent,
			MembersOnly: r.MembersOnly,
		}
	}

	return rooms, nil
}

// GetRoom retrieves information about a specific room
func (a *Adapter) GetRoom(ctx context.Context, room, mucDomain string) (*models.XMPPRoom, error) {
	resp, err := a.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("/admin_api/muc/%s/rooms/%s", mucDomain, room), nil)
	if err != nil {
		return nil, err
	}

	var r models.XMPPRoom
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("failed to parse room: %w", err)
	}

	return &r, nil
}

// CreateRoom creates a new MUC room
func (a *Adapter) CreateRoom(ctx context.Context, req models.CreateXMPPRoomRequest) error {
	body := map[string]interface{}{
		"name":         req.Name,
		"description":  req.Description,
		"public":       req.Public,
		"persistent":   req.Persistent,
		"members_only": req.MembersOnly,
	}

	_, err := a.doRequest(ctx, http.MethodPut,
		fmt.Sprintf("/admin_api/muc/%s/rooms/%s", req.Domain, req.Name), body)
	return err
}

// DeleteRoom deletes a MUC room
func (a *Adapter) DeleteRoom(ctx context.Context, room, mucDomain string) error {
	_, err := a.doRequest(ctx, http.MethodDelete,
		fmt.Sprintf("/admin_api/muc/%s/rooms/%s", mucDomain, room), nil)
	return err
}

// ListModules lists all loaded modules
func (a *Adapter) ListModules(ctx context.Context) ([]types.ModuleInfo, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/admin_api/modules", nil)
	if err != nil {
		return nil, err
	}

	var modules []types.ModuleInfo
	if err := json.Unmarshal(resp, &modules); err != nil {
		return nil, fmt.Errorf("failed to parse modules: %w", err)
	}

	return modules, nil
}

// EnableModule enables a module
func (a *Adapter) EnableModule(ctx context.Context, module string) error {
	_, err := a.doRequest(ctx, http.MethodPut, fmt.Sprintf("/admin_api/modules/%s", module), nil)
	return err
}

// DisableModule disables a module
func (a *Adapter) DisableModule(ctx context.Context, module string) error {
	_, err := a.doRequest(ctx, http.MethodDelete, fmt.Sprintf("/admin_api/modules/%s", module), nil)
	return err
}

// doRequest performs an HTTP request to the Prosody API
func (a *Adapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", apperrors.ErrConnectionFailed, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return respBody, nil
	case http.StatusUnauthorized:
		return nil, apperrors.ErrAuthFailed
	case http.StatusNotFound:
		return nil, apperrors.ErrUserNotFound
	case http.StatusConflict:
		return nil, apperrors.ErrUserExists
	default:
		return nil, fmt.Errorf("%w: %s", apperrors.ErrOperationFailed, string(respBody))
	}
}
