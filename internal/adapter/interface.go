package adapter

import (
	"context"

	"github.com/xmpanel/xmpanel/internal/store/models"
	apperrors "github.com/xmpanel/xmpanel/pkg/errors"
	"github.com/xmpanel/xmpanel/pkg/types"
)

// Re-export errors for convenience
var (
	ErrNotImplemented   = apperrors.ErrNotImplemented
	ErrConnectionFailed = apperrors.ErrConnectionFailed
	ErrAuthFailed       = apperrors.ErrAuthFailed
	ErrUserNotFound     = apperrors.ErrUserNotFound
	ErrUserExists       = apperrors.ErrUserExists
	ErrRoomNotFound     = apperrors.ErrRoomNotFound
	ErrRoomExists       = apperrors.ErrRoomExists
	ErrOperationFailed  = apperrors.ErrOperationFailed
)

// Re-export types for convenience
type (
	ServerInfo = types.ServerInfo
	ModuleInfo = types.ModuleInfo
)

// XMPPAdapter defines the interface for XMPP server adapters
// Both Prosody and ejabberd adapters implement this interface
type XMPPAdapter interface {
	// Connection
	Connect(ctx context.Context) error
	Disconnect() error
	Ping(ctx context.Context) error

	// Server info
	GetServerInfo(ctx context.Context) (*types.ServerInfo, error)
	GetStats(ctx context.Context) (*models.ServerStats, error)

	// User management
	ListUsers(ctx context.Context, domain string) ([]models.XMPPUser, error)
	GetUser(ctx context.Context, username, domain string) (*models.XMPPUser, error)
	CreateUser(ctx context.Context, req models.CreateXMPPUserRequest) error
	DeleteUser(ctx context.Context, username, domain string) error
	ChangePassword(ctx context.Context, username, domain, newPassword string) error

	// Session management
	GetOnlineSessions(ctx context.Context) ([]models.XMPPSession, error)
	GetUserSessions(ctx context.Context, username, domain string) ([]models.XMPPSession, error)
	KickSession(ctx context.Context, jid string) error
	KickUser(ctx context.Context, username, domain string) error

	// MUC (Multi-User Chat) management
	ListRooms(ctx context.Context, mucDomain string) ([]models.XMPPRoom, error)
	GetRoom(ctx context.Context, room, mucDomain string) (*models.XMPPRoom, error)
	CreateRoom(ctx context.Context, req models.CreateXMPPRoomRequest) error
	DeleteRoom(ctx context.Context, room, mucDomain string) error

	// Module management (if supported)
	ListModules(ctx context.Context) ([]types.ModuleInfo, error)
	EnableModule(ctx context.Context, module string) error
	DisableModule(ctx context.Context, module string) error
}

