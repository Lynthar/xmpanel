package handler

import (
	"database/sql"
	"errors"

	"github.com/xmpanel/xmpanel/internal/adapter"
	"github.com/xmpanel/xmpanel/internal/adapter/ejabberd"
	"github.com/xmpanel/xmpanel/internal/adapter/prosody"
	"github.com/xmpanel/xmpanel/internal/security/crypto"
	"github.com/xmpanel/xmpanel/internal/store"
	"github.com/xmpanel/xmpanel/internal/store/models"
)

// GetXMPPAdapter retrieves a server from the database and creates the appropriate adapter
func GetXMPPAdapter(db *store.DB, keyRing *crypto.KeyRing, serverID int64) (adapter.XMPPAdapter, error) {
	var server models.XMPPServer
	var encryptedAPIKey sql.NullString

	err := db.QueryRow(`
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
	if encryptedAPIKey.Valid && keyRing != nil {
		decrypted, err := keyRing.DecryptString(encryptedAPIKey.String)
		if err != nil {
			return nil, err
		}
		apiKey = decrypted
	}

	return NewXMPPAdapter(&server, apiKey)
}

// NewXMPPAdapter creates an adapter based on server type
func NewXMPPAdapter(server *models.XMPPServer, apiKey string) (adapter.XMPPAdapter, error) {
	switch server.Type {
	case models.ServerTypeProsody:
		return prosody.NewAdapter(server, apiKey), nil
	case models.ServerTypeEjabberd:
		return ejabberd.NewAdapter(server, apiKey), nil
	default:
		return nil, errors.New("unsupported server type: " + string(server.Type))
	}
}
