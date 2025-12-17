package types

// ServerType represents the type of XMPP server
type ServerType string

const (
	ServerTypeProsody  ServerType = "prosody"
	ServerTypeEjabberd ServerType = "ejabberd"
)

// ServerInfo contains information about the XMPP server
type ServerInfo struct {
	Type        ServerType `json:"type"`
	Version     string     `json:"version"`
	Hostname    string     `json:"hostname"`
	Domains     []string   `json:"domains"`
	Features    []string   `json:"features"`
	StartupTime int64      `json:"startup_time"`
}

// ModuleInfo contains information about a server module
type ModuleInfo struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}
