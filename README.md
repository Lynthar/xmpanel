# XMPanel

A secure, modern web administration panel for XMPP servers. Supports both **Prosody** and **ejabberd** with a unified interface.

## Features

### Multi-Server Support
- Manage multiple XMPP servers from a single dashboard
- Support for both Prosody and ejabberd
- Unified API adapter pattern for consistent operations

### XMPP Management
- **User Management**: Create, delete, and manage XMPP users
- **Session Management**: View online users, kick sessions
- **MUC Rooms**: Create and manage chat rooms
- **Server Statistics**: Real-time monitoring of server metrics

### Security Features
- **Authentication**: JWT-based authentication with short-lived tokens
- **MFA/2FA**: TOTP-based two-factor authentication
- **Password Security**: Argon2id hashing with configurable parameters
- **Rate Limiting**: Protection against brute-force attacks
- **Audit Logging**: Tamper-evident audit trail with chain hashing
- **RBAC**: Role-based access control (SuperAdmin, Admin, Operator, Viewer, Auditor)
- **Encryption**: AES-256-GCM encryption for sensitive data at rest

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Web UI (React + TS)                   │
└────────────────────────────┬────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────┐
│                    Backend API (Go)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │
│  │ Auth/RBAC│  │ Audit Log│  │  Config  │  │ Crypto  │  │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘  │
└────────────────────────────┬────────────────────────────┘
                             │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────┴───────┐     ┌───────┴───────┐     ┌───────┴───────┐
│    Prosody    │     │    ejabberd   │     │     Proxy     │
│    Adapter    │     │    Adapter    │     │    Monitor    │
└───────────────┘     └───────────────┘     └───────────────┘
```

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+
- SQLite3 (default) or PostgreSQL

### Installation

1. Clone the repository:
```bash
git clone https://github.com/xmpanel/xmpanel.git
cd xmpanel
```

2. Copy and configure the config file:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

3. Generate an encryption key:
```bash
# Use this to generate a secure encryption key
openssl rand -base64 32
# Add the key to config.yaml under database.encryption_key
```

4. Build the project:
```bash
make deps
make build
```

5. Run the server:
```bash
./xmpanel
```

The server will start on `http://localhost:8080` by default.

### Development

Run backend and frontend separately for development:

```bash
# Terminal 1: Backend
make run

# Terminal 2: Frontend (with hot reload)
make dev-frontend
```

## Configuration

See `config.example.yaml` for all configuration options.

### Key Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `server.address` | Server listen address | `:8080` |
| `server.tls.enabled` | Enable TLS | `false` |
| `database.driver` | Database driver (sqlite/postgres) | `sqlite` |
| `database.encryption_key` | Key for encrypting sensitive data | Required |
| `security.jwt.secret` | JWT signing secret | Required |
| `security.mfa.required` | Require MFA for all users | `false` |

## XMPP Server Configuration

### Prosody Setup

Enable the HTTP admin API module in Prosody:

```lua
-- prosody.cfg.lua
modules_enabled = {
    -- ... other modules
    "http_admin_api";
}

http_admin_api_credentials = "your-api-key"
```

### ejabberd Setup

Enable the HTTP API in ejabberd:

```yaml
# ejabberd.yml
listen:
  -
    port: 5280
    module: ejabberd_http
    request_handlers:
      /api: mod_http_api

api_permissions:
  "admin access":
    who:
      - access:
          - allow:
              user: admin@example.com
    what:
      - "*"
      - "!stop"
      - "!start"
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get current user

### Users (Admin only)
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user

### Servers
- `GET /api/v1/servers` - List servers
- `POST /api/v1/servers` - Add server
- `GET /api/v1/servers/:id/stats` - Get server stats
- `POST /api/v1/servers/:id/test` - Test connection

### XMPP Operations
- `GET /api/v1/servers/:id/users` - List XMPP users
- `POST /api/v1/servers/:id/users` - Create XMPP user
- `DELETE /api/v1/servers/:id/users/:username` - Delete XMPP user
- `GET /api/v1/servers/:id/sessions` - List sessions
- `GET /api/v1/servers/:id/rooms` - List MUC rooms

### Audit
- `GET /api/v1/audit` - List audit logs
- `GET /api/v1/audit/verify` - Verify log integrity
- `GET /api/v1/audit/export` - Export as CSV

## Security Considerations

1. **Always use TLS in production**
2. **Set a strong JWT secret** (at least 32 characters)
3. **Enable MFA for all admin users**
4. **Use a strong database encryption key**
5. **Regularly rotate API keys**
6. **Monitor audit logs for suspicious activity**
7. **Keep the software updated**

## Roles and Permissions

| Role | Description | Permissions |
|------|-------------|-------------|
| SuperAdmin | Full access | All operations |
| Admin | Server management | Users, servers, XMPP operations, audit read |
| Operator | Day-to-day operations | Server read, XMPP operations |
| Viewer | Read-only access | Server read, XMPP read |
| Auditor | Audit access | Audit logs, server read |

## License

MIT License - see [LICENSE](LICENSE) for details.
