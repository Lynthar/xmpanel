package errors

import "errors"

// XMPP adapter errors
var (
	ErrNotImplemented   = errors.New("operation not implemented")
	ErrConnectionFailed = errors.New("failed to connect to server")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrUserNotFound     = errors.New("user not found")
	ErrUserExists       = errors.New("user already exists")
	ErrRoomNotFound     = errors.New("room not found")
	ErrRoomExists       = errors.New("room already exists")
	ErrOperationFailed  = errors.New("operation failed")
)
