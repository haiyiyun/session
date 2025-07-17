package session

import (
	"context"
	"net/http"
	"time"
)

// Session 接口定义 - 专注于session核心功能
type Session interface {
	ID() string
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}) error
	Delete(key string) error
	ExpireAt() time.Time
	Renew(duration time.Duration) error
	Destroy() error
	Touch()
}

// Manager 管理接口
type Manager interface {
	Create(ctx context.Context, duration time.Duration) (Session, error)
	Get(ctx context.Context, sessionID string) (Session, error)
	GetFromRequest(r *http.Request) (Session, error)
	SetToResponse(w http.ResponseWriter, s Session)
	Destroy(ctx context.Context, sessionID string) error
	Refresh(ctx context.Context, sessionID string, duration time.Duration) error
	RegenerateSessionID(ctx context.Context, oldSessionID string) (string, error)
}
