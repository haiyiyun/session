package session

import (
	"time"
)

// SessionData 会话数据结构
type SessionData struct {
	SessionID     string                 `gob:"id"`
	SecurityToken string                 `gob:"token"`
	Data          map[string]interface{} `gob:"data"` // 简化数据结构
	Expiration    time.Time              `gob:"expire_at"`
	LastActive    time.Time              `gob:"last_active"`
}

func NewSessionData(id, securityToken string, duration time.Duration) *SessionData {
	return &SessionData{
		SessionID:     id,
		SecurityToken: securityToken,
		Data:          make(map[string]interface{}),
		Expiration:    time.Now().Add(duration),
		LastActive:    time.Now(),
	}
}

// 删除所有分片相关代码
// 简化 Get/Set/Delete 方法：
func (s *SessionData) Get(key string) (interface{}, bool) {
	s.Touch()
	val, ok := s.Data[key]
	return val, ok
}

func (s *SessionData) Set(key string, value interface{}) error {
	s.Touch()
	s.Data[key] = value
	return nil
}

func (s *SessionData) Delete(key string) error {
	delete(s.Data, key)
	return nil
}

func (s *SessionData) ID() string {
	return s.SessionID
}

func (s *SessionData) ExpireAt() time.Time {
	return s.Expiration // 更新引用
}

func (s *SessionData) Renew(duration time.Duration) error {
	s.Expiration = time.Now().Add(duration) // 更新引用
	return nil
}

func (s *SessionData) Destroy() error {
	// 实际销毁由Manager处理
	return nil
}

func (s *SessionData) Touch() {
	s.LastActive = time.Now()
}
