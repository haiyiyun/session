package session

import "time"

// SessionData 会话核心数据结构（需支持序列化）
type SessionData struct {
	SessionID     string                 `gob:"id"`          // 会话唯一ID
	SecurityToken string                 `gob:"token"`       // 防CSRF令牌
	Data          map[string]interface{} `gob:"data"`        // 用户数据存储
	Expiration    time.Time              `gob:"expire_at"`   // 绝对过期时间
	LastActive    time.Time              `gob:"last_active"` // 最后活动时间（用于空闲超时）
}

// NewSessionData 创建新的会话数据实例
func NewSessionData(id, securityToken string, duration time.Duration) *SessionData {
	return &SessionData{
		SessionID:     id,
		SecurityToken: securityToken,
		Data:          make(map[string]interface{}),
		Expiration:    time.Now().Add(duration),
		LastActive:    time.Now(),
	}
}

// Get 获取会话数据
func (s *SessionData) Get(key string) (interface{}, bool) {
	s.Touch()
	val, ok := s.Data[key]
	return val, ok
}

// Set 设置会话数据
func (s *SessionData) Set(key string, value interface{}) error {
	s.Touch()
	s.Data[key] = value
	return nil
}

// Delete 删除会话数据
func (s *SessionData) Delete(key string) error {
	delete(s.Data, key)
	return nil
}

// ID 返回会话ID
func (s *SessionData) ID() string {
	return s.SessionID
}

// ExpireAt 返回会话过期时间
func (s *SessionData) ExpireAt() time.Time {
	return s.Expiration
}

// Renew 更新会话过期时间
func (s *SessionData) Renew(duration time.Duration) error {
	s.Expiration = time.Now().Add(duration)
	return nil
}

// Destroy 销毁会话（空实现，实际销毁由管理器处理）
func (s *SessionData) Destroy() error {
	return nil
}

// Touch 更新最后活动时间（刷新空闲计时）
func (s *SessionData) Touch() {
	s.LastActive = time.Now() // 使用当前时间更新
}
