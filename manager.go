package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const DefaultSessionDuration = 30 * time.Minute

// sessionManager 会话管理器的具体实现
type sessionManager struct {
	cacheAdapter       *CacheAdapter
	signingKey         []byte           // 会话ID签名密钥
	securityTokenKey   []byte           // 安全令牌密钥
	cookieName         string           // Cookie名称
	secureCookie       bool             // 是否仅HTTPS传输
	browserSessionOnly bool             // 是否浏览器会话有效
	sessionCookie      bool             // 是否会话级Cookie
	complianceConfig   ComplianceConfig // 合规配置
	sessionLock        sync.Mutex       // 会话操作互斥锁
	cookiePath         string           // Cookie 路径
	sameSite           http.SameSite    // SameSite 配置
}

// NewManager 创建会话管理器实例
func NewManager(
	cacheAdapter *CacheAdapter,
	signingKey []byte,
	securityTokenKey []byte,
	options ...Option,
) Manager {
	m := &sessionManager{
		cacheAdapter:     cacheAdapter,
		signingKey:       signingKey,
		securityTokenKey: securityTokenKey,
		cookieName:       "hyy_session_id",
		secureCookie:     true,
		cookiePath:       "/",                  // 默认根路径
		sameSite:         http.SameSiteLaxMode, // 默认 Lax 模式
	}

	for _, opt := range options {
		opt(m)
	}
	return m
}

// Create 创建新会话
func (m *sessionManager) Create(ctx context.Context, duration time.Duration) (Session, error) {
	// 生成唯一会话ID和安全令牌
	sessionID := uuid.New().String()
	securityToken := generateSecurityToken()

	// 创建会话数据对象
	sessionData := NewSessionData(sessionID, securityToken, duration)

	// 存储到缓存
	if err := m.cacheAdapter.Set(sessionID, sessionData, duration); err != nil {
		return nil, err
	}
	return sessionData, nil
}

func (m *sessionManager) Get(ctx context.Context, sessionID string) (Session, error) {
	var data SessionData
	found, err := m.cacheAdapter.Get(sessionID, &data)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("session not found")
	}

	if m.checkInactivity(&data) {
		if err := m.Destroy(ctx, sessionID); err != nil {
			return nil, err
		}
		return nil, errors.New("session expired due to inactivity")
	}

	data.Touch()
	if err := m.cacheAdapter.Set(sessionID, &data, time.Until(data.Expiration)); err != nil {
		return nil, err
	}

	return &data, nil
}

func (m *sessionManager) GetFromRequest(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		// 包装标准错误为更友好的消息
		if err == http.ErrNoCookie {
			return nil, errors.New("cookie not found")
		}
		return nil, err
	}

	// 首先验证路径：确保请求路径在Cookie路径范围内
	if !pathMatch(r.URL.Path, cookie.Path) {
		return nil, errors.New("path mismatch")
	}

	sessionID, valid := m.verifySignature(cookie.Value)
	if !valid {
		return nil, errors.New("invalid session signature")
	}

	return m.Get(r.Context(), sessionID)
}

func (m *sessionManager) SetToResponse(w http.ResponseWriter, s Session) {
	signedValue := m.signSessionID(s.ID())

	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    signedValue,
		Path:     m.cookiePath, // 使用配置的路径
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: m.sameSite, // 使用配置的 SameSite 模式
	}

	if !m.sessionCookie {
		cookie.Expires = s.ExpireAt()
	}

	http.SetCookie(w, cookie)
}

func (m *sessionManager) signSessionID(sessionID string) string {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(sessionID))
	signature := mac.Sum(nil)
	return fmt.Sprintf("%s.%s", sessionID, base64.URLEncoding.EncodeToString(signature))
}

func (m *sessionManager) verifySignature(signedValue string) (string, bool) {
	parts := strings.SplitN(signedValue, ".", 2)
	if len(parts) != 2 {
		return "", false
	}

	sessionID := parts[0]
	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}

	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(sessionID))
	expectedSignature := mac.Sum(nil)

	return sessionID, hmac.Equal(signature, expectedSignature)
}

func (m *sessionManager) Destroy(ctx context.Context, sessionID string) error {
	return m.cacheAdapter.Delete(sessionID)
}

func (m *sessionManager) Refresh(ctx context.Context, sessionID string, duration time.Duration) error {
	sess, err := m.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	if sd, ok := sess.(*SessionData); ok {
		if err := sd.Renew(duration); err != nil {
			return err
		}
		if m.complianceConfig.MaxSessionDuration > 0 {
			duration = min(duration, m.complianceConfig.MaxSessionDuration)
		}
		return m.cacheAdapter.Set(sessionID, sd, duration)
	}
	return errors.New("session data type error")
}

func (m *sessionManager) RegenerateSessionID(ctx context.Context, oldSessionID string) (string, error) {
	m.sessionLock.Lock() // 全局锁防止并发冲突
	defer m.sessionLock.Unlock()

	// 获取分布式锁（防并发）
	lockKey := "hyy_session_lock:" + oldSessionID
	if err := m.cacheAdapter.Add(lockKey, "hyy_locked", 5*time.Second); err != nil {
		return "", errors.New("acquire lock failed")
	}
	defer m.cacheAdapter.Delete(lockKey) // 确保释放锁

	// 获取旧会话数据
	sess, err := m.Get(ctx, oldSessionID)
	if err != nil {
		return "", err
	}
	oldSessionData := sess.(*SessionData) // 类型断言

	// 创建新会话
	newSessionID := uuid.New().String()
	// 修复：添加正确的参数
	newSessionData := NewSessionData(
		newSessionID,                          // 新会话ID
		generateSecurityToken(),               // 生成安全令牌
		time.Until(oldSessionData.Expiration), // 使用原会话的剩余时间
	)

	// 深度复制数据（关键步骤）
	for k, v := range oldSessionData.Data {
		newSessionData.Data[k] = v
	}

	// 保存新会话
	if err := m.cacheAdapter.Set(newSessionID, newSessionData, time.Until(newSessionData.Expiration)); err != nil {
		return "", err
	}

	// 删除旧会话（重试机制）
	for i := 0; i < 3; i++ {
		if err := m.cacheAdapter.Delete(oldSessionID); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return newSessionID, nil
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (m *sessionManager) checkInactivity(s *SessionData) bool {
	if m.complianceConfig.InactivityTimeout > 0 {
		inactiveTime := time.Since(s.LastActive)
		return inactiveTime > m.complianceConfig.InactivityTimeout
	}
	return false
}

// 标准库的路径匹配逻辑 (来自 net/http/cookie.go)
func pathMatch(requestPath, cookiePath string) bool {
	if len(requestPath) == 0 {
		requestPath = "/"
	}
	if len(cookiePath) == 0 {
		cookiePath = "/"
	}

	if requestPath == cookiePath {
		return true
	}
	if strings.HasPrefix(requestPath, cookiePath) {
		if cookiePath[len(cookiePath)-1] == '/' {
			return true // "/foo/" matches "/foo/bar"
		} else if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true // "/foo" matches "/foo/bar"
		}
	}
	return false
}
