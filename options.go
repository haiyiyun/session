package session

import (
	"net/http"
	"time"
)

type Option func(*sessionManager)

type ComplianceConfig struct {
	MaxSessionDuration    time.Duration
	InactivityTimeout     time.Duration
	PasswordChangeRefresh bool
}

func WithCookieName(name string) Option {
	return func(m *sessionManager) {
		m.cookieName = name
	}
}

func WithSecureCookie(secure bool) Option {
	return func(m *sessionManager) {
		m.secureCookie = secure
	}
}

func WithBrowserSessionOnly(browserSessionOnly bool) Option {
	return func(m *sessionManager) {
		m.browserSessionOnly = browserSessionOnly
	}
}

func WithSessionCookie(sessionCookie bool) Option {
	return func(m *sessionManager) {
		m.sessionCookie = sessionCookie
	}
}

func WithSecurityTokenKey(key []byte) Option {
	return func(m *sessionManager) {
		m.securityTokenKey = key
	}
}

func WithCookieConfig(name string, secure bool) Option {
	return func(m *sessionManager) {
		m.cookieName = name
		m.secureCookie = secure
	}
}

func WithComplianceConfig(config ComplianceConfig) Option {
	return func(m *sessionManager) {
		m.complianceConfig = config
	}
}

func WithCookiePath(path string) Option {
	return func(m *sessionManager) {
		m.cookiePath = path
	}
}

// 添加 SameSite 配置选项
func WithSameSite(sameSite http.SameSite) Option {
	return func(m *sessionManager) {
		m.sameSite = sameSite
	}
}
