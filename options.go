package session

// 配置选项
type Option func(*sessionManager)

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

// 强制要求安全密钥配置
func WithSecurityTokenKey(key []byte) Option {
	return func(m *sessionManager) {
		m.securityTokenKey = key
	}
}

// 提供默认值但允许覆盖
func WithCookieConfig(name string, secure bool) Option {
	return func(m *sessionManager) {
		m.cookieName = name
		m.secureCookie = secure
	}
}

// 新增合规性配置选项
func WithComplianceConfig(config ComplianceConfig) Option {
	return func(m *sessionManager) {
		m.complianceConfig = config
	}
}
