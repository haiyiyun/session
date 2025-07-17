package session

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/haiyiyun/cache"
	"github.com/stretchr/testify/suite"
)

type SessionTestSuite struct {
	suite.Suite
	manager Manager
	mr      *miniredis.Miniredis
	cache   cache.Cache
}

func (s *SessionTestSuite) SetupTest() {
	s.mr = miniredis.RunT(s.T())
	cacheInstance := createTestHYYCache(s.T(), s.mr.Addr())
	s.cache = cacheInstance

	cacheAdapter := NewCacheAdapter(cacheInstance)

	signingKey := []byte("test-signing-key")
	securityTokenKey := []byte("test-security-token-key")
	s.manager = NewManager(
		cacheAdapter,
		signingKey,
		securityTokenKey,
		WithComplianceConfig(ComplianceConfig{
			MaxSessionDuration:    4 * time.Hour,
			InactivityTimeout:     1 * time.Minute,
			PasswordChangeRefresh: true,
		}),
	)
}

func createTestHYYCache(t *testing.T, addr string) cache.Cache {
	local := cache.NewMemoryCache(5*time.Minute, 100*time.Millisecond, 0, 32, false)

	options := cache.RedisOptions{
		Addresses:               []string{addr},
		Compression:             false,
		CompressionThreshold:    1024,
		StreamCompressThreshold: 50*1024*1024 + 1,
		Namespace:               "testns" + strconv.Itoa(os.Getpid()),
	}
	redisCache, err := cache.NewRedisCache(options, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create Redis cache: %v", err)
	}

	return cache.NewHYYCache(local, redisCache)
}

func (s *SessionTestSuite) TestCreateSession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)
	s.NotEmpty(session.ID())
}

func (s *SessionTestSuite) TestGetSession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	retrieved, err := s.manager.Get(ctx, session.ID())
	s.NoError(err)
	s.Equal(session.ID(), retrieved.ID())

	_, err = s.manager.Get(ctx, "invalid-id")
	s.Error(err)
}

func (s *SessionTestSuite) TestGetFromRequest() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp := httptest.NewRecorder()
	s.manager.SetToResponse(resp, session)

	cookie := resp.Result().Cookies()[0]
	req.AddCookie(cookie)

	reqSession, err := s.manager.GetFromRequest(req)
	s.NoError(err)
	s.Equal(session.ID(), reqSession.ID())
}

func (s *SessionTestSuite) TestRefreshSession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 500*time.Millisecond)
	s.NoError(err)

	time.Sleep(200 * time.Millisecond)

	err = s.manager.Refresh(ctx, session.ID(), 30*time.Minute)
	s.NoError(err)

	_, err = s.manager.Get(ctx, session.ID())
	s.NoError(err)
}

func (s *SessionTestSuite) TestDestroySession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	err = s.manager.Destroy(ctx, session.ID())
	s.NoError(err)

	_, err = s.manager.Get(ctx, session.ID())
	s.Error(err)
}

func (s *SessionTestSuite) TestRegenerateSessionID() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	testKey := "test_key"
	testValue := "test_value"
	s.NoError(session.Set(testKey, testValue))

	manager := s.manager.(*sessionManager)
	sessionData := session.(*SessionData)
	if err := manager.cacheAdapter.Set(session.ID(), sessionData, time.Until(sessionData.Expiration)); err != nil {
		s.FailNow("Failed to save session data: %v", err)
	}

	oldData := session.(*SessionData)
	s.NotEmpty(oldData.Data)
	s.Equal(1, len(oldData.Data))

	newID, err := s.manager.RegenerateSessionID(ctx, session.ID())
	s.NoError(err)
	s.NotEqual(session.ID(), newID)

	time.Sleep(100 * time.Millisecond)

	newSession, err := s.manager.Get(ctx, newID)
	s.NoError(err)

	val, found := newSession.Get(testKey)
	s.True(found, "Test data not found")
	s.Equal(testValue, val, "Test data value mismatch")

	newData := newSession.(*SessionData)
	s.Equal(len(oldData.Data), len(newData.Data))
}

func (s *SessionTestSuite) TestInactivityTimeout() {
	manager := s.manager.(*sessionManager)
	manager.complianceConfig.InactivityTimeout = 1 * time.Second

	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	_, err = s.manager.Get(ctx, session.ID())
	s.NoError(err)

	time.Sleep(2 * time.Second)

	_, err = s.manager.Get(ctx, session.ID())
	s.Error(err)
	s.Contains(err.Error(), "inactivity")
}

func (s *SessionTestSuite) TestSecurityTokenValidation() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	manager := s.manager.(*sessionManager)
	key := session.ID()
	manager.cacheAdapter.Cache.Set(key, []byte("invalid binary data"), 30*time.Minute)

	_, err = s.manager.Get(ctx, key)
	s.Error(err)

	s.True(
		strings.Contains(err.Error(), "gob") ||
			strings.Contains(err.Error(), "unexpected EOF"),
		"Expected serialization error, got: %v", err,
	)
}

func (s *SessionTestSuite) TestConcurrency() {
	ctx := context.Background()
	sessionMap := sync.Map{}
	var wg sync.WaitGroup
	results := make(chan struct {
		idx    int
		sessID string
	}, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var sess Session
			var err error
			for retry := 0; retry < 3; retry++ {
				sess, err = s.manager.Create(ctx, 5*time.Minute)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				return
			}

			key := fmt.Sprintf("key%d", idx)
			value := fmt.Sprintf("value%d", idx)
			sess.Set(key, value)

			sessionMap.Store(idx, sess)
			results <- struct {
				idx    int
				sessID string
			}{idx, sess.ID()}
		}(i)
	}
	wg.Wait()
	close(results)

	for result := range results {
		sess, _ := sessionMap.Load(result.idx)
		if session, ok := sess.(Session); ok {
			key := fmt.Sprintf("key%d", result.idx)
			val, found := session.Get(key)
			s.True(found)
			s.Equal(fmt.Sprintf("value%d", result.idx), val)
		} else {
			s.Fail("Session not found")
		}
	}
}

// 创建带路径的请求
func createRequestWithPath(path string) *http.Request {
	req := httptest.NewRequest("GET", "http://example.com"+path, nil)
	return req
}

func (s *SessionTestSuite) TestCookiePath_Level2() {
	manager := NewManager(
		NewCacheAdapter(s.cache),
		[]byte("test-signing-key"),
		[]byte("test-security-token-key"),
		WithCookiePath("/subpath"),
	)

	ctx := context.Background()
	session, err := manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 测试路径匹配的请求
	req := createRequestWithPath("/subpath/test")
	resp := httptest.NewRecorder()
	manager.SetToResponse(resp, session)

	// 验证Cookie路径
	cookies := resp.Result().Cookies()
	s.Len(cookies, 1)
	s.Equal("/subpath", cookies[0].Path)

	// 设置Cookie后发送请求
	req.AddCookie(cookies[0])
	_, err = manager.GetFromRequest(req)
	s.NoError(err, "应能获取到会话")

	// 测试路径不匹配的请求（模拟浏览器行为）
	reqInvalid := createRequestWithPath("/otherpath")
	// 注意：浏览器不会发送路径不匹配的Cookie，所以这里不添加Cookie

	// 直接调用GetFromRequest，期望返回"cookie not found"错误
	_, err = manager.GetFromRequest(reqInvalid)
	s.Error(err, "路径不匹配时不应获取到会话")

	// 检查错误消息是否包含预期内容
	s.True(
		strings.Contains(err.Error(), "cookie not found") ||
			strings.Contains(err.Error(), "named cookie not present"),
		"应为未找到Cookie错误，实际错误: %s", err.Error(),
	)
}

func (s *SessionTestSuite) TestCookiePath_Level3() {
	manager := NewManager(
		NewCacheAdapter(s.cache),
		[]byte("test-signing-key"),
		[]byte("test-security-token-key"),
		WithCookiePath("/subpath"),
	)

	ctx := context.Background()
	session, err := manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 三级目录请求
	req := createRequestWithPath("/subpath/subsub/test")
	resp := httptest.NewRecorder()
	manager.SetToResponse(resp, session)

	cookies := resp.Result().Cookies()
	s.Len(cookies, 1)

	// 三级目录应能使用二级目录的Cookie
	req.AddCookie(cookies[0])
	_, err = manager.GetFromRequest(req)
	s.NoError(err, "三级目录应能使用二级目录设置的Cookie")
}

func (s *SessionTestSuite) TestSameSiteStrictMode() {
	manager := NewManager(
		NewCacheAdapter(s.cache),
		[]byte("test-signing-key"),
		[]byte("test-security-token-key"),
		WithSameSite(http.SameSiteStrictMode), // 设置严格模式
	)

	ctx := context.Background()
	session, err := manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	resp := httptest.NewRecorder()
	manager.SetToResponse(resp, session)

	cookies := resp.Result().Cookies()
	s.Len(cookies, 1)
	s.Equal(http.SameSiteStrictMode, cookies[0].SameSite)
}

func (s *SessionTestSuite) TearDownTest() {
	if closer, ok := s.cache.(interface{ Close() }); ok {
		closer.Close()
	}
	if s.mr != nil {
		s.mr.Close()
	}
}

func TestSessionTestSuite(t *testing.T) {
	suite.Run(t, new(SessionTestSuite))
}
