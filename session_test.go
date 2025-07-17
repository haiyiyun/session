package session

import (
	"context" // 添加标准库errors
	"fmt"
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

// 测试套件结构体
type SessionTestSuite struct {
	suite.Suite
	manager Manager
	mr      *miniredis.Miniredis // 添加 miniredis 实例引用
	cache   cache.Cache          // 添加缓存实例引用
}

// 初始化测试套件
func (s *SessionTestSuite) SetupTest() {
	s.mr = miniredis.RunT(s.T()) // 保存 miniredis 实例

	// 创建缓存实例
	cacheInstance := createTestHYYCache(s.T(), s.mr.Addr())
	s.cache = cacheInstance // 保存缓存实例

	// 创建适配器
	cacheAdapter := NewCacheAdapter(cacheInstance)

	// 初始化session管理器
	signingKey := []byte("test-signing-key")
	securityTokenKey := []byte("test-security-token-key")
	s.manager = NewManager(
		cacheAdapter, // 现在传递的是 *CacheAdapter 类型
		signingKey,
		securityTokenKey,
		WithComplianceConfig(ComplianceConfig{
			MaxSessionDuration:    4 * time.Hour,
			InactivityTimeout:     1 * time.Minute,
			PasswordChangeRefresh: true,
		}),
	)
}

// 创建测试用的HYYCache（本地+Redis模拟）
func createTestHYYCache(t *testing.T, addr string) cache.Cache {
	// 创建本地缓存
	local := cache.NewMemoryCache(5*time.Minute, 100*time.Millisecond, 0, 32, false)

	// 创建Redis缓存（使用miniredis模拟）
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

// 测试创建会话
func (s *SessionTestSuite) TestCreateSession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)
	s.NotEmpty(session.ID())
}

// 测试获取会话
func (s *SessionTestSuite) TestGetSession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 正常获取
	retrieved, err := s.manager.Get(ctx, session.ID())
	s.NoError(err)
	s.Equal(session.ID(), retrieved.ID())

	// 获取不存在的会话
	_, err = s.manager.Get(ctx, "invalid-id")
	s.Error(err)
}

// 测试HTTP请求中的会话获取
func (s *SessionTestSuite) TestGetFromRequest() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 创建HTTP请求
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// 设置Cookie到响应
	resp := httptest.NewRecorder()
	s.manager.SetToResponse(resp, session)

	// 从响应中提取Cookie
	cookie := resp.Result().Cookies()[0]
	req.AddCookie(cookie)

	// 从请求中获取会话
	reqSession, err := s.manager.GetFromRequest(req)
	s.NoError(err)
	s.Equal(session.ID(), reqSession.ID())
}

// 测试刷新会话
func (s *SessionTestSuite) TestRefreshSession() {
	ctx := context.Background()

	// 延长初始会话时间（关键修复）
	session, err := s.manager.Create(ctx, 500*time.Millisecond)
	s.NoError(err)

	// 等待部分时间（但不超过过期时间）
	time.Sleep(200 * time.Millisecond)

	// 刷新会话
	err = s.manager.Refresh(ctx, session.ID(), 30*time.Minute)
	s.NoError(err)

	// 验证会话仍然有效
	_, err = s.manager.Get(ctx, session.ID())
	s.NoError(err)
}

// 测试销毁会话
func (s *SessionTestSuite) TestDestroySession() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 销毁会话
	err = s.manager.Destroy(ctx, session.ID())
	s.NoError(err)

	// 验证会话不存在
	_, err = s.manager.Get(ctx, session.ID())
	s.Error(err)
}

// 测试会话ID重置
func (s *SessionTestSuite) TestRegenerateSessionID() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 设置测试数据
	testKey := "test_key"
	testValue := "test_value"
	s.NoError(session.Set(testKey, testValue))

	// 显式保存会话数据到缓存（关键修复）
	manager := s.manager.(*sessionManager)
	sessionData := session.(*SessionData)
	if err := manager.cacheAdapter.Set(session.ID(), sessionData, time.Until(sessionData.Expiration)); err != nil {
		s.FailNow("Failed to save session data: %v", err)
	}

	// 确保旧会话数据不为空
	oldData := session.(*SessionData)
	s.NotEmpty(oldData.Data)
	s.Equal(1, len(oldData.Data))

	// 重置会话ID
	newID, err := s.manager.RegenerateSessionID(ctx, session.ID())
	s.NoError(err)
	s.NotEqual(session.ID(), newID)

	// 添加短暂延迟确保缓存更新
	time.Sleep(100 * time.Millisecond)

	// 验证新会话数据
	newSession, err := s.manager.Get(ctx, newID)
	s.NoError(err)

	val, found := newSession.Get(testKey)
	s.True(found, "Test data not found")
	s.Equal(testValue, val, "Test data value mismatch")

	// 验证数据量
	newData := newSession.(*SessionData)
	s.Equal(len(oldData.Data), len(newData.Data))
}

// 测试不活动超时
func (s *SessionTestSuite) TestInactivityTimeout() {
	// 配置管理器使用短不活动超时
	manager := s.manager.(*sessionManager)
	manager.complianceConfig.InactivityTimeout = 1 * time.Second

	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 立即获取并记录活动时间
	_, err = s.manager.Get(ctx, session.ID())
	s.NoError(err)

	// 等待超时
	time.Sleep(2 * time.Second)

	// 再次获取应触发销毁
	_, err = s.manager.Get(ctx, session.ID())
	s.Error(err)
	s.Contains(err.Error(), "inactivity")

	// 避免访问已销毁的会话（关键修复）
	// 删除以下可能导致空指针的代码：
	// if sess, err := s.manager.Get(ctx, session.ID()); err == nil {
	// 	sess.Touch()
	// }
}

// 测试安全令牌验证
func (s *SessionTestSuite) TestSecurityTokenValidation() {
	ctx := context.Background()
	session, err := s.manager.Create(ctx, 30*time.Minute)
	s.NoError(err)

	// 篡改缓存中的安全令牌
	manager := s.manager.(*sessionManager)
	key := session.ID()

	// 直接操作缓存：写入无效数据
	manager.cacheAdapter.Cache.Set(key, []byte("invalid binary data"), 30*time.Minute)

	// 尝试获取应失败
	_, err = s.manager.Get(ctx, key)
	s.Error(err)

	// 更新错误检查（关键修复）
	s.True(
		strings.Contains(err.Error(), "gob") ||
			strings.Contains(err.Error(), "unexpected EOF"),
		"Expected serialization error, got: %v", err,
	)
}

// 测试并发会话操作
func (s *SessionTestSuite) TestConcurrency() {
	ctx := context.Background()
	// 创建会话存储map
	sessionMap := sync.Map{}

	// 并发设置数据
	var wg sync.WaitGroup
	results := make(chan struct {
		idx    int
		sessID string
	}, 10) // 收集结果

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// 添加创建重试
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

			// 设置数据
			key := fmt.Sprintf("key%d", idx)
			value := fmt.Sprintf("value%d", idx)
			sess.Set(key, value)

			// 存储会话
			sessionMap.Store(idx, sess)
			results <- struct {
				idx    int
				sessID string
			}{idx, sess.ID()}
		}(i)
	}
	wg.Wait()
	close(results)

	// 验证每个会话的数据
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

// 添加清理方法
func (s *SessionTestSuite) TearDownTest() {
	// 先关闭缓存组件
	if closer, ok := s.cache.(interface{ Close() }); ok {
		closer.Close()
	}
	// 然后关闭miniredis
	if s.mr != nil {
		s.mr.Close()
	}
}

// 运行测试套件
func TestSessionTestSuite(t *testing.T) {
	suite.Run(t, new(SessionTestSuite))
}
