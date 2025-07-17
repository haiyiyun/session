package session

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"github.com/haiyiyun/cache"
)

// 注册Gob序列化所需的类型
func init() {
	gob.Register(&SessionData{})           // 注册会话数据类型
	gob.Register(map[string]interface{}{}) // 注册map类型
	gob.Register(time.Time{})              // 注册时间类型
}

// CacheAdapter 将基础缓存接口适配为会话专用缓存
type CacheAdapter struct {
	cache.Cache // 嵌入基础缓存接口
}

// NewCacheAdapter 创建新的缓存适配器
func NewCacheAdapter(c cache.Cache) *CacheAdapter {
	return &CacheAdapter{Cache: c}
}

// Get 从缓存获取会话数据并反序列化
func (a *CacheAdapter) Get(sessionID string, target interface{}) (bool, error) {
	var data []byte
	found, err := a.Cache.Get(sessionID, &data)
	if !found || err != nil {
		return found, err
	}

	// 处理空数据情况（防止gob解码错误）
	if len(data) == 0 {
		return false, nil
	}

	// 使用gob解码二进制数据
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return true, dec.Decode(target)
}

// Set 将会话数据序列化后存入缓存
func (a *CacheAdapter) Set(sessionID string, data interface{}, duration time.Duration) error {
	// 空数据特殊处理
	if data == nil {
		return a.Cache.Set(sessionID, []byte{}, duration)
	}

	// 类型安全检查（仅允许SessionData类型）
	if _, ok := data.(*SessionData); !ok {
		return errors.New("invalid session data type")
	}

	// 使用gob编码
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return err
	}

	return a.Cache.Set(sessionID, buf.Bytes(), duration)
}

// Delete 删除会话缓存
func (a *CacheAdapter) Delete(sessionID string) error {
	a.Cache.Delete(sessionID)
	return nil
}

// Add 实现缓存接口（用于分布式锁）
func (a *CacheAdapter) Add(key string, value interface{}, duration time.Duration) error {
	return a.Cache.Add(key, value, duration)
}
