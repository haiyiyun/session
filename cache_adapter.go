package session

import (
	"bytes"
	"encoding/gob"
	"errors" // 使用标准库替代第三方包
	"time"

	"github.com/haiyiyun/cache"
)

func init() {
	// 注册会话数据类型
	gob.Register(&SessionData{})
	gob.Register(map[string]interface{}{})
	gob.Register(time.Time{}) // 注册时间类型
}

// CacheAdapter 缓存适配器 - 简化版
type CacheAdapter struct {
	cache.Cache // 直接嵌入缓存接口
}

func NewCacheAdapter(c cache.Cache) *CacheAdapter {
	return &CacheAdapter{Cache: c}
}

func (a *CacheAdapter) Get(sessionID string, target interface{}) (bool, error) {
	// 使用原始 Get 方法
	var data []byte
	found, err := a.Cache.Get(sessionID, &data)
	if !found || err != nil {
		return found, err
	}

	// 处理空数据情况（最终修复）
	if len(data) == 0 {
		return false, nil
	}

	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return true, dec.Decode(target)
}

func (a *CacheAdapter) Set(sessionID string, data interface{}, duration time.Duration) error {
	// 添加类型检查（关键修复）
	if _, ok := data.(*SessionData); !ok && data != nil {
		return errors.New("invalid session data type") // 使用标准库
	}

	// 处理空值情况（关键修复）
	if data == nil {
		return a.Cache.Set(sessionID, []byte{}, duration)
	}

	// 使用 gob 进行深度序列化
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return err
	}

	// 使用原始 Set 方法（关键修复）
	return a.Cache.Set(sessionID, buf.Bytes(), duration)
}

func (a *CacheAdapter) Delete(sessionID string) error {
	a.Cache.Delete(sessionID)
	return nil
}
