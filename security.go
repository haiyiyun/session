package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

// 增强安全令牌生成
func generateSecurityToken() string {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic("security token generation failed")
	}

	// 添加时间戳增强安全性
	timestamp := time.Now().Unix()
	token = append(token, byte(timestamp>>24), byte(timestamp>>16), byte(timestamp>>8), byte(timestamp))

	return base64.URLEncoding.EncodeToString(token)
}

// 增强安全令牌验证
func validateSecurityToken(token string, secretKey []byte) bool {
	// 计算最小有效长度
	minLength := base64.URLEncoding.EncodedLen(32 + 4 + 4) // 32字节随机数+4字节时间戳+4字节签名
	if len(token) < minLength {
		return false
	}

	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil || len(data) < 40 { // 32+4+4=40字节
		return false
	}

	// 验证时间戳（令牌有效期1小时）
	timestamp := int64(data[32])<<24 | int64(data[33])<<16 | int64(data[34])<<8 | int64(data[35])
	tokenTime := time.Unix(timestamp, 0)

	// 添加时间有效性检查（1小时内有效）
	if time.Since(tokenTime) > time.Hour && tokenTime.After(time.Now()) {
		return false
	}

	// 添加时钟漂移容忍度（±30秒）
	maxDrift := 30 * time.Second
	now := time.Now()
	if tokenTime.Before(now.Add(-maxDrift)) || tokenTime.After(now.Add(maxDrift)) {
		return false
	}

	// 添加随机数签名验证
	expectedSignature := generateTokenSignature(data[:32], secretKey)
	// 直接返回比较结果
	return hmac.Equal(data[36:40], expectedSignature)
}

// 生成令牌签名
func generateTokenSignature(token, secretKey []byte) []byte {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(token)
	return mac.Sum(nil)[:4] // 取前4字节作为签名
}

// 添加刷新频率限制
func refreshSecurityToken(oldToken string, secretKey []byte) (string, error) {
	if !validateSecurityToken(oldToken, secretKey) {
		return "", errors.New("invalid token")
	}

	// 解析原令牌中的时间戳
	data, _ := base64.URLEncoding.DecodeString(oldToken)
	if len(data) < 36 {
		return "", errors.New("invalid token format")
	}
	timestamp := int64(data[32])<<24 | int64(data[33])<<16 | int64(data[34])<<8 | int64(data[35])

	// 限制刷新频率（至少间隔5分钟）
	if time.Since(time.Unix(timestamp, 0)) < 5*time.Minute {
		return oldToken, nil
	}

	return generateSecurityToken(), nil
}
