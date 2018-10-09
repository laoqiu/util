package util

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	TokenInvalid = errors.New("invalid token")
	TokenExpired = errors.New("token expired")
)

// GeneratePassword 生成hash密码
func GeneratePassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

// ValidPassword 验证hash密码
func ValidPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HMACEncode hmac加密
func HMACEncode(secret string, s string) string {
	hash := hmac.New(sha1.New, []byte(secret))
	hash.Write([]byte(s))
	estring := hex.EncodeToString(hash.Sum(nil))
	return estring
}

// GenerateToken 创建token
func GenerateToken(secret string, data interface{}) (sign string, err error) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	created := time.Now().Unix()
	// base64处理信息
	s := base64.StdEncoding.EncodeToString(b)
	message := strconv.FormatInt(created, 10) + "." + s
	// 加密
	sign = message + "." + HMACEncode(secret, message)
	return
}

// ValidToken 验证签名
func ValidToken(secret string, token string, expires int64) ([]byte, error) {
	s := strings.Split(token, ".")
	if len(s) < 3 {
		return nil, TokenInvalid
	}
	t, data, sign := s[0], s[1], s[2]
	// 判断有效期
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n+expires < time.Now().Unix() {
		return nil, TokenExpired
	}
	// 解析内容
	d, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, TokenInvalid
	}
	// 验证签名
	if HMACEncode(secret, data) != sign {
		return nil, TokenInvalid
	}
	return d, nil
}
