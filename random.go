package util

import (
	"math/rand"
	"time"
)

// Captcha 生成验证码
func Captcha(n int) string {
	return RandNewStr(n, true)
}

// RandNewStr 生成随机字符串
func RandNewStr(n int, onlyDigits bool) string {
	var bytes []byte
	digits := "0123456789"
	ascii_letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if onlyDigits {
		bytes = []byte(digits)
	} else {
		bytes = []byte(digits + ascii_letters)
	}
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
