/*
为避免任何隐藏麻烦，在Encode时如失败不会去尝试gob.Register注册，会直接报错。
以免上一次Encode失败时尝试注册的的类型再Decode时不被识别到，而报错。
顾在程序运行时，尽可能完整的做好测试，再遇到Encode出错时，预注册好此用户自定义类型
注册方式可以：
import "encoding/gob"
func init() {
	gob.Register([UserType的初始化])
}
*/

package cookiesession

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"github.com/haiyiyun/log"
	"github.com/haiyiyun/utils/help"
	"net/http"
	"strings"
)

func init() {
	gob.Register([]interface{}{})
	gob.Register(map[int]interface{}{})
	gob.Register(map[string]interface{}{})
	gob.Register(map[interface{}]interface{}{})
	gob.Register(map[string]string{})
	gob.Register(map[int]string{})
	gob.Register(map[int]int{})
	gob.Register(map[int]int64{})
}

func encodeGob(obj map[string]interface{}) (string, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(obj)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func decodeGob(encoded []byte) (map[string]interface{}, error) {
	buf := bytes.NewBuffer(encoded)
	dec := gob.NewDecoder(buf)
	var out map[string]interface{}
	err := dec.Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func encodeCookie(content map[string]interface{}, key, iv []byte) (string, error) {
	sessionGob, err := encodeGob(content)
	if err != nil {
		log.Error("<encodeCookie> ", err)
		return "", err
	}

	//实现动态填充,达到aes.BlockSize的倍数,+4是为了后面提供4个字节来保存字符串长度使用的
	padLen := aes.BlockSize - (len(sessionGob)+4)%aes.BlockSize
	buf := bytes.NewBuffer(nil)
	var sessionLen int32 = (int32)(len(sessionGob))
	binary.Write(buf, binary.BigEndian, sessionLen)
	buf.WriteString(sessionGob)
	buf.WriteString(strings.Repeat("\000", padLen))
	sessionBytes := buf.Bytes()
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	encrypter.CryptBlocks(sessionBytes, sessionBytes)
	b64 := base64.URLEncoding.EncodeToString(sessionBytes)
	return b64, nil
}

func decodeCookie(encodedCookie string, key, iv []byte) (map[string]interface{}, error) {
	sessionBytes, err := base64.URLEncoding.DecodeString(encodedCookie)
	if err != nil {
		log.Error("<decodeCookie> ", "base64.Decodestring:", err)
		return nil, err
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Error("<decodeCookie> ", "aes.NewCipher:", err)
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypter.CryptBlocks(sessionBytes, sessionBytes)

	buf := bytes.NewBuffer(sessionBytes)
	var gobLen int32
	binary.Read(buf, binary.BigEndian, &gobLen)
	gobBytes := sessionBytes[4 : 4+gobLen]
	session, err := decodeGob(gobBytes)
	if err != nil {
		log.Error("<decodeCookie> ", "decodeGob:", err)
		return nil, err
	}
	return session, nil
}

type SessionManager struct {
	CookieName   string
	CookieDomain string
	key          []byte
	iv           []byte
}

func New(cookieName, key, cookieDomain string) *SessionManager {
	if cookieName == "" {
		cookieName = "HaiyiyunCookieSession"
	}

	if key == "" {
		key = "Haiyiyun Support CookieSession"
	}

	keySha1 := sha1.New()
	keySha1.Write([]byte(key))
	sum := keySha1.Sum(nil)
	return &SessionManager{
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		key:          sum[:16],
		iv:           sum[4:],
	}
}

func (s *SessionManager) SetCookieExpires(session map[string]interface{}, cookieExpires int) {
	session["__cookieExpires"] = cookieExpires
}

func (s *SessionManager) Get(req *http.Request) map[string]interface{} {
	cookie, err := req.Cookie(s.CookieName)
	if err != nil {
		return map[string]interface{}{}
	}
	session, err := decodeCookie(cookie.Value, s.key, s.iv)
	if err != nil {
		return map[string]interface{}{}
	}

	return session
}

func (s *SessionManager) Set(session map[string]interface{}, rw http.ResponseWriter, req *http.Request) {
	origCookie, err := req.Cookie(s.CookieName)
	var origCookieVal string
	if err != nil {
		origCookieVal = ""
	} else {
		origCookieVal = origCookie.Value
	}

	if len(session) == 0 {
		if origCookieVal != "" {
			help.SetCookie(rw, nil, s.CookieName, "", -3600)
		}
	} else {
		var cookieExpires int
		if ce, ok := session["__cookieExpires"].(int); ok {
			cookieExpires = ce
		}

		if encoded, err := encodeCookie(session, s.key, s.iv); err == nil {
			if encoded != origCookieVal {
				help.SetCookie(rw, nil, s.CookieName, encoded, cookieExpires, "/", s.CookieDomain, true)
			}
		}
	}
}
