package redissession

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"io"
	"net/http"
	"sync"

	"github.com/garyburd/redigo/redis"
	"go.haiyiyun.org/log"
	"go.haiyiyun.org/utils/help"
	// "time"
)

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

type SessionManager struct {
	pool         *redis.Pool
	CookieName   string
	CookieDomain string
	rmutex       sync.RWMutex
	mutex        sync.Mutex
	sessions     map[string]interface{}
	expires      int
}

func New(pool *redis.Pool, cookieName, cookieDomain string, expires int) *SessionManager {
	if cookieName == "" {
		cookieName = "HaiyiyunSession"
	}

	if expires <= 0 {
		expires = 3600 * 24
	}

	s := &SessionManager{
		pool:         pool,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		expires:      expires,
	}

	return s
}

func (s *SessionManager) Get(rw http.ResponseWriter, req *http.Request) map[string]interface{} {
	var sessionSign string

	s.rmutex.RLock()
	defer s.rmutex.RUnlock()
	log.Debug("<GET> CookieName:", s.CookieName)
	c, err := req.Cookie(s.CookieName)
	if err == nil {
		sessionSign = c.Value
		log.Debug("<GET> ", "sessionSign:", sessionSign)
		log.Debug("<GET> ", "pool:", s.pool.Get())
		session_string, err := redis.String(s.pool.Get().Do("GET", sessionSign))
		if err != nil {
			log.Debug("<GET> ", "redis_get_error:", err)
			return map[string]interface{}{}
		}
		log.Debug("<GET> ", "redis_get_session:", session_string)
		session, err := decodeGob([]byte(session_string))
		if err != nil {
			log.Debug("<GET> ", "session_decode_error:", err)
			return map[string]interface{}{}
		}
		log.Debug("<GET> ", "redis_get_session:", session)
		return session

	}
	log.Error("<GET> error:", err)
	log.Debug("<GET> ", "no_cookie_name")
	s.new(rw)
	return map[string]interface{}{}
}

func (s *SessionManager) Set(session map[string]interface{}, rw http.ResponseWriter, req *http.Request) {
	s.SetEX(session, rw, req, s.expires)
}

//设置session和cookie
func (s *SessionManager) SetEX(session map[string]interface{}, rw http.ResponseWriter, req *http.Request, exprie int) {
	s.rmutex.RLock()
	cookieName := s.CookieName
	s.rmutex.RUnlock()

	if c, err := req.Cookie(cookieName); err == nil {
		sessionSign := c.Value
		lsess := len(session)
		if lsess == 0 {
			// s.Clear(sessionSign)
			help.SetCookie(rw, nil, cookieName, "", -3600)
			return
		}
		session_string, err := encodeGob(session)
		if err != nil {
			log.Debug("<SET> ", "session_encode_error:", err)
			return
		}
		log.Debug("<SET> ", "session_encode:", session_string)
		_, err = s.pool.Get().Do("SETEX", sessionSign, exprie, session_string)
		if err != nil {
			log.Debug("<SET> ", "session_set_error:", err)
			return
		}
	}
}
func (s *SessionManager) Clear(rw http.ResponseWriter, req *http.Request) {
	s.rmutex.RLock()
	cookieName := s.CookieName
	s.rmutex.RUnlock()

	if c, err := req.Cookie(cookieName); err == nil {
		sessionSign := c.Value

		_, err = s.pool.Get().Do("DEL", sessionSign)
		if err != nil {
			log.Debug("<SET> ", "session_del_error:", err)
			return
		}
		help.SetCookie(rw, nil, cookieName, "", -3600)
	}
}

func (s *SessionManager) Len() int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return int64(len(s.sessions))
}

func (s *SessionManager) new(rw http.ResponseWriter) string {
	//timeNano := time.Now().UnixNano()
	s.rmutex.RLock()
	cookieName := s.CookieName
	cookieDomain := s.CookieDomain
	sessionSign := s.sessionSign()
	s.rmutex.RUnlock()

	help.SetCookie(rw, nil, cookieName, sessionSign, 0, "/", cookieDomain, true)

	log.Debug("<new> sessionSign:", sessionSign)
	return sessionSign
}

func (s *SessionManager) sessionSign() string {
	var n int = 24
	b := make([]byte, n)
	io.ReadFull(rand.Reader, b)

	//return length:32
	return base64.URLEncoding.EncodeToString(b)
}
