package session

import (
	"net/http"
)

type Session interface {
	Get(http.ResponseWriter, *http.Request) map[string]interface{}
	Set(map[string]interface{}, http.ResponseWriter, *http.Request)
	SetCookieExpires(map[string]interface{}, int)
}
