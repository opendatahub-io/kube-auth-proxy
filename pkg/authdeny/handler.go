package authdeny

import "net/http"

// Handler can override the default denial response for matched requests.
// Returning true means the handler wrote the complete response and the caller
// must stop. Returning false means the caller should continue with the
// existing fallback behavior.
type Handler interface {
	Handle(rw http.ResponseWriter, req *http.Request, statusCode int) bool
}
