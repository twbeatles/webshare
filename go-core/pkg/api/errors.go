// Package api ports utils/api_errors.py: the shared JSON error schema and
// request-ID contract. Error-like payloads are normalized exactly like
// normalize_error_response_payload: existing keys win, 5xx messages are
// masked (except 507), request_id always present.
package api

import (
	"encoding/json"
	"net/http"
)

// CodeByStatus mirrors DEFAULT_ERROR_BY_STATUS.
var CodeByStatus = map[int]string{
	400: "BAD_REQUEST",
	401: "UNAUTHORIZED",
	403: "FORBIDDEN",
	404: "NOT_FOUND",
	405: "METHOD_NOT_ALLOWED",
	409: "CONFLICT",
	413: "PAYLOAD_TOO_LARGE",
	415: "UNSUPPORTED_MEDIA_TYPE",
	422: "UNPROCESSABLE_ENTITY",
	429: "TOO_MANY_REQUESTS",
	500: "INTERNAL_ERROR",
	502: "BAD_GATEWAY",
	503: "SERVICE_UNAVAILABLE",
	504: "GATEWAY_TIMEOUT",
	507: "INSUFFICIENT_STORAGE",
}

// codeFor returns the mapped code or "ERROR".
func codeFor(status int) string {
	if c, ok := CodeByStatus[status]; ok {
		return c
	}
	return "ERROR"
}

// Normalize mirrors normalize_error_response_payload for an error payload.
func Normalize(payload map[string]any, status int, requestID string) map[string]any {
	out := map[string]any{}
	for k, v := range payload {
		out[k] = v
	}
	msg, _ := out["message"].(string)
	if msg == "" {
		msg, _ = out["error"].(string)
	}
	if msg == "" {
		msg = codeFor(status)
	}
	if status >= 500 && status != 507 {
		msg = "서버 내부 오류가 발생했습니다."
	}
	if _, ok := out["success"]; !ok {
		out["success"] = false
	}
	if status >= 500 && status != 507 {
		out["error"] = msg
	} else if _, ok := out["error"]; !ok {
		out["error"] = msg
	}
	if _, ok := out["code"]; !ok {
		out["code"] = codeFor(status)
	}
	out["message"] = msg
	if _, ok := out["request_id"]; !ok {
		out["request_id"] = requestID
	}
	return out
}

// Error writes a normalized JSON error with the request's ID.
func Error(w http.ResponseWriter, r *http.Request, status int, message string) {
	id := ""
	if r != nil {
		id, _ = r.Context().Value(RequestIDKey{}).(string)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Normalize(map[string]any{"error": message}, status, id))
}

// RequestIDKey is the context key for the request ID (shared with server middleware).
type RequestIDKey struct{}

// RequestID returns the request ID from context, or "".
func RequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(RequestIDKey{}).(string)
	return id
}
