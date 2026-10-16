package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

const maxCoworkTrafficBody = 2 * 1024 * 1024

// GET /api/tasks/{id}/cowork/traffic returns only captures whose stable ID is
// bound to this task. It does not expose proxy-captured or other-task traffic.
func (s *Server) coworkListTraffic(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	tr := s.m.Traffic()
	if tr == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "total": 0, "exchanges": []any{}})
		return
	}
	page, err := parseCoworkTrafficInt(r.URL.Query().Get("page"), 0)
	if err != nil || page < 0 || page > 1_000_000 {
		writeErr(w, http.StatusBadRequest, "page must be an integer between 0 and 1000000")
		return
	}
	size, err := parseCoworkTrafficInt(r.URL.Query().Get("size"), 50)
	if err != nil || size < 1 || size > 100 {
		writeErr(w, http.StatusBadRequest, "size must be between 1 and 100")
		return
	}
	prefix := "cowork-t" + t.ID + "-"
	exchanges, total, err := tr.Page(traffic.PageQuery{IDPrefix: prefix, RespMin: -1, RespMax: -1}, page, size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read task Cowork traffic")
		return
	}
	for i := range exchanges {
		exchanges[i].URL = redactCoworkTrafficURL(exchanges[i].URL)
		exchanges[i].URLTemplate = redactCoworkTrafficURL(exchanges[i].URLTemplate)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "task_id": t.ID, "total": total, "page": page, "size": size, "exchanges": exchanges,
	})
}

func redactCoworkTrafficURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable captured URL]"
	}
	secretNames := map[string]struct{}{
		"password": {}, "passwd": {}, "token": {}, "accesstoken": {}, "refreshtoken": {},
		"apikey": {}, "key": {}, "secret": {}, "code": {}, "auth": {}, "authorization": {},
		"session": {}, "sessionid": {}, "csrf": {}, "csrftoken": {}, "jwt": {}, "nonce": {},
		"credential": {}, "clientsecret": {}, "samlresponse": {}, "assertion": {}, "state": {}, "ticket": {},
		"email": {}, "user": {}, "username": {}, "userid": {},
		"account": {}, "accountid": {}, "accountname": {}, "login": {}, "member": {}, "memberid": {},
		"phone": {}, "telephone": {}, "tel": {}, "mobile": {}, "address": {},
		"fullname": {}, "firstname": {}, "lastname": {}, "dateofbirth": {}, "birthdate": {}, "dob": {},
	}
	query := u.Query()
	for key, values := range query {
		normalized := strings.ToLower(regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(key, ""))
		if _, sensitive := secretNames[normalized]; sensitive {
			for i := range values {
				values[i] = "[REDACTED]"
			}
			query[key] = values
		}
	}
	u.RawQuery = query.Encode()
	u.Fragment = ""
	segments := strings.Split(u.Path, "/")
	for i := 0; i+1 < len(segments); i++ {
		if strings.EqualFold(segments[i], "reset") || strings.EqualFold(segments[i], "verify") || strings.EqualFold(segments[i], "token") || strings.EqualFold(segments[i], "invite") {
			if len(segments[i+1]) >= 8 {
				segments[i+1] = "[REDACTED]"
			}
		}
	}
	u.Path = strings.Join(segments, "/")
	return u.String()
}

// GET /api/tasks/{id}/cowork/traffic/{captureID} reads one task-owned capture.
// Request and response bodies may contain sensitive data and are returned only
// after the capture ID is proven to belong to this task.
func (s *Server) coworkGetTraffic(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	captureID := r.PathValue("captureID")
	if !regexp.MustCompile(`^cowork-t` + regexp.QuoteMeta(t.ID) + `-[a-f0-9]{32}-[1-9][0-9]*$`).MatchString(captureID) {
		writeErr(w, http.StatusNotFound, "Cowork capture does not belong to this task")
		return
	}
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, http.StatusServiceUnavailable, "ARTEx traffic recorder is unavailable")
		return
	}
	req, resp, err := tr.Get(captureID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Cowork traffic capture not found")
		return
	}
	result := map[string]any{"task_id": t.ID, "capture_id": captureID, "req": req, "resp": resp}
	if r.URL.Query().Get("preview") == "1" {
		result["req"], result["request_truncated"] = coworkTrafficPreview(req)
		result["resp"], result["response_truncated"] = coworkTrafficPreview(resp)
	}
	writeJSON(w, http.StatusOK, result)
}

func coworkTrafficPreview(raw string) (string, bool) {
	const previewBytes = 8 << 10
	content := []byte(raw)
	if len(content) <= previewBytes && utf8.Valid(content) {
		return raw, false
	}
	truncated := len(content) > previewBytes
	var preview strings.Builder
	preview.Grow(previewBytes)
	for len(content) > 0 {
		r, size := utf8.DecodeRune(content)
		if size == 0 {
			break
		}
		if r == utf8.RuneError && size == 1 {
			const replacement = "�"
			if preview.Len()+len(replacement) > previewBytes {
				break
			}
			preview.WriteString(replacement)
			content = content[1:]
			continue
		}
		if preview.Len()+size > previewBytes {
			break
		}
		preview.Write(content[:size])
		content = content[size:]
	}
	return preview.String(), truncated || len(content) > 0
}

// GET /api/tasks/{id}/cowork/traffic/{captureID}/blob reads one bounded chunk
// only when the hash is referenced by that task-owned capture.
func (s *Server) coworkGetTrafficBlob(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	captureID := r.PathValue("captureID")
	if !regexp.MustCompile(`^cowork-t` + regexp.QuoteMeta(t.ID) + `-[a-f0-9]{32}-[1-9][0-9]*$`).MatchString(captureID) {
		writeErr(w, http.StatusNotFound, "Cowork capture does not belong to this task")
		return
	}
	hash := r.URL.Query().Get("hash")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hash) {
		writeErr(w, http.StatusBadRequest, "hash must be a SHA-256 hex value")
		return
	}
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		writeErr(w, http.StatusBadRequest, "offset must be a non-negative integer")
		return
	}
	length, err := parseCoworkTrafficInt(r.URL.Query().Get("length"), 8192)
	if err != nil || length < 1 || length > 8192 {
		writeErr(w, http.StatusBadRequest, "length must be between 1 and 8192")
		return
	}
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, http.StatusServiceUnavailable, "ARTEx traffic recorder is unavailable")
		return
	}
	referenced, err := tr.ExchangeReferencesBlob(captureID, hash)
	if err != nil || !referenced {
		writeErr(w, http.StatusNotFound, "blob is not referenced by this task capture")
		return
	}
	data, total, err := tr.BlobRange(hash, offset, int64(length))
	if err != nil {
		writeErr(w, http.StatusNotFound, "captured traffic blob is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id": t.ID, "capture_id": captureID, "hash": hash, "offset": offset,
		"length": len(data), "total": total, "data_b64": base64.StdEncoding.EncodeToString(data),
	})
}

func parseCoworkTrafficInt(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}

// POST /api/tasks/{id}/cowork/traffic imports one completed exchange from the
// Cowork target connector into the same native Traffic store used by ARTEx's
// recording proxy. The authenticated caller must present the exact task target
// and operator confirmation; this endpoint never contacts the target itself.
func (s *Server) coworkRecordTraffic(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	tr := s.m.Traffic()
	if tr == nil {
		writeErr(w, http.StatusServiceUnavailable, "ARTEx traffic recorder is unavailable")
		return
	}
	var req struct {
		Confirmation    string            `json:"confirmation"`
		Target          string            `json:"target"`
		CaptureID       string            `json:"capture_id"`
		URL             string            `json:"url"`
		Method          string            `json:"method"`
		Status          int               `json:"status"`
		RequestHeaders  map[string]string `json:"request_headers"`
		ResponseHeaders map[string]string `json:"response_headers"`
		RequestBodyB64  string            `json:"request_body_b64"`
		ResponseBodyB64 string            `json:"response_body_b64"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM record_cowork_traffic task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific traffic-recording confirmation required")
		return
	}
	if !regexp.MustCompile(`^cowork-t` + regexp.QuoteMeta(t.ID) + `-[a-f0-9]{32}-[1-9][0-9]*$`).MatchString(req.CaptureID) {
		writeErr(w, http.StatusBadRequest, "capture_id must be bound to this task and Cowork run")
		return
	}
	authorizedOrigin, status, message := s.validateCoworkTarget(t, req.Target)
	if status != 0 {
		writeErr(w, status, message)
		return
	}
	parsed, err := url.ParseRequestURI(req.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		writeErr(w, http.StatusBadRequest, "captured URL must be an absolute HTTP(S) URL without user info or fragment")
		return
	}
	requestOrigin := parsed.Scheme + "://" + parsed.Host
	if !strings.EqualFold(requestOrigin, authorizedOrigin) {
		writeErr(w, http.StatusForbidden, "captured URL origin does not match the authorized task target")
		return
	}
	requestBody, err := base64.StdEncoding.DecodeString(req.RequestBodyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "request_body_b64 is invalid")
		return
	}
	responseBody, err := base64.StdEncoding.DecodeString(req.ResponseBodyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "response_body_b64 is invalid")
		return
	}
	if len(requestBody) > maxCoworkTrafficBody || len(responseBody) > maxCoworkTrafficBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "captured request or response body exceeds 2 MB")
		return
	}
	id, reused, err := tr.RecordCoworkExchange(req.CaptureID, req.URL, req.Method, req.Status, req.RequestHeaders, req.ResponseHeaders, requestBody, responseBody)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	activityID, activityCreated, activityErr := t.Store.AppendCoworkTrafficActivity(db.Activity{
		Worker: "cowork", Kind: "tool_result", Tool: "record_target_traffic",
		ToolUseID: "cowork-traffic-" + req.CaptureID,
		Summary:   "Cowork가 승인된 HTTP 요청/응답을 ARTEx Traffic에 기록했습니다",
		Detail:    fmt.Sprintf("traffic_id=%s method=%s status=%d", id, strings.ToUpper(req.Method), req.Status),
	})
	if activityErr == nil && activityCreated {
		s.publishCoworkActivity(t, db.Activity{
			ID: activityID, Worker: "cowork", Kind: "tool_result", Tool: "record_target_traffic",
			ToolUseID: "cowork-traffic-" + req.CaptureID,
			Summary:   "Cowork가 승인된 HTTP 요청/응답을 ARTEx Traffic에 기록했습니다",
			Detail:    fmt.Sprintf("traffic_id=%s method=%s status=%d", id, strings.ToUpper(req.Method), req.Status),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "task_id": t.ID, "traffic_id": id, "capture_id": req.CaptureID,
		"idempotent_reuse": reused, "source": "cowork", "target_origin": authorizedOrigin,
		"activity_id": strconv.FormatInt(activityID, 10), "activity_updated": activityErr == nil,
		"activity_created": activityCreated, "activity_error": errorString(activityErr),
		"note": "Completed exchange recorded in native ARTEx Traffic; request and response bodies are retained there.",
	})
}
