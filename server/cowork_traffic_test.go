package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCoworkTrafficURLRedactsAuthenticationQueryVariants(t *testing.T) {
	got := redactCoworkTrafficURL("http://127.0.0.1:18081/callback?auth=secret&session_id=abc123&jwt=header.payload.sig&state=opaque&next=%2Fhome")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for _, key := range []string{"auth", "session_id", "jwt", "state"} {
		if value := query.Get(key); value != "[REDACTED]" {
			t.Errorf("%s query value = %q, want redacted", key, value)
		}
	}
	if value := query.Get("next"); value != "/home" {
		t.Errorf("non-sensitive query value = %q, want preserved value", value)
	}
}

func TestCoworkTrafficURLRedactsPersonalIdentifierQueryVariants(t *testing.T) {
	got := redactCoworkTrafficURL("http://127.0.0.1:18081/search?user=alice&account_id=42&phone=01012345678&dob=2000-01-02&mode=check")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for _, key := range []string{"user", "account_id", "phone", "dob"} {
		if value := query.Get(key); value != "[REDACTED]" {
			t.Errorf("%s query value = %q, want redacted", key, value)
		}
	}
	if value := query.Get("mode"); value != "check" {
		t.Errorf("non-sensitive query value = %q, want preserved value", value)
	}
}

func TestCoworkTrafficPreviewIsBoundedAndValidUTF8(t *testing.T) {
	input := strings.Repeat("a", (8<<10)-1) + "한글"
	preview, truncated := coworkTrafficPreview(input)
	if !truncated {
		t.Fatal("expected oversized preview to be truncated")
	}
	if len([]byte(preview)) > 8<<10 {
		t.Fatalf("preview exceeds 8 KB: %d bytes", len([]byte(preview)))
	}
	if !utf8.ValidString(preview) {
		t.Fatal("preview is not valid UTF-8")
	}
	binaryInput := strings.Repeat("x", 4000) + string([]byte{0xff}) + strings.Repeat("y", 5000)
	binaryPreview, binaryTruncated := coworkTrafficPreview(binaryInput)
	if !binaryTruncated || !utf8.ValidString(binaryPreview) || !strings.Contains(binaryPreview, "�") || len([]byte(binaryPreview)) > 8<<10 {
		t.Fatalf("binary preview should preserve a bounded replacement view: truncated=%t bytes=%d", binaryTruncated, len([]byte(binaryPreview)))
	}
	shortInvalid, invalidTruncated := coworkTrafficPreview(string([]byte{0xff}))
	if !utf8.ValidString(shortInvalid) || !strings.Contains(shortInvalid, "�") || invalidTruncated {
		t.Fatalf("short malformed input should be safely replaced without claiming truncation: %q truncated=%t", shortInvalid, invalidTruncated)
	}
	whole, truncated := coworkTrafficPreview("small")
	if truncated || whole != "small" {
		t.Fatalf("small preview changed: %q truncated=%t", whole, truncated)
	}
}

func TestCoworkTrafficCaptureEnforcesTaskAuthorizationAndDeduplicates(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	taskID := tasks[0].ID
	task, ok := s.m.Task(taskID)
	if !ok || task.Store == nil {
		t.Fatal("task store unavailable")
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.assetStore().AddAgentScope(id, "ip", "127.0.0.1/32", "isolated fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddConstraint("allow", "http://127.0.0.1:18081 only", "human"); err != nil {
		t.Fatal(err)
	}
	path := "/api/tasks/" + taskID + "/cowork/traffic"
	payload := map[string]any{
		"confirmation": "CONFIRM record_cowork_traffic task=" + taskID,
		"target":       "http://127.0.0.1:18081",
		"capture_id":   "cowork-t" + taskID + "-0123456789abcdef0123456789abcdef-1",
		"url":          "http://127.0.0.1:18081/api/check?q=test&token=secret-value",
		"method":       "GET",
		"status":       200,
		"request_headers": map[string]string{
			"Accept": "application/json",
		},
		"response_headers": map[string]string{
			"Content-Type": "application/json",
		},
		"request_body_b64":  base64.StdEncoding.EncodeToString([]byte(`{"query":"test"}`)),
		"response_body_b64": base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
	}
	call := func(body map[string]any) *httptest.ResponseRecorder {
		raw, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return request(http.MethodPost, path, string(raw))
	}
	missingConfirmation := map[string]any{}
	for key, value := range payload {
		missingConfirmation[key] = value
	}
	missingConfirmation["confirmation"] = ""
	if got := call(missingConfirmation); got.Code != http.StatusBadRequest {
		t.Fatalf("missing operation confirmation should reject: %d %s", got.Code, got.Body)
	}
	wrongOrigin := map[string]any{}
	for key, value := range payload {
		wrongOrigin[key] = value
	}
	wrongOrigin["target"] = "http://127.0.0.1:18082"
	if got := call(wrongOrigin); got.Code != http.StatusForbidden {
		t.Fatalf("wrong authorized origin should reject: %d %s", got.Code, got.Body)
	}
	wrongURL := map[string]any{}
	for key, value := range payload {
		wrongURL[key] = value
	}
	wrongURL["url"] = "http://127.0.0.1:18082/api/check?q=test"
	if got := call(wrongURL); got.Code != http.StatusForbidden {
		t.Fatalf("captured URL outside exact authorized origin should reject: %d %s", got.Code, got.Body)
	}
	first := call(payload)
	if first.Code != http.StatusOK {
		t.Fatalf("authorized Cowork traffic capture: %d %s", first.Code, first.Body)
	}
	var result struct {
		TrafficID       string `json:"traffic_id"`
		ActivityUpdated bool   `json:"activity_updated"`
		IdempotentReuse bool   `json:"idempotent_reuse"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil || result.TrafficID == "" || !result.ActivityUpdated || result.IdempotentReuse {
		t.Fatalf("invalid first capture result: %+v err=%v body=%s", result, err, first.Body)
	}
	req, resp, err := s.m.Traffic().Get(result.TrafficID)
	if err != nil || !strings.Contains(req, `{"query":"test"}`) || !strings.Contains(resp, `{"ok":true}`) {
		t.Fatalf("native Traffic bodies unavailable: request=%q response=%q err=%v", req, resp, err)
	}
	list := request(http.MethodGet, path+"?page=0&size=10", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), result.TrafficID) || strings.Contains(list.Body.String(), `{"query":"test"}`) || strings.Contains(list.Body.String(), "token=secret-value") || !strings.Contains(list.Body.String(), "token=%5BREDACTED%5D") {
		t.Fatalf("task-scoped Cowork traffic list should return metadata only: %d %s", list.Code, list.Body)
	}
	detail := request(http.MethodGet, path+"/"+result.TrafficID, "")
	var detailPayload struct {
		Request  string `json:"req"`
		Response string `json:"resp"`
	}
	if detail.Code != http.StatusOK || json.Unmarshal(detail.Body.Bytes(), &detailPayload) != nil || !strings.Contains(detailPayload.Request, `{"query":"test"}`) || !strings.Contains(detailPayload.Response, `{"ok":true}`) {
		t.Fatalf("task-scoped Cowork traffic detail should return saved exchange: %d %s", detail.Code, detail.Body)
	}
	foreign := request(http.MethodGet, path+"/cowork-t999-0123456789abcdef0123456789abcdef-1", "")
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("cross-task capture ID should not be readable: %d %s", foreign.Code, foreign.Body)
	}
	largePayload := map[string]any{}
	for key, value := range payload {
		largePayload[key] = value
	}
	largeCaptureID := "cowork-t" + taskID + "-0123456789abcdef0123456789abcdef-2"
	largePayload["capture_id"] = largeCaptureID
	largeBody := strings.Repeat("x", 300*1024)
	largePayload["response_body_b64"] = base64.StdEncoding.EncodeToString([]byte(largeBody))
	largeCreated := call(largePayload)
	if largeCreated.Code != http.StatusOK {
		t.Fatalf("large Cowork capture: %d %s", largeCreated.Code, largeCreated.Body)
	}
	_, largeResponse, err := s.m.Traffic().Get(largeCaptureID)
	if err != nil {
		t.Fatal(err)
	}
	blobMatch := regexp.MustCompile(`@blob sha256:([a-f0-9]{64})`).FindStringSubmatch(largeResponse)
	if len(blobMatch) != 2 {
		tail := largeResponse
		if len(tail) > 120 {
			tail = tail[len(tail)-120:]
		}
		t.Fatalf("large response should use a native blob pointer: %s", tail)
	}
	preview := request(http.MethodGet, path+"/"+largeCaptureID+"?preview=1", "")
	var previewResult struct {
		Resp              string `json:"resp"`
		ResponseTruncated bool   `json:"response_truncated"`
	}
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &previewResult) != nil || !previewResult.ResponseTruncated || len([]byte(previewResult.Resp)) > 8<<10 {
		t.Fatalf("large task capture preview must be explicitly bounded: %d %s", preview.Code, preview.Body)
	}
	blobURL := path + "/" + largeCaptureID + "/blob?hash=" + blobMatch[1] + "&offset=0&length=8192"
	blobChunk := request(http.MethodGet, blobURL, "")
	var chunkResult struct {
		Total   int64  `json:"total"`
		DataB64 string `json:"data_b64"`
	}
	chunkErr := json.Unmarshal(blobChunk.Body.Bytes(), &chunkResult)
	chunkData, decodeErr := base64.StdEncoding.DecodeString(chunkResult.DataB64)
	if blobChunk.Code != http.StatusOK || chunkErr != nil || decodeErr != nil || chunkResult.Total != 307200 || len(chunkData) != 8192 {
		t.Fatalf("task-owned blob chunk: %d %s", blobChunk.Code, blobChunk.Body)
	}
	wrongBlob := request(http.MethodGet, path+"/"+largeCaptureID+"/blob?hash="+strings.Repeat("0", 64)+"&offset=0&length=8192", "")
	if wrongBlob.Code != http.StatusNotFound {
		t.Fatalf("unreferenced blob hash should be rejected: %d %s", wrongBlob.Code, wrongBlob.Body)
	}
	findingPath := "/api/tasks/" + taskID + "/cowork/findings"
	findingBody := fmt.Sprintf(`{"target":"http://127.0.0.1:18081","vulnclass":"TEST","name":"Traffic binding fixture","severity":"low","summary":"Fixture finding for same-task traffic binding","evidence":"A captured response supports the finding","confirmation":"CONFIRM report_finding task=%s"}`, taskID)
	findingResponse := request(http.MethodPost, findingPath, findingBody)
	var findingResult struct {
		FindingID string `json:"finding_id"`
	}
	if findingResponse.Code != http.StatusCreated || json.Unmarshal(findingResponse.Body.Bytes(), &findingResult) != nil || findingResult.FindingID == "" {
		t.Fatalf("create fixture finding: %d %s", findingResponse.Code, findingResponse.Body)
	}
	bindPath := "/api/tasks/" + taskID + "/cowork/findings/" + findingResult.FindingID + "/traffic"
	bindPayload := map[string]any{
		"confirmation": "CONFIRM bind_cowork_traffic task=" + taskID + " finding=" + findingResult.FindingID,
		"target":       "http://127.0.0.1:18081",
		"traffic_refs": []map[string]string{{"traffic_id": result.TrafficID, "role": "proof", "note": "captured fixture exchange"}},
	}
	bindRaw, err := json.Marshal(bindPayload)
	if err != nil {
		t.Fatal(err)
	}
	wrongBindTarget := strings.Replace(string(bindRaw), "127.0.0.1:18081", "127.0.0.1:18082", 1)
	if got := request(http.MethodPost, bindPath, wrongBindTarget); got.Code != http.StatusForbidden {
		t.Fatalf("traffic binding must revalidate exact task origin: %d %s", got.Code, got.Body)
	}
	missingBindConfirmation := strings.Replace(string(bindRaw), "CONFIRM bind_cowork_traffic task="+taskID+" finding="+findingResult.FindingID, "", 1)
	if got := request(http.MethodPost, bindPath, missingBindConfirmation); got.Code != http.StatusBadRequest {
		t.Fatalf("traffic binding must require its operation confirmation: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, bindPath, string(bindRaw)); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"verified":true`) {
		t.Fatalf("same-task traffic binding: %d %s", got.Code, got.Body)
	}
	changedBinding := strings.Replace(string(bindRaw), "captured fixture exchange", "different note", 1)
	if got := request(http.MethodPost, bindPath, changedBinding); got.Code != http.StatusConflict {
		t.Fatalf("retry with changed binding metadata must not claim success: %d %s", got.Code, got.Body)
	}
	foreignRef := strings.Replace(string(bindRaw), result.TrafficID, "cowork-t999-0123456789abcdef0123456789abcdef-1", 1)
	if got := request(http.MethodPost, bindPath, foreignRef); got.Code != http.StatusForbidden {
		t.Fatalf("cross-task traffic reference should reject: %d %s", got.Code, got.Body)
	}
	boundTraffic := request(http.MethodGet, "/api/exploration/findings/"+findingResult.FindingID+"/traffic?context_task="+taskID, "")
	if boundTraffic.Code != http.StatusOK || !strings.Contains(boundTraffic.Body.String(), result.TrafficID) {
		t.Fatalf("native Finding traffic surface should show bound capture: %d %s", boundTraffic.Code, boundTraffic.Body)
	}
	activity := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", taskID), "")
	if activity.Code != http.StatusOK || !strings.Contains(activity.Body.String(), "record_target_traffic") || !strings.Contains(activity.Body.String(), result.TrafficID) || !strings.Contains(activity.Body.String(), "bind_cowork_traffic") {
		t.Fatalf("Cowork traffic activity or finding binding activity missing: %d %s", activity.Code, activity.Body)
	}
	second := call(payload)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"idempotent_reuse":true`) {
		t.Fatalf("exact retry should reuse the same exchange: %d %s", second.Code, second.Body)
	}
	count, err := s.m.Traffic().Count()
	if err != nil || count != 2 {
		t.Fatalf("exact retry created a duplicate traffic row: count=%d err=%v", count, err)
	}
	changed := map[string]any{}
	for key, value := range payload {
		changed[key] = value
	}
	changed["response_body_b64"] = base64.StdEncoding.EncodeToString([]byte(`{"ok":false}`))
	if got := call(changed); got.Code != http.StatusBadRequest {
		t.Fatalf("changed content under same capture ID must reject: %d %s", got.Code, got.Body)
	}
}
