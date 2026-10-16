package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

func trafficEvidenceServer(t *testing.T) (*Server, *db.RecordedFinding, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	m.traffic, err = traffic.Open(filepath.Join(m.dir, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("traffic evidence API", "local evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() {
		if _, err := m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, tid); err != nil {
			t.Errorf("clean test task archives: %v", err)
		}
		if _, err := m.pg.DeleteTaskCascade(tid, true, true); err != nil {
			t.Errorf("clean test task and findings: %v", err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()
	// The archive test below replaces the cancelled service context. Wait for
	// the side-question snapshot writer too before reusing this fixture.
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	input := db.RecordFindingInput{TaskID: tid, ExplorationID: task.ExpID, Worker: "test", VulnClass: "TEST", Summary: "bound evidence", Name: "Evidence API", Severity: "low"}
	f, err := s.evidenceStore().Record(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, request
}

func seedServerEvidenceFlow(t *testing.T, s *Server, id string, body []byte) {
	t.Helper()
	_, err := s.m.traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'evidence.local','POST','/','http://evidence.local/',200,'application/octet-stream',0,?,'')`, id, len(body))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.m.traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body) VALUES(?,'POST / HTTP/1.1','HTTP/1.1 200 OK',?,?)`, id, []byte{}, body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetTaskCountersMatchTaskListMetrics(t *testing.T) {
	s, finding, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatal("fixture finding has no task ID")
	}
	taskID := *stored.TaskID
	var single TaskDTO
	response := req("GET", fmt.Sprintf("/api/tasks/%d", taskID), "")
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &single) != nil {
		t.Fatalf("get task: %d %s", response.Code, response.Body)
	}
	var list struct {
		Tasks []TaskDTO `json:"tasks"`
	}
	response = req("GET", "/api/tasks", "")
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &list) != nil || len(list.Tasks) != 1 {
		t.Fatalf("list tasks: %d %s", response.Code, response.Body)
	}
	listed := list.Tasks[0]
	if single.GoalsTotal != listed.GoalsTotal || single.GoalsMet != listed.GoalsMet || single.FactsCount != listed.FactsCount ||
		single.LastActivity != listed.LastActivity || single.Findings != listed.Findings || single.Tokens != listed.Tokens {
		t.Fatalf("single-task counters differ from list: single=%+v list=%+v", single, listed)
	}
	if single.Findings.Low != 1 {
		t.Fatalf("expected fixture finding in Task counters, got %+v", single.Findings)
	}
}

func TestGetReportCountsOnlyAssetsLinkedToSelectedTask(t *testing.T) {
	s, finding, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatal("fixture finding has no task ID")
	}
	other, err := s.m.CreateTask("unrelated asset fixture", "synthetic", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherTaskID, err := strconv.ParseInt(other.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	assetID, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL: fmt.Sprintf("https://cowork-report-%d.example.test", time.Now().UnixNano()), TaskID: otherTaskID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.Assets().DeleteByIDs([]int64{assetID})
		_, _ = s.m.DeleteTask(other.ID, DeleteTaskOptions{DeleteAssets: true})
	})

	selectedReport := req("GET", fmt.Sprintf("/api/report?task=%d", *stored.TaskID), "")
	if selectedReport.Code != 200 || strings.Contains(selectedReport.Body.String(), "service 1") {
		t.Fatalf("report included an unrelated task asset: %d %s", selectedReport.Code, selectedReport.Body)
	}
	otherReport := req("GET", fmt.Sprintf("/api/report?task=%d", other.ID), "")
	if otherReport.Code != 200 || !strings.Contains(otherReport.Body.String(), "service 1") {
		t.Fatalf("report omitted the selected task's asset: %d %s", otherReport.Code, otherReport.Body)
	}
}

func TestFindingTrafficToolUpgradePreservesCustomization(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal("missing worker", err)
	}
	oldPrompt, _ := pg.CurrentPrompt(worker.ID)
	t.Cleanup(func() { pg.SavePrompt(worker.ID, oldPrompt, "restore test fixture", "test") })
	if _, err := pg.SavePrompt(worker.ID, "USER CUSTOM PROMPT", "test", "test"); err != nil {
		t.Fatal(err)
	}
	custom := json.RawMessage(`{"type":"object","properties":{"evidence":{"type":"string","description":"user evidence instructions"}},"required":["evidence"]}`)
	for _, key := range []string{"report_finding", "update_finding_report", "get_finding_traffic"} {
		old, err := pg.GetTool(key)
		if err != nil || old == nil {
			t.Fatal("missing tool", key, err)
		}
		t.Cleanup(func() {
			bindings, _ := json.Marshal(old.Agents)
			pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		})
		if err := pg.UpdateTool(key, "user description", custom, json.RawMessage(`["worker"]`), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.SetSetting("finding_traffic_tools_v1", "false"); err != nil {
		t.Fatal(err)
	}
	s.seedFindingTrafficTools()
	for key, property := range map[string]string{"report_finding": "traffic_refs", "update_finding_report": "evidence_version"} {
		tool, err := pg.GetTool(key)
		if err != nil || tool == nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		}
		if err := json.Unmarshal(tool.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if tool.Enabled || tool.Description != "user description" || len(tool.Agents) != 1 || tool.Agents[0] != "worker" || len(schema.Required) != 1 || schema.Required[0] != "evidence" || len(schema.Properties[property]) == 0 || !strings.Contains(string(schema.Properties["evidence"]), "user evidence instructions") {
			t.Fatalf("custom configuration overwritten: %+v", tool)
		}
	}
	reader, _ := pg.GetTool("get_finding_traffic")
	if reader.Enabled || !contains(reader.Agents, "reporter") {
		t.Fatal("reader should be bound without enabling it")
	}
	if err := pg.RemoveAgentFromTool("reporter", "get_finding_traffic"); err != nil {
		t.Fatal(err)
	}
	s.seedFindingTrafficTools()
	reader, _ = pg.GetTool("get_finding_traffic")
	if contains(reader.Agents, "reporter") {
		t.Fatal("restart overwrote user's unbinding")
	}
	if got, _ := pg.CurrentPrompt(worker.ID); got != "USER CUSTOM PROMPT" {
		t.Fatal("custom prompt replaced")
	}
}

func TestFindingTrafficAPIAndExport(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	body := bytes.Repeat([]byte{0, 255, 65, 66}, 5000)
	for _, id := range []string{"a", "b", "c"} {
		seedServerEvidenceFlow(t, s, id, body)
	}
	base := fmt.Sprintf("/api/exploration/findings/%d/traffic", f.FindingID)
	w := req("POST", base, `{"traffic_refs":[{"traffic_id":"a","role":"baseline"},{"traffic_id":"b","role":"proof","note":"proof note"},{"traffic_id":"c"}]}`)
	if w.Code != 200 {
		t.Fatalf("bind: %d %s", w.Code, w.Body)
	}
	var list db.FindingTraffic
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Bindings) != 3 || list.Bindings[0].Snapshot.ReqHead != "" {
		t.Fatal("not a bounded summary")
	}
	first, second, third := list.Bindings[0].ID, list.Bindings[1].ID, list.Bindings[2].ID
	if w = req("PATCH", fmt.Sprintf("%s/%d", base, first), `{"version":0,"note":"stale"}`); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("PUT", base+"/order", fmt.Sprintf(`{"version":1,"binding_ids":["%d","%d","%d"]}`, third, first, second)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("PUT", base+"/order", fmt.Sprintf(`{"version":2,"binding_ids":["%d"]}`, first)); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("GET", fmt.Sprintf("%s/%d", base, first), ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"binary":true`) {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("GET", fmt.Sprintf("%s/%d/body?side=response&offset=20001", base, first), ""); w.Code != 422 {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	if w = req("GET", fmt.Sprintf("%s/%d/body?side=response&download=1", base, first), ""); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatal("download after original removal failed")
	}
	// IDs belong to the requested finding; cross-finding detail cannot be read.
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.GetTask(*finding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.evidenceStore().Record(t.Context(), db.RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "other", Severity: "low"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/traffic/%d", other.FindingID, first), ""); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	exportURL := fmt.Sprintf("/api/exploration/findings/export?format=md-zip&scope=selected&ids=%d", f.FindingID)
	w = req("GET", exportURL, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	archive, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	binaries := 0
	linked := false
	for _, entry := range archive.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(entry.Name, "/response.bin") {
			binaries++
			if !bytes.Equal(raw, body) {
				t.Fatal("export changed binary")
			}
		}
		if strings.HasSuffix(entry.Name, ".md") && bytes.Contains(raw, []byte(fmt.Sprintf("evidence/%d/%d/", f.FindingID, third))) {
			linked = true
		}
	}
	if binaries != 3 || !linked {
		t.Fatalf("missing attachments/links: %d %v", binaries, linked)
	}
	// Reports can use snapshots with capture stopped and original rows gone.
	result, err := s.toolGetFindingTraffic().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"finding_id":"%d"}`, f.FindingID)), nil)
	if err != nil || !strings.Contains(result.Flatten(), "proof note") {
		t.Fatal(result, err)
	}
	// Corrupt body must fail before an attachment response is sent.
	snap := list.Bindings[0].Snapshot
	path := filepath.Join(s.m.dir, "evidence", "blobs", snap.RespHash[:2], snap.RespHash+".bin")
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if w = req("GET", exportURL, ""); w.Code < 400 || strings.Contains(w.Header().Get("Content-Type"), "zip") {
		t.Fatal("corrupt export returned an attachment", w.Code)
	}
}

func TestCoworkRetestUsesNativeRetestSurfaceAndChecksAuthorization(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load test finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	base := fmt.Sprintf("/api/tasks/%d/cowork/retests", taskID)
	body := fmt.Sprintf(`{"finding_id":%d,"target":"http://127.0.0.1:18081","verdict":"reproduced","summary":"Still reproducible","evidence":"GET / still returns the observed proof","confirmation":"CONFIRM record_cowork_retest task=%d finding=%d"}`, f.FindingID, taskID, f.FindingID)
	if w := req("POST", base, body); w.Code != 403 {
		t.Fatalf("missing scope/allow should reject: %d %s", w.Code, w.Body)
	}
	if _, err := s.assetStore().AddAgentScope(taskID, "ip", "127.0.0.1/32", "authorized test", "manual"); err != nil {
		t.Fatal(err)
	}
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		t.Fatal("task missing")
	}
	if _, err := task.Store.AddConstraint("allow", "http://127.0.0.1:18081 only", "human"); err != nil {
		t.Fatal(err)
	}
	w := req("POST", base, body)
	if w.Code != 201 {
		t.Fatalf("record cowork retest: %d %s", w.Code, w.Body)
	}
	var result struct {
		Retest db.FindingRetest `json:"retest"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Retest.Status != "completed" || result.Retest.Verdict != "reproduced" || result.Retest.ConversationID != nil {
		t.Fatalf("unexpected result: %+v", result.Retest)
	}
	history, err := s.m.pg.ListFindingRetests(f.FindingID)
	if err != nil || len(history) != 1 || history[0].ID != result.Retest.ID {
		t.Fatalf("native history=%+v err=%v", history, err)
	}
}

func TestCoworkInterceptDecisionIsTaskScopedAndConfirmed(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load test finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	pendingID, err := s.m.pg.CreateInterceptPending(0, 0, strconv.FormatInt(taskID, 10), "test-agent", "test_tool", []byte(`{"x":1}`), "operator review")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/tasks/%d/cowork/intercepts/%d/decide", taskID, pendingID)
	if w := req("POST", path, `{"decision":"denied"}`); w.Code != 400 {
		t.Fatalf("missing confirmation should reject: %d %s", w.Code, w.Body)
	}
	wrongTaskPath := fmt.Sprintf("/api/tasks/%d/cowork/intercepts/%d/decide", taskID+1, pendingID)
	if w := req("POST", wrongTaskPath, fmt.Sprintf(`{"decision":"denied","confirmation":"CONFIRM decide_intercept task=%d pending=%d decision=denied"}`, taskID+1, pendingID)); w.Code != 404 {
		t.Fatalf("cross-task decision should reject: %d %s", w.Code, w.Body)
	}
	body := fmt.Sprintf(`{"decision":"denied","confirmation":"CONFIRM decide_intercept task=%d pending=%d decision=denied"}`, taskID, pendingID)
	decision := req("POST", path, body)
	if decision.Code != 200 {
		t.Fatalf("confirmed decision: %d %s", decision.Code, decision.Body)
	}
	var decisionResult struct {
		ActivityUpdated bool `json:"activity_updated"`
	}
	if err := json.Unmarshal(decision.Body.Bytes(), &decisionResult); err != nil || !decisionResult.ActivityUpdated {
		t.Fatalf("intercept decision activity was not recorded: %s err=%v", decision.Body, err)
	}
	got, err := s.m.pg.GetInterceptPending(pendingID)
	if err != nil || got == nil || got.Status != "denied" {
		t.Fatalf("decision not stored: pending=%+v err=%v", got, err)
	}
	history := req("GET", fmt.Sprintf("/api/exploration/activity/history?task=%d&session=cowork", taskID), "")
	if history.Code != 200 || !bytes.Contains(history.Body.Bytes(), []byte("decide_intercept")) {
		t.Fatalf("intercept decision missing from Cowork activity history: %d %s", history.Code, history.Body)
	}
}

func TestCoworkAddIntentsWritesAndDeduplicatesTaskGraph(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load test finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	path := fmt.Sprintf("/api/tasks/%d/cowork/intents", taskID)
	invalidBatch := fmt.Sprintf(`{"confirmation":"CONFIRM add_cowork_intents task=%d","intents":[{"summary":"Must not partially persist","priority":5},{"summary":"Invalid priority","priority":11}]}`, taskID)
	if rejected := req("POST", path, invalidBatch); rejected.Code != 400 {
		t.Fatalf("invalid batch should reject before any write: %d %s", rejected.Code, rejected.Body)
	}
	before := req("GET", fmt.Sprintf("/api/exploration/graph?task=%d", taskID), "")
	if bytes.Contains(before.Body.Bytes(), []byte("Must not partially persist")) {
		t.Fatalf("invalid batch partially wrote an intent: %s", before.Body)
	}
	body := fmt.Sprintf(`{"confirmation":"CONFIRM add_cowork_intents task=%d","intents":[{"summary":"Inspect the authorized test response","priority":7}]}`, taskID)
	first := req("POST", path, body)
	if first.Code != 201 {
		t.Fatalf("add intent: %d %s", first.Code, first.Body)
	}
	var result struct {
		IDs []int64 `json:"intent_ids"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil || len(result.IDs) != 1 {
		t.Fatalf("result=%s err=%v", first.Body, err)
	}
	graph := req("GET", fmt.Sprintf("/api/exploration/graph?task=%d", taskID), "")
	var graphResult struct {
		Nodes []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"nodes"`
	}
	if graph.Code != 200 || json.Unmarshal(graph.Body.Bytes(), &graphResult) != nil {
		t.Fatalf("read graph: %d %s", graph.Code, graph.Body)
	}
	found := false
	for _, node := range graphResult.Nodes {
		if node.ID == strconv.FormatInt(result.IDs[0], 10) && node.Type == "intent" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("intent missing from graph: %d %s", graph.Code, graph.Body)
	}
	second := req("POST", path, body)
	if second.Code != 201 {
		t.Fatalf("retry add intent: %d %s", second.Code, second.Body)
	}
	var retry struct {
		IDs []int64 `json:"intent_ids"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &retry); err != nil || len(retry.IDs) != 1 || retry.IDs[0] != result.IDs[0] {
		t.Fatalf("retry was not idempotent: %s err=%v", second.Body, err)
	}
}

func TestCoworkIntentCompletionPreservesSourceAndIntentHistory(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load test finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task.Store == nil {
		t.Fatal("task store unavailable")
	}
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "Verify a bounded local behavior"}, 5, nil, "cowork")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/tasks/%d/cowork/intents/%d/complete", taskID, intentID)
	if rejected := req("POST", path, `{"state":"done","summary":"Completed"}`); rejected.Code != 400 {
		t.Fatalf("missing confirmation should reject: %d %s", rejected.Code, rejected.Body)
	}
	confirmation := fmt.Sprintf("CONFIRM complete_cowork_intent task=%d intent=%d state=done", taskID, intentID)
	missingEvidence := fmt.Sprintf(`{"confirmation":%q,"state":"done","summary":"Completed"}`, confirmation)
	if rejected := req("POST", path, missingEvidence); rejected.Code != 400 {
		t.Fatalf("done without evidence should reject: %d %s", rejected.Code, rejected.Body)
	}
	live, unsubscribe := s.engine.Broadcaster().Subscribe(strconv.FormatInt(taskID, 10))
	defer unsubscribe()
	body := fmt.Sprintf(`{"confirmation":%q,"state":"done","summary":"Completed bounded review","evidence":"Reviewed the supplied local response and source; no target request was made."}`, confirmation)
	if recorded := req("POST", path, body); recorded.Code != 200 {
		t.Fatalf("complete intent: %d %s", recorded.Code, recorded.Body)
	}
	select {
	case event := <-live:
		if event.Tool != "complete_intent" || event.Worker != "cowork" || event.NodeID == nil || *event.NodeID != intentID {
			t.Fatalf("live activity stream did not publish the persisted Cowork intent event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("Cowork intent completion was not published to the live activity stream")
	}
	completed, err := task.Store.GetNode(intentID)
	if err != nil || completed == nil || completed.State != "done" {
		t.Fatalf("intent state=%+v err=%v", completed, err)
	}
	historyPath := fmt.Sprintf("/api/exploration/activity/history?task=%d&session=intent:%d", taskID, intentID)
	history := req("GET", historyPath, "")
	if history.Code != 200 || !bytes.Contains(history.Body.Bytes(), []byte("Completed bounded review")) || !bytes.Contains(history.Body.Bytes(), []byte("Reviewed the supplied local response and source; no target request was made.")) {
		t.Fatalf("Cowork result or evidence missing from intent outcome history: %d %s", history.Code, history.Body)
	}
	coworkHistory := req("GET", fmt.Sprintf("/api/exploration/activity/history?task=%d&session=cowork", taskID), "")
	if coworkHistory.Code != 200 || !bytes.Contains(coworkHistory.Body.Bytes(), []byte("Completed bounded review")) || !bytes.Contains(coworkHistory.Body.Bytes(), []byte("Reviewed the supplied local response and source; no target request was made.")) {
		t.Fatalf("Cowork activity or evidence missing from its distinct session stream: %d %s", coworkHistory.Code, coworkHistory.Body)
	}
	intentIndex := req("GET", fmt.Sprintf("/api/exploration/intents?task=%d&limit=1&page=1&before=%d", taskID, intentID+1), "")
	var indexed struct {
		Items []TaskNodeDTO `json:"items"`
	}
	if intentIndex.Code != 200 || json.Unmarshal(intentIndex.Body.Bytes(), &indexed) != nil || len(indexed.Items) != 1 || indexed.Items[0].ID != strconv.FormatInt(intentID, 10) || !indexed.Items[0].CompletedByCowork {
		t.Fatalf("intent index did not preserve Cowork completion provenance: %d %s", intentIndex.Code, intentIndex.Body)
	}
}

func TestCoworkIntentCompletionRollsBackWhenSessionEventCannotBeWritten(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load test finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task.Store == nil {
		t.Fatal("task store unavailable")
	}
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "Atomic Cowork completion fixture"}, 5, nil, "cowork")
	if err != nil {
		t.Fatal(err)
	}
	triggerName := fmt.Sprintf("artex_test_block_cowork_activity_%d", taskID)
	functionName := fmt.Sprintf("artex_test_block_cowork_activity_fn_%d", taskID)
	if _, err := s.m.pg.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.worker='cowork' AND NEW.tool='complete_intent' THEN RAISE EXCEPTION 'forced activity failure'; END IF;
  RETURN NEW;
END $$`, functionName)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON activity FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, functionName)); err != nil {
		_, _ = s.m.pg.Exec(fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName))
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.m.pg.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON activity`, triggerName))
		_, _ = s.m.pg.Exec(fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName))
	}()

	confirmation := fmt.Sprintf("CONFIRM complete_cowork_intent task=%d intent=%d state=done", taskID, intentID)
	body := fmt.Sprintf(`{"confirmation":%q,"state":"done","summary":"Atomic completion","evidence":"Fixture evidence"}`, confirmation)
	path := fmt.Sprintf("/api/tasks/%d/cowork/intents/%d/complete", taskID, intentID)
	live, unsubscribe := s.engine.Broadcaster().Subscribe(strconv.FormatInt(taskID, 10))
	defer unsubscribe()
	if failed := req("POST", path, body); failed.Code != 500 {
		t.Fatalf("forced session event failure should fail the whole operation: %d %s", failed.Code, failed.Body)
	}
	select {
	case event := <-live:
		t.Fatalf("rolled-back Cowork completion must not publish a live activity: %+v", event)
	default:
	}
	unchanged, err := task.Store.GetNode(intentID)
	if err != nil || unchanged == nil || unchanged.State != "open" {
		t.Fatalf("intent state must roll back with the missing session event: intent=%+v err=%v", unchanged, err)
	}
	historyPath := fmt.Sprintf("/api/exploration/activity/history?task=%d&session=intent:%d", taskID, intentID)
	history := req("GET", historyPath, "")
	if history.Code != 200 || strings.Contains(history.Body.String(), "Atomic completion") {
		t.Fatalf("failed transactional completion must not leave partial session history: %d %s", history.Code, history.Body)
	}
}

func TestFindingTrafficArchiveV3RoundTripAndRetry(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	s.ctx = ctx
	body := []byte("evidence without original traffic\x00\xff")
	seedServerEvidenceFlow(t, s, "original", body)
	list, err := s.evidenceStore().Bind(ctx, f.FindingID, []db.TrafficRef{{TrafficID: "original", Role: "proof", Note: "keep note"}})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	tid := *finding.TaskID
	sharedTask, err := s.m.CreateTask("shared evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := strconv.ParseInt(sharedTask.ID, 10, 64)
	defer s.m.pg.DeleteTask(sid)
	shared, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{TaskID: sid, ExplorationID: sharedTask.ExpID, Summary: "shared", Severity: "low"}, []db.TrafficRef{{TrafficID: "original"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	if err = s.m.SetTaskPaused(strconv.FormatInt(tid, 10), true); err != nil {
		t.Fatal(err)
	}
	job, err := s.m.pg.QueueTaskArchive(tid)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.EditFindingTraffic(ctx, f.FindingID, list.Bindings[0].ID, 1, nil, nil, true, nil); err == nil {
		t.Fatal("write allowed after archive queued")
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.m.pg.GetFinding(f.FindingID); got != nil {
		t.Fatal("archive retained hot finding")
	}
	if err = s.evidenceStore().Collect(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.evidenceStore().WithBinding(ctx, shared.FindingID, shared.Traffic.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
		r, _, err := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if r != nil {
			r.Close()
		}
		return err
	}); err != nil {
		t.Fatal("shared body deleted", err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	// Force a database error after validated body installation; then retry normally.
	if _, err = s.m.pg.Exec(`CREATE FUNCTION fail_evidence_restore_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'restore fixture failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.Exec(`CREATE TRIGGER fail_evidence_restore_test BEFORE INSERT ON finding_traffic_bindings FOR EACH ROW EXECUTE FUNCTION fail_evidence_restore_test()`); err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DROP FUNCTION IF EXISTS fail_evidence_restore_test() CASCADE`)
	if err = s.runOneTaskArchiveJob(); err == nil {
		t.Fatal("expected restore failure")
	}
	if got, _ := s.m.pg.GetFinding(f.FindingID); got != nil {
		t.Fatal("partial restore")
	}
	if _, err = s.m.pg.Exec(`DROP FUNCTION fail_evidence_restore_test() CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	restored, err := s.m.pg.GetFindingTraffic(ctx, f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	b := restored.Bindings[0]
	if restored.Version != list.Version || b.ID != list.Bindings[0].ID || b.Note != "keep note" || b.Role != "proof" || b.Position != 0 {
		t.Fatalf("restored: %+v", restored)
	}
	if err = s.evidenceStore().WithBinding(ctx, f.FindingID, b.ID, func(b db.FindingTrafficBinding) error {
		r, _, err := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if err != nil {
			return err
		}
		defer r.Close()
		got, err := io.ReadAll(r)
		if !bytes.Equal(got, body) {
			t.Fatal("restore changed body")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The read tool enforces task visibility too.
	result, err := s.toolGetFindingTraffic().Call(agent.WithRunInfo(ctx, agent.RunInfo{TaskID: sid}), json.RawMessage(fmt.Sprintf(`{"finding_id":"%d"}`, f.FindingID)), nil)
	if err != nil || !strings.Contains(result.Flatten(), "不可读取") {
		t.Fatal(result, err)
	}
}

func TestFindingTrafficFailedReportDoesNotTrigger(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.GetTask(*finding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	if err = s.m.pg.QueryRow(`SELECT COALESCE(max(id),0) FROM activity`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(last, 10)); err != nil {
		t.Fatal(err)
	}
	id, err := s.m.pg.Exploration(task.ExplorationID).AppendActivity(db.Activity{Kind: "tool_result", Tool: "report_finding", ToolUseID: "failure-fixture", IsError: true, Detail: "body missing"})
	if err != nil {
		t.Fatal(err)
	}
	// A nil server makes any attempted trigger fail this test immediately.
	scheduler := &Scheduler{pg: s.m.pg}
	scheduler.fireToolCalls([]*db.AgentTrigger{{OnToolCall: true, ToolNames: []string{"report_finding"}, AgentKey: "reporter"}})
	if got := scheduler.mustState(schedKeyLastToolCall); got != strconv.FormatInt(id, 10) {
		t.Fatal("failed finding must still advance watermark", got)
	}
}

func TestFindingTrafficUTF8SegmentsAndInheritedWrites(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	ctx := context.Background()
	text := strings.Repeat("中文证据🙂", 2000)
	seedServerEvidenceFlow(t, s, "unicode", []byte(text))
	list, err := s.evidenceStore().Bind(ctx, f.FindingID, []db.TrafficRef{{TrafficID: "unicode"}})
	if err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	offset := int64(0)
	for {
		var preview evidencePreview
		err = s.evidenceStore().WithBinding(ctx, f.FindingID, list.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
			var e error
			preview, e = readEvidencePreview(s.evidenceStore(), b.Snapshot, "response", offset, 8192)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		if preview.Binary {
			t.Fatal("valid UTF-8 classified binary")
		}
		joined.WriteString(preview.Content)
		if !preview.Truncated {
			break
		}
		if preview.NextOffset <= offset {
			t.Fatal("preview made no progress")
		}
		offset = preview.NextOffset
	}
	if joined.String() != text {
		t.Fatal("UTF-8 character split damaged preview")
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.m.CreateTaskWithOptions("inherited evidence API", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{*finding.TaskID}})
	if err != nil {
		t.Fatal(err)
	}
	cid, _ := strconv.ParseInt(child.ID, 10, 64)
	defer s.m.pg.DeleteTask(cid)
	base := fmt.Sprintf("/api/exploration/findings/%d/traffic", f.FindingID)
	suffix := "?context_task=" + child.ID
	if w := req("GET", base+suffix, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, method := range []string{"POST", "PATCH", "PUT", "DELETE"} {
		path := base
		if method == "PATCH" || method == "DELETE" {
			path += fmt.Sprintf("/%d", list.Bindings[0].ID)
		}
		if method == "PUT" {
			path += "/order"
		}
		w := req(method, path+suffix, `{"version":1,"traffic_refs":[{"traffic_id":"unicode"}]}`)
		if w.Code != 403 {
			t.Fatal(method, w.Code, w.Body)
		}
	}
	if _, err = s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	result, err := s.toolUpdateFindingReport().Call(ctx, json.RawMessage(fmt.Sprintf(`{"finding_id":%d,"evidence_version":1,"report":"## 证据报告\n\n证据 #%d：已验证完整请求响应"}`, f.NodeID, list.Bindings[0].ID)), nil)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	updated, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ReportEvidenceVersion != 1 || updated.EvidenceVersion != 1 {
		t.Fatal("report did not record the read evidence version")
	}
	for _, format := range []string{"md-single", "json", "csv"} {
		w := req("GET", fmt.Sprintf("/api/exploration/findings/export?scope=selected&ids=%d&format=%s", f.FindingID, format), "")
		if w.Code != 200 {
			t.Fatal(format, w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), fmt.Sprint(list.Bindings[0].ID)) {
			t.Fatal("export omitted evidence ID", format)
		}
	}
}
