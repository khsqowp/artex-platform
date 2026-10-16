package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCoworkFactAndFindingWritesEnforceServerSideTargetAuthorization(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	taskID, err := strconv.ParseInt(tasks[0].ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	task, ok := s.m.Task(tasks[0].ID)
	if !ok || task.Store == nil {
		t.Fatal("task store unavailable")
	}
	factPath := fmt.Sprintf("/api/tasks/%s/cowork/facts", tasks[0].ID)
	factBody := fmt.Sprintf(`{"target":"http://127.0.0.1:18081","summary":"Observed behavior","detail":"A concrete response was observed","evidence":"GET / returned the captured response","confidence":"observed","confirmation":"CONFIRM record_fact task=%s"}`, tasks[0].ID)
	if got := request(http.MethodPost, factPath, factBody); got.Code != http.StatusForbidden {
		t.Fatalf("fact write without scope/allow should reject: %d %s", got.Code, got.Body)
	}
	if _, err := s.assetStore().AddAgentScope(taskID, "ip", "127.0.0.1/32", "isolated test", "manual"); err != nil {
		t.Fatal(err)
	}
	allowID, err := task.Store.AddConstraint("allow", "http://127.0.0.1:18081 only", "human")
	if err != nil {
		t.Fatal(err)
	}
	if got := request(http.MethodPost, factPath, strings.Replace(factBody, "127.0.0.1:18081", "127.0.0.2:18081", 1)); got.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope fact target should reject: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, factPath, strings.Replace(factBody, "127.0.0.1:18081", "127.0.0.1:18082", 1)); got.Code != http.StatusForbidden {
		t.Fatalf("target on a port outside the exact human allow should reject: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, factPath, strings.Replace(factBody, `"target":"http://127.0.0.1:18081"`, `"target":"http://127.0.0.1:18081/other"`, 1)); got.Code != http.StatusBadRequest {
		t.Fatalf("target path should reject because only an origin is authorized: %d %s", got.Code, got.Body)
	}
	credentialFact := strings.Replace(factBody, "GET / returned the captured response", "password=fixture-secret", 1)
	if got := request(http.MethodPost, factPath, credentialFact); got.Code != http.StatusBadRequest {
		t.Fatalf("fact write must reject credential-like content at the server boundary: %d %s", got.Code, got.Body)
	}
	factWritten := request(http.MethodPost, factPath, factBody)
	if factWritten.Code != http.StatusCreated {
		t.Fatalf("authorized fact write: %d %s", factWritten.Code, factWritten.Body)
	}
	var factResult struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(factWritten.Body.Bytes(), &factResult); err != nil {
		t.Fatal(err)
	}
	factID, err := strconv.ParseInt(factResult.NodeID, 10, 64)
	if err != nil || factID <= 0 {
		t.Fatalf("fact node id=%q err=%v", factResult.NodeID, err)
	}
	graph := request(http.MethodGet, fmt.Sprintf("/api/exploration/graph?task=%s", tasks[0].ID), "")
	if graph.Code != http.StatusOK || !strings.Contains(graph.Body.String(), "Observed behavior") {
		t.Fatalf("fact did not appear in native exploration graph: %d %s", graph.Code, graph.Body)
	}
	factHistory := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", tasks[0].ID), "")
	if factHistory.Code != http.StatusOK || !strings.Contains(factHistory.Body.String(), "record_fact") || !strings.Contains(factHistory.Body.String(), fmt.Sprintf("cowork-fact-%d", factID)) {
		t.Fatalf("fact write must atomically create its Cowork activity history row: %d %s", factHistory.Code, factHistory.Body)
	}
	goalID, err := task.Store.AddGoal(map[string]any{"text": "Verify an evidenced goal"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	provePath := fmt.Sprintf("/api/tasks/%s/cowork/goals/%d/prove", tasks[0].ID, goalID)
	proveBody := fmt.Sprintf(`{"target":"http://127.0.0.1:18081","evidence_id":%d,"reason":"A task-local observation directly supports this goal","confirmation":"CONFIRM prove_goal task=%s goal=%d evidence=%d"}`, factID, tasks[0].ID, goalID, factID)
	if got := request(http.MethodPost, provePath, strings.Replace(proveBody, "127.0.0.1:18081", "127.0.0.1:18082", 1)); got.Code != http.StatusForbidden {
		t.Fatalf("goal proof outside exact human allow should reject: %d %s", got.Code, got.Body)
	}
	missingEvidenceBody := strings.Replace(proveBody, fmt.Sprintf(`"evidence_id":%d`, factID), `"evidence_id":99999999`, 1)
	if got := request(http.MethodPost, provePath, missingEvidenceBody); got.Code != http.StatusBadRequest {
		t.Fatalf("goal proof with missing task-local evidence should reject: %d %s", got.Code, got.Body)
	}
	proven := request(http.MethodPost, provePath, proveBody)
	if proven.Code != http.StatusOK {
		t.Fatalf("goal proof: %d %s", proven.Code, proven.Body)
	}
	var proofResult struct {
		TaskCompleted bool `json:"task_completed"`
	}
	if err := json.Unmarshal(proven.Body.Bytes(), &proofResult); err != nil || !proofResult.TaskCompleted {
		t.Fatalf("last goal should complete task: result=%s err=%v", proven.Body, err)
	}
	provedGoal, err := task.Store.GetNode(goalID)
	if err != nil || provedGoal == nil || provedGoal.State != "met" || s.m.TaskStatus(tasks[0].ID) != "done" {
		t.Fatalf("goal/task completion not persisted: goal=%+v status=%q err=%v", provedGoal, s.m.TaskStatus(tasks[0].ID), err)
	}
	goalHistory := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", tasks[0].ID), "")
	if goalHistory.Code != http.StatusOK || !strings.Contains(goalHistory.Body.String(), "prove_goal") || !strings.Contains(goalHistory.Body.String(), fmt.Sprintf("cowork-prove-goal-%d-%d", goalID, factID)) {
		t.Fatalf("goal proof and activity must be committed together: %d %s", goalHistory.Code, goalHistory.Body)
	}
	denyID, err := task.Store.AddConstraint("deny", "127.0.0.1:18081", "human")
	if err != nil {
		t.Fatal(err)
	}
	if got := request(http.MethodPost, factPath, factBody); got.Code != http.StatusForbidden {
		t.Fatalf("matching deny should override allow: %d %s", got.Code, got.Body)
	}
	if err := task.Store.DeleteConstraint(allowID); err != nil {
		t.Fatal(err)
	}
	if err := task.Store.DeleteConstraint(denyID); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddConstraint("allow", "http://127.0.0.1:18081 only", "human"); err != nil {
		t.Fatal(err)
	}
	findingPath := fmt.Sprintf("/api/tasks/%s/cowork/findings", tasks[0].ID)
	findingBody := fmt.Sprintf(`{"target":"http://127.0.0.1:18081","vulnclass":"TEST","name":"Confirmed test finding","severity":"low","summary":"Reproducible fixture evidence","evidence":"The isolated test request produced the expected result","confirmation":"CONFIRM report_finding task=%s"}`, tasks[0].ID)
	credentialFinding := strings.Replace(findingBody, "The isolated test request produced the expected result", "Authorization: Bearer fixture-secret", 1)
	if got := request(http.MethodPost, findingPath, credentialFinding); got.Code != http.StatusBadRequest {
		t.Fatalf("finding write must reject credential-like content at the server boundary: %d %s", got.Code, got.Body)
	}
	created := request(http.MethodPost, findingPath, findingBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("authorized finding write: %d %s", created.Code, created.Body)
	}
	var result struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.FindingID == "" {
		t.Fatalf("finding response=%s err=%v", created.Body, err)
	}
	repeated := request(http.MethodPost, findingPath, findingBody)
	var repeatedResult struct {
		FindingID       string `json:"finding_id"`
		IdempotentReuse bool   `json:"idempotent_reuse"`
		ActivityUpdated bool   `json:"activity_updated"`
	}
	if repeated.Code != http.StatusOK || json.Unmarshal(repeated.Body.Bytes(), &repeatedResult) != nil || repeatedResult.FindingID != result.FindingID || !repeatedResult.IdempotentReuse || repeatedResult.ActivityUpdated {
		t.Fatalf("identical confirmed finding retry should reuse the native row without duplicate activity: %d %s", repeated.Code, repeated.Body)
	}
	findingID, err := strconv.ParseInt(result.FindingID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := s.m.pg.GetFinding(findingID)
	if err != nil || finding == nil || finding.TaskID == nil || *finding.TaskID != taskID || finding.Name != "Confirmed test finding" {
		t.Fatalf("native finding not stored for task: finding=%+v err=%v", finding, err)
	}
	if finding.NodeID == nil || *finding.NodeID <= 0 {
		t.Fatalf("native finding node ID missing: %+v", finding)
	}
	reportPath := fmt.Sprintf("/api/tasks/%s/cowork/findings/%d/report", tasks[0].ID, *finding.NodeID)
	updatedReport := "# Cowork verified report"
	reportBody := fmt.Sprintf(`{"confirmation":"CONFIRM update_finding_report task=%s","report":%q}`, tasks[0].ID, updatedReport)
	if got := request(http.MethodPut, reportPath, reportBody); got.Code != http.StatusOK {
		t.Fatalf("task-scoped report update: %d %s", got.Code, got.Body)
	}
	readback := request(http.MethodGet, reportPath, "")
	var reportResult struct {
		TaskID      string `json:"task_id"`
		NodeID      int64  `json:"finding_node_id"`
		FindingID   int64  `json:"finding_id"`
		Report      string `json:"report"`
		ReportStale bool   `json:"report_stale"`
	}
	if readback.Code != http.StatusOK || json.Unmarshal(readback.Body.Bytes(), &reportResult) != nil || reportResult.TaskID != tasks[0].ID || reportResult.NodeID != *finding.NodeID || reportResult.FindingID != findingID || reportResult.Report != updatedReport {
		t.Fatalf("task-scoped report readback mismatch: %d %s", readback.Code, readback.Body)
	}
	reportHistory := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", tasks[0].ID), "")
	if reportHistory.Code != http.StatusOK || !strings.Contains(reportHistory.Body.String(), "update_finding_report") || !strings.Contains(reportHistory.Body.String(), fmt.Sprintf("cowork-report-%d", *finding.NodeID)) {
		t.Fatalf("finding report and activity must persist together: %d %s", reportHistory.Code, reportHistory.Body)
	}
	statusPath := fmt.Sprintf("/api/tasks/%s/cowork/findings/%d/status", tasks[0].ID, findingID)
	wrongConfirmation := fmt.Sprintf(`{"status":"confirmed","confirmation":"CONFIRM update_finding_status task=%s finding=%d status=resolved"}`, tasks[0].ID, findingID)
	if got := request(http.MethodPatch, statusPath, wrongConfirmation); got.Code != http.StatusBadRequest {
		t.Fatalf("finding status change must require exact transition confirmation: %d %s", got.Code, got.Body)
	}
	foreignStatusPath := "/api/tasks/999999/cowork/findings/" + strconv.FormatInt(findingID, 10) + "/status"
	foreignConfirmation := fmt.Sprintf(`{"status":"confirmed","confirmation":"CONFIRM update_finding_status task=999999 finding=%d status=confirmed"}`, findingID)
	if got := request(http.MethodPatch, foreignStatusPath, foreignConfirmation); got.Code != http.StatusNotFound {
		t.Fatalf("finding status change must not cross task boundary: %d %s", got.Code, got.Body)
	}
	statusBody := fmt.Sprintf(`{"status":"confirmed","confirmation":"CONFIRM update_finding_status task=%s finding=%d status=confirmed"}`, tasks[0].ID, findingID)
	statusResult := request(http.MethodPatch, statusPath, statusBody)
	var statusResponse struct {
		FindingID       int64  `json:"finding_id"`
		Status          string `json:"status"`
		ActivityUpdated bool   `json:"activity_updated"`
	}
	if statusResult.Code != http.StatusOK || json.Unmarshal(statusResult.Body.Bytes(), &statusResponse) != nil || statusResponse.FindingID != findingID || statusResponse.Status != "confirmed" || !statusResponse.ActivityUpdated {
		t.Fatalf("task-scoped finding status update: %d %s", statusResult.Code, statusResult.Body)
	}
	statusReadback, err := s.m.pg.GetFinding(findingID)
	if err != nil || statusReadback == nil || statusReadback.Status != "confirmed" {
		t.Fatalf("native finding status was not updated: finding=%+v err=%v", statusReadback, err)
	}
	retestPath := fmt.Sprintf("/api/tasks/%s/cowork/retests", tasks[0].ID)
	retestBody := fmt.Sprintf(`{"finding_id":%d,"target":"http://127.0.0.1:18081","verdict":"reproduced","summary":"Fixture retest reproduced the behavior","evidence":"The isolated fixture evidence still matches","confirmation":"CONFIRM record_cowork_retest task=%s finding=%d"}`, findingID, tasks[0].ID, findingID)
	retestCreated := request(http.MethodPost, retestPath, retestBody)
	var retestResult struct {
		Retest struct {
			ID      int64  `json:"id"`
			Status  string `json:"status"`
			Verdict string `json:"verdict"`
		} `json:"retest"`
		ActivityUpdated bool `json:"activity_updated"`
	}
	if retestCreated.Code != http.StatusCreated || json.Unmarshal(retestCreated.Body.Bytes(), &retestResult) != nil || retestResult.Retest.ID <= 0 || retestResult.Retest.Status != "completed" || retestResult.Retest.Verdict != "reproduced" || !retestResult.ActivityUpdated {
		t.Fatalf("Cowork retest and activity should persist: %d %s", retestCreated.Code, retestCreated.Body)
	}
	retestID := retestResult.Retest.ID
	retestRepeated := request(http.MethodPost, retestPath, retestBody)
	var repeatedRetest struct {
		Retest struct {
			ID int64 `json:"id"`
		} `json:"retest"`
		ActivityUpdated bool `json:"activity_updated"`
		IdempotentReuse bool `json:"idempotent_reuse"`
	}
	if retestRepeated.Code != http.StatusOK || json.Unmarshal(retestRepeated.Body.Bytes(), &repeatedRetest) != nil || repeatedRetest.Retest.ID != retestID || repeatedRetest.ActivityUpdated || !repeatedRetest.IdempotentReuse {
		t.Fatalf("identical Cowork retest retry should reuse the native record: %d %s", retestRepeated.Code, retestRepeated.Body)
	}
	coworkHistory := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", tasks[0].ID), "")
	if coworkHistory.Code != http.StatusOK || !strings.Contains(coworkHistory.Body.String(), "update_finding_status") || !strings.Contains(coworkHistory.Body.String(), "record_finding_retest_result") || !strings.Contains(coworkHistory.Body.String(), "report_finding") || !strings.Contains(coworkHistory.Body.String(), fmt.Sprintf("cowork-finding-%d", findingID)) || !strings.Contains(coworkHistory.Body.String(), fmt.Sprintf("cowork-retest-%d", retestID)) {
		t.Fatalf("finding creation/status transitions missing from Cowork activity history: %d %s", coworkHistory.Code, coworkHistory.Body)
	}
	otherTaskPath := fmt.Sprintf("/api/tasks/999999/cowork/findings/%d/report", *finding.NodeID)
	if got := request(http.MethodGet, otherTaskPath, ""); got.Code != http.StatusNotFound {
		t.Fatalf("finding report must not cross task boundary: %d %s", got.Code, got.Body)
	}
}

func TestCoworkPauseTaskRequiresServerVerifiedConfirmation(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task, ok := s.m.Task(tasks[0].ID)
	if !ok {
		t.Fatal("fixture task unavailable")
	}
	path := fmt.Sprintf("/api/tasks/%s/cowork/pause", task.ID)
	if task.lifecycleSnapshot().Paused {
		t.Fatal("fixture task must begin unpaused")
	}
	if got := request(http.MethodPost, path, `{"confirmation":"wrong"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("pause without exact confirmation should reject: %d %s", got.Code, got.Body)
	}
	if task.lifecycleSnapshot().Paused {
		t.Fatal("rejected pause request changed task state")
	}
	body := fmt.Sprintf(`{"confirmation":"CONFIRM pause_task task=%s"}`, task.ID)
	if got := request(http.MethodPost, path, body); got.Code != http.StatusOK {
		t.Fatalf("confirmed pause: %d %s", got.Code, got.Body)
	}
	if !task.lifecycleSnapshot().Paused {
		t.Fatal("confirmed Cowork pause did not persist native paused state")
	}
}

func TestCoworkTaskSetupAppendsNativeRowsWithoutResumingArtexEngine(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task := tasks[0]
	initialStatus := s.m.TaskStatus(task.ID)
	goalPath := fmt.Sprintf("/api/tasks/%s/cowork/goals", task.ID)
	goalConfirmation := fmt.Sprintf("CONFIRM add_goal task=%s", task.ID)
	goalBody := fmt.Sprintf(`{"confirmation":%q,"text":"Cowork-only goal","vulnclass":"TEST"}`, goalConfirmation)
	goalResult := request(http.MethodPost, goalPath, goalBody)
	if goalResult.Code != http.StatusCreated {
		t.Fatalf("Cowork goal setup: %d %s", goalResult.Code, goalResult.Body)
	}
	var goalResponse struct {
		Goal struct {
			ID string `json:"id"`
		} `json:"goal"`
		TaskMayResume bool `json:"task_may_resume"`
	}
	if err := json.Unmarshal(goalResult.Body.Bytes(), &goalResponse); err != nil || goalResponse.Goal.ID == "" || goalResponse.TaskMayResume {
		t.Fatalf("Cowork goal response must be verified and non-resuming: %s err=%v", goalResult.Body, err)
	}
	if got := s.m.TaskStatus(task.ID); got != initialStatus {
		t.Fatalf("Cowork goal setup changed ARTEx task status: before=%q after=%q", initialStatus, got)
	}
	constraintsPath := fmt.Sprintf("/api/tasks/%s/cowork/constraints", task.ID)
	constraintConfirmation := fmt.Sprintf("CONFIRM add_constraint task=%s", task.ID)
	constraintBody := fmt.Sprintf(`{"confirmation":%q,"kind":"deny","text":"No writes"}`, constraintConfirmation)
	if got := request(http.MethodPost, constraintsPath, constraintBody); got.Code != http.StatusCreated {
		t.Fatalf("Cowork constraint setup: %d %s", got.Code, got.Body)
	}
	scopePath := fmt.Sprintf("/api/tasks/%s/cowork/scope", task.ID)
	scopeConfirmation := fmt.Sprintf("CONFIRM add_scope task=%s", task.ID)
	scopeBody := fmt.Sprintf(`{"confirmation":%q,"kind":"ip","value":"127.0.0.1/32","reason":"isolated fixture"}`, scopeConfirmation)
	scopeResult := request(http.MethodPost, scopePath, scopeBody)
	if scopeResult.Code != http.StatusCreated {
		t.Fatalf("Cowork scope setup: %d %s", scopeResult.Code, scopeResult.Body)
	}
	var scopeResponse struct {
		Scope struct {
			ID int64 `json:"id"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(scopeResult.Body.Bytes(), &scopeResponse); err != nil || scopeResponse.Scope.ID <= 0 {
		t.Fatalf("Cowork scope setup must return the persisted row ID: %s err=%v", scopeResult.Body, err)
	}
	if got := request(http.MethodPost, goalPath, `{"text":"Missing confirmation"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("Cowork goal setup must require operation confirmation: %d %s", got.Code, got.Body)
	}
	credentialGoal := fmt.Sprintf(`{"confirmation":%q,"text":"password=fixture-secret"}`, goalConfirmation)
	if got := request(http.MethodPost, goalPath, credentialGoal); got.Code != http.StatusBadRequest {
		t.Fatalf("Cowork setup must reject credential-like content: %d %s", got.Code, got.Body)
	}
	if got := s.m.TaskStatus(task.ID); got != initialStatus {
		t.Fatalf("Cowork setup should not resume native ARTEx execution: before=%q after=%q", initialStatus, got)
	}
}

func TestCoworkTaskSetupUpdatesAndDeletesOnlyConfirmedTaskRows(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task := tasks[0]
	goalConfirmation := fmt.Sprintf("CONFIRM add_goal task=%s", task.ID)
	goalResult := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/goals", task.ID), fmt.Sprintf(`{"confirmation":%q,"text":"before"}`, goalConfirmation))
	var goal struct {
		Goal struct {
			ID string `json:"id"`
		} `json:"goal"`
	}
	if goalResult.Code != http.StatusCreated || json.Unmarshal(goalResult.Body.Bytes(), &goal) != nil || goal.Goal.ID == "" {
		t.Fatalf("create fixture goal: %d %s", goalResult.Code, goalResult.Body)
	}
	goalID, _ := strconv.ParseInt(goal.Goal.ID, 10, 64)
	updateGoalConfirmation := coworkTaskSetupConfirmation(task.ID, "update_goal", goalID, "after", "xss")
	goalUpdatePath := fmt.Sprintf("/api/tasks/%s/cowork/goals/%s", task.ID, goal.Goal.ID)
	if got := request(http.MethodPost, goalUpdatePath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"text":"tampered","vulnclass":"xss"}`, updateGoalConfirmation)); got.Code != http.StatusBadRequest {
		t.Fatalf("changed goal payload must reject stale confirmation: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, goalUpdatePath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"text":"after","vulnclass":"xss"}`, updateGoalConfirmation)); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"text":"after"`) {
		t.Fatalf("update task goal: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/goals/%s", task.ID, goal.Goal.ID), `{"operation":"delete","confirmation":"wrong"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("goal delete without exact confirmation should reject: %d %s", got.Code, got.Body)
	}
	deleteGoalConfirmation := fmt.Sprintf("CONFIRM delete_goal task=%s goal=%s", task.ID, goal.Goal.ID)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/goals/%s", task.ID, goal.Goal.ID), fmt.Sprintf(`{"operation":"delete","confirmation":%q}`, deleteGoalConfirmation)); got.Code != http.StatusOK {
		t.Fatalf("delete task goal: %d %s", got.Code, got.Body)
	}

	constraintConfirmation := fmt.Sprintf("CONFIRM add_constraint task=%s", task.ID)
	constraintResult := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/constraints", task.ID), fmt.Sprintf(`{"confirmation":%q,"kind":"deny","text":"before"}`, constraintConfirmation))
	var constraint struct {
		Constraint struct {
			ID string `json:"id"`
		} `json:"constraint"`
	}
	if constraintResult.Code != http.StatusCreated || json.Unmarshal(constraintResult.Body.Bytes(), &constraint) != nil || constraint.Constraint.ID == "" {
		t.Fatalf("create fixture constraint: %d %s", constraintResult.Code, constraintResult.Body)
	}
	constraintID, _ := strconv.ParseInt(constraint.Constraint.ID, 10, 64)
	updateConstraintConfirmation := coworkTaskSetupConfirmation(task.ID, "update_constraint", constraintID, "allow", "after")
	constraintPath := fmt.Sprintf("/api/tasks/%s/cowork/constraints/%s", task.ID, constraint.Constraint.ID)
	if got := request(http.MethodPost, constraintPath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"kind":"allow","text":"tampered"}`, updateConstraintConfirmation)); got.Code != http.StatusBadRequest {
		t.Fatalf("changed constraint payload must reject stale confirmation: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, constraintPath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"kind":"allow","text":"after"}`, updateConstraintConfirmation)); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"text":"after"`) {
		t.Fatalf("update task constraint: %d %s", got.Code, got.Body)
	}
	deleteConstraintConfirmation := fmt.Sprintf("CONFIRM delete_constraint task=%s constraint=%s", task.ID, constraint.Constraint.ID)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/constraints/%s", task.ID, constraint.Constraint.ID), fmt.Sprintf(`{"operation":"delete","confirmation":%q}`, deleteConstraintConfirmation)); got.Code != http.StatusOK {
		t.Fatalf("delete task constraint: %d %s", got.Code, got.Body)
	}

	scopeConfirmation := fmt.Sprintf("CONFIRM add_scope task=%s", task.ID)
	scopeResult := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/scope", task.ID), fmt.Sprintf(`{"confirmation":%q,"kind":"ip","value":"127.0.0.1/32"}`, scopeConfirmation))
	var scope struct {
		Scope struct {
			ID int64 `json:"id"`
		} `json:"scope"`
	}
	if scopeResult.Code != http.StatusCreated || json.Unmarshal(scopeResult.Body.Bytes(), &scope) != nil || scope.Scope.ID <= 0 {
		t.Fatalf("create fixture scope: %d %s", scopeResult.Code, scopeResult.Body)
	}
	scopePath := fmt.Sprintf("/api/tasks/%s/cowork/scope/%d", task.ID, scope.Scope.ID)
	if got := request(http.MethodDelete, scopePath, `{"confirmation":"wrong"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("scope delete without confirmation should reject: %d %s", got.Code, got.Body)
	}
	deleteScopeConfirmation := fmt.Sprintf("CONFIRM delete_scope task=%s scope=%d", task.ID, scope.Scope.ID)
	if got := request(http.MethodDelete, scopePath, fmt.Sprintf(`{"confirmation":%q}`, deleteScopeConfirmation)); got.Code != http.StatusOK {
		t.Fatalf("delete task scope: %d %s", got.Code, got.Body)
	}

	history := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=50", task.ID), "")
	for _, tool := range []string{"update_goal", "delete_goal", "update_constraint", "delete_constraint", "delete_task_scope"} {
		if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), tool) {
			t.Fatalf("Cowork setup activity %q missing: %d %s", tool, history.Code, history.Body)
		}
	}
}

func TestCoworkTaskSetupRollsBackMutationsWhenActivityWriteFails(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task := tasks[0]
	store, ok := s.m.Task(task.ID)
	if !ok || store.Store == nil {
		t.Fatal("task store unavailable")
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	goalID, err := store.Store.AddGoal(map[string]any{"text": "rollback fixture goal"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	constraintID, err := store.Store.AddConstraint("deny", "rollback fixture constraint", "human")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := s.assetStore().AddAgentScope(taskID, "ip", "127.0.0.1/32", "rollback fixture", "manual")
	if err != nil {
		t.Fatal(err)
	}
	beforeNodes, err := store.Store.Nodes(1000)
	if err != nil {
		t.Fatal(err)
	}
	beforeConstraints, err := store.Store.ListConstraints()
	if err != nil {
		t.Fatal(err)
	}
	beforeScopes, err := s.assetStore().ListTaskScope(taskID)
	if err != nil {
		t.Fatal(err)
	}
	goalBefore, err := store.Store.GetNode(goalID)
	if err != nil {
		t.Fatal(err)
	}
	triggerName := fmt.Sprintf("artex_test_fail_setup_activity_%d", taskID)
	functionName := fmt.Sprintf("artex_test_fail_setup_activity_fn_%d", taskID)
	if _, err := s.m.pg.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.worker='cowork' AND NEW.tool IN ('add_goal','add_constraint','add_task_scope','update_goal','delete_goal','update_constraint','delete_constraint','delete_task_scope') THEN RAISE EXCEPTION 'forced task setup activity failure'; END IF;
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
	live, unsubscribe := s.engine.Broadcaster().Subscribe(task.ID)
	defer unsubscribe()
	checkFailure := func(label, method, path, body string) {
		t.Helper()
		if got := request(method, path, body); got.Code != http.StatusInternalServerError {
			t.Fatalf("%s should fail with activity insert error: %d %s", label, got.Code, got.Body)
		}
		select {
		case event := <-live:
			t.Fatalf("%s broadcast an uncommitted activity: %+v", label, event)
		default:
		}
	}

	goalPath := fmt.Sprintf("/api/tasks/%s/cowork/goals", task.ID)
	checkFailure("add goal", http.MethodPost, goalPath, fmt.Sprintf(`{"confirmation":%q,"text":"must roll back"}`, fmt.Sprintf("CONFIRM add_goal task=%s", task.ID)))
	constraintPath := fmt.Sprintf("/api/tasks/%s/cowork/constraints", task.ID)
	checkFailure("add constraint", http.MethodPost, constraintPath, fmt.Sprintf(`{"confirmation":%q,"kind":"deny","text":"must roll back"}`, fmt.Sprintf("CONFIRM add_constraint task=%s", task.ID)))
	scopePath := fmt.Sprintf("/api/tasks/%s/cowork/scope", task.ID)
	scopeFailure := request(http.MethodPost, scopePath, fmt.Sprintf(`{"confirmation":%q,"kind":"ip","value":"127.0.0.2/32"}`, fmt.Sprintf("CONFIRM add_scope task=%s", task.ID)))
	if scopeFailure.Code != http.StatusInternalServerError {
		t.Fatalf("add scope should fail with activity insert error: %d %s", scopeFailure.Code, scopeFailure.Body)
	}
	if strings.Contains(scopeFailure.Body.String(), "forced task setup activity failure") || strings.Contains(scopeFailure.Body.String(), "SQLSTATE") {
		t.Fatalf("scope write exposed an internal database error: %s", scopeFailure.Body)
	}
	select {
	case event := <-live:
		t.Fatalf("add scope broadcast an uncommitted activity: %+v", event)
	default:
	}
	goalItemPath := fmt.Sprintf("/api/tasks/%s/cowork/goals/%d", task.ID, goalID)
	goalUpdate := coworkTaskSetupConfirmation(task.ID, "update_goal", goalID, "changed", "xss")
	checkFailure("update goal", http.MethodPost, goalItemPath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"text":"changed","vulnclass":"xss"}`, goalUpdate))
	checkFailure("delete goal", http.MethodPost, goalItemPath, fmt.Sprintf(`{"operation":"delete","confirmation":%q}`, fmt.Sprintf("CONFIRM delete_goal task=%s goal=%d", task.ID, goalID)))
	constraintItemPath := fmt.Sprintf("/api/tasks/%s/cowork/constraints/%d", task.ID, constraintID)
	constraintUpdate := coworkTaskSetupConfirmation(task.ID, "update_constraint", constraintID, "allow", "changed")
	checkFailure("update constraint", http.MethodPost, constraintItemPath, fmt.Sprintf(`{"operation":"update","confirmation":%q,"kind":"allow","text":"changed"}`, constraintUpdate))
	checkFailure("delete constraint", http.MethodPost, constraintItemPath, fmt.Sprintf(`{"operation":"delete","confirmation":%q}`, fmt.Sprintf("CONFIRM delete_constraint task=%s constraint=%d", task.ID, constraintID)))
	scopeItemPath := fmt.Sprintf("/api/tasks/%s/cowork/scope/%d", task.ID, scope.ID)
	checkFailure("delete scope", http.MethodDelete, scopeItemPath, fmt.Sprintf(`{"confirmation":%q}`, fmt.Sprintf("CONFIRM delete_scope task=%s scope=%d", task.ID, scope.ID)))

	afterNodes, err := store.Store.Nodes(1000)
	if err != nil {
		t.Fatal(err)
	}
	afterConstraints, err := store.Store.ListConstraints()
	if err != nil {
		t.Fatal(err)
	}
	afterScopes, err := s.assetStore().ListTaskScope(taskID)
	if err != nil {
		t.Fatal(err)
	}
	goalAfter, err := store.Store.GetNode(goalID)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterNodes) != len(beforeNodes) || !reflect.DeepEqual(afterConstraints, beforeConstraints) || !reflect.DeepEqual(afterScopes, beforeScopes) || goalAfter == nil || !reflect.DeepEqual(goalAfter.Payload, goalBefore.Payload) {
		t.Fatalf("failed Cowork setup operations left partial state: nodes=%d/%d constraints=%+v/%+v scopes=%+v/%+v goal=%+v", len(afterNodes), len(beforeNodes), afterConstraints, beforeConstraints, afterScopes, beforeScopes, goalAfter)
	}
}

func TestCoworkFactRejectsOversizedRequestBodyBeforeWriting(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	path := fmt.Sprintf("/api/tasks/%s/cowork/facts", tasks[0].ID)
	body := `{"padding":"` + strings.Repeat("x", (256<<10)+1) + `"}`
	if got := request(http.MethodPost, path, body); got.Code != http.StatusBadRequest {
		t.Fatalf("oversized Cowork fact body should reject before parsing or writing: %d %s", got.Code, got.Body)
	}
	graph := request(http.MethodGet, fmt.Sprintf("/api/exploration/graph?task=%s", tasks[0].ID), "")
	if graph.Code != http.StatusOK || strings.Contains(graph.Body.String(), "padding") {
		t.Fatalf("oversized request must not create a graph fact: %d %s", graph.Code, graph.Body)
	}
}

func TestCoworkIntentBatchPersistsGraphAndActivityAsOneVerifiedPlan(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	taskID := tasks[0].ID
	task, ok := s.m.Task(taskID)
	if !ok || task.Store == nil {
		t.Fatal("fixture task store unavailable")
	}
	path := fmt.Sprintf("/api/tasks/%s/cowork/intents", taskID)
	confirmation := fmt.Sprintf("CONFIRM add_cowork_intents task=%s", taskID)
	body := fmt.Sprintf(`{"confirmation":%q,"intents":[{"summary":"Plan item A","priority":7},{"summary":"Plan item B","priority":4}]}`, confirmation)
	created := request(http.MethodPost, path, body)
	if created.Code != http.StatusCreated {
		t.Fatalf("Cowork intent batch: %d %s", created.Code, created.Body)
	}
	var result struct {
		IDs             []int64 `json:"intent_ids"`
		ActivityUpdated bool    `json:"activity_updated"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || len(result.IDs) != 2 || result.IDs[0] <= 0 || result.IDs[1] <= 0 || !result.ActivityUpdated {
		t.Fatalf("intent batch must return both IDs and its persisted activity: %s err=%v", created.Body, err)
	}
	for _, id := range result.IDs {
		intent, getErr := task.Store.GetNode(id)
		if getErr != nil || intent == nil || intent.Kind != db.KindIntent {
			t.Fatalf("intent %d missing from native exploration graph: node=%+v err=%v", id, intent, getErr)
		}
	}
	historyPath := fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", taskID)
	history := request(http.MethodGet, historyPath, "")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), "add_intent") || !strings.Contains(history.Body.String(), fmt.Sprintf("cowork-intents-%s-%d", taskID, result.IDs[0])) {
		t.Fatalf("intent batch activity missing: %d %s", history.Code, history.Body)
	}
	duplicate := request(http.MethodPost, path, body)
	var repeated struct {
		IDs []int64 `json:"intent_ids"`
	}
	if duplicate.Code != http.StatusCreated || json.Unmarshal(duplicate.Body.Bytes(), &repeated) != nil || len(repeated.IDs) != len(result.IDs) || repeated.IDs[0] != result.IDs[0] || repeated.IDs[1] != result.IDs[1] {
		t.Fatalf("identical intent batch should deduplicate to the original IDs: %d %s", duplicate.Code, duplicate.Body)
	}
}

func TestCoworkIntentBatchRollsBackWhenActivityWriteFails(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task := tasks[0]
	store, ok := s.m.Task(task.ID)
	if !ok || store.Store == nil {
		t.Fatal("fixture task store unavailable")
	}
	var beforeNodes, beforeEdges, beforeActivities int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, store.Store.ID()).Scan(&beforeNodes); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_edges WHERE exploration_id=$1`, store.Store.ID()).Scan(&beforeEdges); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND worker='cowork' AND tool='add_intent'`, store.Store.ID()).Scan(&beforeActivities); err != nil {
		t.Fatal(err)
	}

	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	triggerName := fmt.Sprintf("artex_test_fail_intent_activity_%d", taskID)
	functionName := fmt.Sprintf("artex_test_fail_intent_activity_fn_%d", taskID)
	if _, err := s.m.pg.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.worker='cowork' AND NEW.tool='add_intent' THEN RAISE EXCEPTION 'forced intent activity failure'; END IF;
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

	live, unsubscribe := s.engine.Broadcaster().Subscribe(task.ID)
	defer unsubscribe()
	confirmation := fmt.Sprintf("CONFIRM add_cowork_intents task=%s", task.ID)
	body := fmt.Sprintf(`{"confirmation":%q,"intents":[{"summary":"rollback intent A","priority":7},{"summary":"rollback intent B","priority":4}]}`, confirmation)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intents", task.ID), body); got.Code != http.StatusInternalServerError {
		t.Fatalf("activity insert failure should reject the intent plan: %d %s", got.Code, got.Body)
	}
	select {
	case event := <-live:
		t.Fatalf("rolled-back intent plan must not broadcast activity: %+v", event)
	default:
	}
	var afterNodes, afterEdges, afterActivities int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, store.Store.ID()).Scan(&afterNodes); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_edges WHERE exploration_id=$1`, store.Store.ID()).Scan(&afterEdges); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND worker='cowork' AND tool='add_intent'`, store.Store.ID()).Scan(&afterActivities); err != nil {
		t.Fatal(err)
	}
	if afterNodes != beforeNodes || afterEdges != beforeEdges || afterActivities != beforeActivities {
		t.Fatalf("failed intent plan left partial rows: nodes=%d/%d edges=%d/%d activities=%d/%d", afterNodes, beforeNodes, afterEdges, beforeEdges, afterActivities, beforeActivities)
	}
}

func TestCoworkAssetWritesRequireServerScopeAndStayOnExactOrigin(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	task := tasks[0]
	path := fmt.Sprintf("/api/tasks/%s/cowork/assets", task.ID)
	confirmation := fmt.Sprintf("CONFIRM insert_assets task=%s", task.ID)
	assets := `{"target":"http://127.0.0.1:18081","confirmation":"` + confirmation + `","assets":[{"type":"ip","ip":"127.0.0.1"},{"type":"service","url":"http://127.0.0.1:18081","technologies":["fixture"],"status_code":200},{"type":"endpoint","url":"http://127.0.0.1:18081/api/observed","method":"GET"}]}`
	if got := request(http.MethodPost, path, assets); got.Code != http.StatusForbidden {
		t.Fatalf("asset write without task scope and human allow should reject: %d %s", got.Code, got.Body)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.assetStore().AddAgentScope(taskID, "ip", "127.0.0.1/32", "isolated fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddConstraint("allow", "http://127.0.0.1:18081 only", "human"); err != nil {
		t.Fatal(err)
	}
	wrongConfirmation := strings.Replace(assets, confirmation, "CONFIRM insert_assets task=999", 1)
	if got := request(http.MethodPost, path, wrongConfirmation); got.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation should reject: %d %s", got.Code, got.Body)
	}
	outOfOrigin := strings.Replace(assets, "http://127.0.0.1:18081/api/observed", "http://127.0.0.2:18081/api/observed", 1)
	if got := request(http.MethodPost, path, outOfOrigin); got.Code != http.StatusBadRequest {
		t.Fatalf("asset URL outside exact origin should reject: %d %s", got.Code, got.Body)
	}
	unsafeMethod := strings.Replace(assets, `"method":"GET"`, `"method":"DELETE"`, 1)
	if got := request(http.MethodPost, path, unsafeMethod); got.Code != http.StatusBadRequest {
		t.Fatalf("write-capable endpoint metadata should reject: %d %s", got.Code, got.Body)
	}
	credentialMetadata := strings.Replace(assets, `"url":"http://127.0.0.1:18081","technologies"`, `"url":"http://127.0.0.1:18081","page_title":"Authorization: secret","technologies"`, 1)
	if got := request(http.MethodPost, path, credentialMetadata); got.Code != http.StatusBadRequest {
		t.Fatalf("credential-like metadata should reject: %d %s", got.Code, got.Body)
	}
	created := request(http.MethodPost, path, assets)
	if created.Code != http.StatusOK {
		t.Fatalf("authorized assets should be stored through native asset path: %d %s", created.Code, created.Body)
	}
	listed := request(http.MethodGet, fmt.Sprintf("/api/assets?task_id=%d", taskID), "")
	if listed.Code != http.StatusOK {
		t.Fatalf("native Test Assets list: %d %s", listed.Code, listed.Body)
	}
	for _, expected := range []string{"127.0.0.1", "http://127.0.0.1:18081", "/api/observed"} {
		if !strings.Contains(listed.Body.String(), expected) {
			t.Fatalf("registered asset %q missing from native Test Assets response: %s", expected, listed.Body)
		}
	}
	if !strings.Contains(created.Body.String(), `"activity_updated":true`) {
		t.Fatalf("asset write should confirm the Cowork activity record: %s", created.Body)
	}
	history := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork", task.ID), "")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), "insert_assets") || !strings.Contains(history.Body.String(), "cowork-assets-") {
		t.Fatalf("registered assets should appear in task Cowork activity history: %d %s", history.Code, history.Body)
	}
}
