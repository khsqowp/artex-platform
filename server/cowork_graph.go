package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const maxCoworkGraphField = 12000

func validCoworkText(value string) bool {
	return strings.TrimSpace(value) != "" && len([]rune(value)) <= maxCoworkGraphField
}

// POST /api/tasks/{id}/cowork/pause stops ARTEx's own planner and workers.
// Cowork cannot resume this engine because it would use ARTEx's separate LLM runtime.
func (s *Server) coworkPauseTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM pause_task task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	result, err := s.applyTaskControl(t, "pause")
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	_, activityErr := s.appendCoworkActivity(t, db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "pause_task", ToolUseID: fmt.Sprintf("cowork-pause-%s", t.ID), Summary: "운영자 요청으로 ARTEx 네이티브 작업 실행을 일시정지했습니다", Detail: "Cowork 세션 상태에는 영향을 주지 않습니다"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": t.ID, "paused": result.Paused, "status": result.Status, "activity_updated": activityErr == nil, "activity_error": errorString(activityErr)})
}

// validateCoworkTarget repeats the Cowork connector's preflight at the ARTEx
// server boundary. A local REST caller must not be able to bypass task scope or
// operator-authored allow/deny constraints by calling these write routes directly.
func (s *Server) validateCoworkTarget(t *Task, raw string) (string, int, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", http.StatusBadRequest, "target must be an HTTP(S) origin without credentials, query or fragment"
	}
	if u.Path != "" && u.Path != "/" {
		return "", http.StatusBadRequest, "target must be an origin only"
	}
	u.Path, u.RawPath = "", ""
	origin := strings.TrimRight(u.String(), "/")
	host := strings.ToLower(u.Hostname())
	authority := strings.ToLower(u.Host)

	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return "", http.StatusBadRequest, "invalid task id"
	}
	scopes, err := s.assetStore().ListTaskScope(taskID)
	if err != nil {
		return "", http.StatusInternalServerError, err.Error()
	}
	hostAllowed := false
	parsedIP := net.ParseIP(host)
	for _, scope := range scopes {
		switch scope.Kind {
		case "ip", "cidr":
			if parsedIP != nil {
				_, network, parseErr := net.ParseCIDR(scope.Net)
				if parseErr == nil && network.Contains(parsedIP) {
					hostAllowed = true
				}
			}
		case "root_domain", "subdomain":
			domain := strings.ToLower(strings.TrimPrefix(scope.Domain, "."))
			if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
				hostAllowed = true
			}
		}
	}
	constraints, err := t.Store.ListConstraints()
	if err != nil {
		return "", http.StatusInternalServerError, err.Error()
	}
	allow, denied := false, false
	for _, constraint := range constraints {
		text := strings.ToLower(constraint.Text)
		matches := strings.Contains(text, strings.ToLower(origin)) || containsCoworkAuthority(text, authority)
		if !matches {
			continue
		}
		if constraint.Kind == "deny" {
			denied = true
		}
		if constraint.Kind == "allow" && constraint.Origin == "human" {
			allow = true
		}
	}
	if !hostAllowed || !allow || denied {
		return "", http.StatusForbidden, "Cowork target is not covered by task scope and exact human allow constraint, or matches a deny constraint"
	}
	return origin, 0, ""
}

func containsCoworkAuthority(text, authority string) bool {
	for start := 0; start <= len(text)-len(authority); {
		relative := strings.Index(text[start:], authority)
		if relative < 0 {
			return false
		}
		index := start + relative
		end := index + len(authority)
		leftOK := index == 0 || !isCoworkHostChar(text[index-1])
		rightOK := end == len(text) || !isCoworkHostChar(text[end])
		if leftOK && rightOK {
			return true
		}
		start = index + 1
	}
	return false
}

func isCoworkHostChar(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '.' || value == '-'
}

// POST /api/tasks/{id}/facts appends one task-local exploration fact. This route
// deliberately uses the same graph store and activity stream as native agents.
func (s *Server) coworkRecordFact(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Target       string `json:"target"`
		Summary      string `json:"summary"`
		Detail       string `json:"detail"`
		Evidence     string `json:"evidence"`
		Confidence   string `json:"confidence"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM record_fact task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if _, status, message := s.validateCoworkTarget(t, req.Target); status != 0 {
		writeErr(w, status, message)
		return
	}
	if !validCoworkText(req.Summary) || !validCoworkText(req.Detail) || !validCoworkText(req.Evidence) {
		writeErr(w, http.StatusBadRequest, "summary, detail and evidence are required and must be at most 12000 characters")
		return
	}
	if credentialLikeCoworkText(req.Summary) || credentialLikeCoworkText(req.Detail) || credentialLikeCoworkText(req.Evidence) {
		writeErr(w, http.StatusBadRequest, "fact fields must not contain credential-like values")
		return
	}
	if req.Confidence != "observed" && req.Confidence != "inferred" {
		writeErr(w, http.StatusBadRequest, "confidence must be observed or inferred")
		return
	}
	payload := map[string]any{"summary": strings.TrimSpace(req.Summary), "detail": strings.TrimSpace(req.Detail), "evidence": strings.TrimSpace(req.Evidence), "confidence": req.Confidence}
	nodeID, activity, err := t.Store.RecordCoworkFact(r.Context(), payload,
		"Cowork가 Task 그래프에 관찰 사실을 기록했습니다", req.Summary)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "task_id": t.ID, "node_id": strconv.FormatInt(nodeID, 10), "kind": db.KindFact, "activity_updated": true})
}

// POST /api/tasks/{id}/cowork/goals/{goalID}/prove marks one task-local goal
// met from an existing task-local fact or finding, matching ARTEx prove_goal.
func (s *Server) coworkProveGoal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	goalID, err := strconv.ParseInt(r.PathValue("goalID"), 10, 64)
	if err != nil || goalID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid goal id")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Target       string `json:"target"`
		EvidenceID   int64  `json:"evidence_id"`
		Reason       string `json:"reason"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	expected := fmt.Sprintf("CONFIRM prove_goal task=%s goal=%d evidence=%d", t.ID, goalID, req.EvidenceID)
	if req.EvidenceID <= 0 || req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if _, status, message := s.validateCoworkTarget(t, req.Target); status != 0 {
		writeErr(w, status, message)
		return
	}
	if !validCoworkText(req.Reason) {
		writeErr(w, http.StatusBadRequest, "reason is required and must be at most 12000 characters")
		return
	}
	goal, err := t.Store.GetNode(goalID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if goal == nil || goal.Kind != db.KindGoal {
		writeErr(w, http.StatusNotFound, "goal does not belong to this task")
		return
	}
	evidence, err := t.Store.GetNode(req.EvidenceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if evidence == nil || (evidence.Kind != db.KindFact && evidence.Kind != db.KindFinding) {
		writeErr(w, http.StatusBadRequest, "evidence_id must identify a fact or finding in this task")
		return
	}
	callID := fmt.Sprintf("cowork-prove-goal-%d-%d", goalID, req.EvidenceID)
	allMet, activity, err := t.Store.ProveCoworkGoal(r.Context(), goalID, req.EvidenceID, req.Reason, callID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if allMet {
		if err := s.m.SetTaskStatus(t.ID, "done"); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if s.engine != nil {
			s.engine.cancelExec(t.ID, agent.AbortGoalMet)
		}
	}
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": t.ID, "goal_id": goalID, "evidence_id": req.EvidenceID, "state": "met", "task_completed": allMet, "activity_updated": true})
}

// POST /api/tasks/{id}/findings records a confirmed finding through ARTEx's
// native transactional finding store. Candidate/observation records belong in
// facts and are not accepted as findings by the Cowork tool contract.
func (s *Server) coworkReportFinding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Target       string `json:"target"`
		VulnClass    string `json:"vulnclass"`
		Name         string `json:"name"`
		Severity     string `json:"severity"`
		Summary      string `json:"summary"`
		Evidence     string `json:"evidence"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM report_finding task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if _, status, message := s.validateCoworkTarget(t, req.Target); status != 0 {
		writeErr(w, status, message)
		return
	}
	if !validCoworkText(req.VulnClass) || !validCoworkText(req.Name) || !validCoworkText(req.Summary) || !validCoworkText(req.Evidence) {
		writeErr(w, http.StatusBadRequest, "vulnclass, name, summary and evidence are required and must be at most 12000 characters")
		return
	}
	if credentialLikeCoworkText(req.VulnClass) || credentialLikeCoworkText(req.Name) || credentialLikeCoworkText(req.Summary) || credentialLikeCoworkText(req.Evidence) {
		writeErr(w, http.StatusBadRequest, "finding fields must not contain credential-like values")
		return
	}
	req.Severity = strings.ToLower(strings.TrimSpace(req.Severity))
	if req.Severity != "critical" && req.Severity != "high" && req.Severity != "medium" && req.Severity != "low" {
		writeErr(w, http.StatusBadRequest, "severity must be critical, high, medium or low")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	recorded, activities, reused, err := t.Store.RecordCoworkFinding(r.Context(), db.RecordFindingInput{TaskID: taskID, ExplorationID: t.Store.ID(), VulnClass: strings.TrimSpace(req.VulnClass), Name: strings.TrimSpace(req.Name), Severity: req.Severity, Summary: strings.TrimSpace(req.Summary), Evidence: strings.TrimSpace(req.Evidence), Worker: "cowork"})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, activity := range activities {
		s.publishCoworkActivity(t, activity)
	}
	if !reused {
		t.NotifyFinding(0, req.Summary)
	}
	status := http.StatusCreated
	if reused {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"ok": true, "task_id": t.ID, "finding_id": strconv.FormatInt(recorded.FindingID, 10), "finding_node_id": strconv.FormatInt(recorded.NodeID, 10), "activity_updated": len(activities) > 0, "idempotent_reuse": reused})
}

// GET /api/tasks/{id}/cowork/findings/{nodeID}/report reads the native report
// through the task-local graph node ID used by the write operation.
func (s *Server) coworkGetFindingReport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid finding node id")
		return
	}
	nodes, err := t.Store.ListByKind(db.KindFinding, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	belongs := false
	for _, node := range nodes {
		if node.ID == nodeID {
			belongs = true
			break
		}
	}
	if !belongs {
		writeErr(w, http.StatusNotFound, "finding does not belong to this task")
		return
	}
	findingID, err := s.m.pg.FindingIDByNodeID(nodeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "finding report not found")
		return
	}
	finding, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || finding == nil || finding.TaskID == nil || *finding.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "finding report does not belong to this task")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id": t.ID, "finding_node_id": nodeID, "finding_id": findingID,
		"report": finding.Report, "evidence_version": finding.EvidenceVersion,
		"report_evidence_version": finding.ReportEvidenceVersion, "report_stale": finding.Report != "" && finding.EvidenceVersion != finding.ReportEvidenceVersion,
	})
}

// PUT /api/tasks/{id}/cowork/findings/{nodeID}/report saves a Cowork-authored
// report through ARTEx's native finding store. The finding must belong to this
// task, and an operation-specific confirmation is required.
func (s *Server) coworkUpdateFindingReport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid finding node id")
		return
	}
	var req struct {
		Confirmation    string `json:"confirmation"`
		Report          string `json:"report"`
		EvidenceVersion *int64 `json:"evidence_version"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM update_finding_report task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if strings.TrimSpace(req.Report) == "" || len([]rune(req.Report)) > 120000 {
		writeErr(w, http.StatusBadRequest, "report is required and must be at most 120000 characters")
		return
	}
	if credentialLikeCoworkText(req.Report) {
		writeErr(w, http.StatusBadRequest, "report must not contain credential-like values")
		return
	}
	nodes, err := t.Store.ListByKind(db.KindFinding, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	belongs := false
	for _, node := range nodes {
		if node.ID == nodeID {
			belongs = true
			break
		}
	}
	if !belongs {
		writeErr(w, http.StatusNotFound, "finding does not belong to this task")
		return
	}
	updated, activity, err := s.m.pg.SetCoworkFindingReportWithActivity(r.Context(), t.Store.ID(), nodeID, strings.TrimSpace(req.Report), req.EvidenceVersion, fmt.Sprintf("cowork-report-%d", nodeID))
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if !updated {
		writeErr(w, http.StatusNotFound, "finding report target not found")
		return
	}
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": t.ID, "finding_node_id": nodeID, "updated": true, "activity_updated": true})
}

// PATCH /api/tasks/{id}/cowork/findings/{findingID}/status updates the triage
// status of a finding that belongs to this task. Status changes use ARTEx's
// notification-aware workflow and require exact operator confirmation.
func (s *Server) coworkUpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	findingID, err := strconv.ParseInt(r.PathValue("findingID"), 10, 64)
	if err != nil || findingID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Status       string `json:"status"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != fmt.Sprintf("CONFIRM update_finding_status task=%s finding=%d status=%s", t.ID, findingID, req.Status) {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if !db.ValidFindingStatus(req.Status) {
		writeErr(w, http.StatusBadRequest, "invalid finding status")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	meta, err := s.m.pg.FindingMetaByNodeID(taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var nodeID int64
	for id, finding := range meta {
		if finding.ID == findingID {
			nodeID = id
			break
		}
	}
	if nodeID == 0 {
		writeErr(w, http.StatusNotFound, "finding does not belong to this task")
		return
	}
	from, found, changed, notified, activity, err := t.Store.SetCoworkFindingStatusWithActivity(
		r.Context(), findingID, nodeID, req.Status, fmt.Sprintf("cowork-finding-status-%d-%s-%d", findingID, req.Status, time.Now().UnixNano()),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	if changed {
		s.publishCoworkActivity(t, activity)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "task_id": t.ID, "finding_id": findingID, "finding_node_id": nodeID,
		"from": from, "status": req.Status, "changed": changed, "notified": notified,
		"activity_updated": changed && activity.ID > 0, "activity_seq": activity.ID,
	})
}

// POST /api/tasks/{id}/cowork/retests records a Cowork-executed retest in the
// native retest history. The server rechecks task ownership, target scope and
// the human allow constraint; a client-side MCP preflight is not sufficient.
func (s *Server) coworkRecordFindingRetest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 600<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		FindingID    int64  `json:"finding_id"`
		Target       string `json:"target"`
		Verdict      string `json:"verdict"`
		Summary      string `json:"summary"`
		Evidence     string `json:"evidence"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.FindingID <= 0 || req.Confirmation != fmt.Sprintf("CONFIRM record_cowork_retest task=%s finding=%d", t.ID, req.FindingID) {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	target, status, message := s.validateCoworkTarget(t, req.Target)
	if status != 0 {
		writeErr(w, status, message)
		return
	}
	tid, _ := strconv.ParseInt(t.ID, 10, 64)
	if !validCoworkText(req.Summary) || !validCoworkText(req.Evidence) || len([]rune(req.Evidence)) > 128000 {
		writeErr(w, http.StatusBadRequest, "summary and evidence are required and evidence must be at most 128000 characters")
		return
	}
	rt, activity, reused, err := s.m.pg.RecordCoworkFindingRetest(r.Context(), tid, req.FindingID, target, req.Verdict, req.Summary, req.Evidence)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "finding does not belong to this task")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if !reused {
		s.publishCoworkActivity(t, activity)
	}
	statusCode := http.StatusCreated
	if reused {
		statusCode = http.StatusOK
	}
	writeJSON(w, statusCode, map[string]any{"ok": true, "retest": rt, "activity_updated": !reused, "idempotent_reuse": reused})
}

// POST /api/tasks/{id}/cowork/assets registers already observed asset metadata
// only after the server rechecks Task scope, human allow/deny, and exact origin.
// It delegates persistence to the native task asset store after validation.
func (s *Server) coworkRegisterAssets(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string           `json:"confirmation"`
		Target       string           `json:"target"`
		Assets       []map[string]any `json:"assets"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM insert_assets task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	target, status, message := s.validateCoworkTarget(t, req.Target)
	if status != 0 {
		writeErr(w, status, message)
		return
	}
	if len(req.Assets) == 0 || len(req.Assets) > 20 {
		writeErr(w, http.StatusBadRequest, "assets must contain 1 to 20 already observed records")
		return
	}
	for index, asset := range req.Assets {
		if err := validateCoworkAsset(asset, target); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("assets[%d]: %v", index, err))
			return
		}
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	encoded, err := json.Marshal(req.Assets)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid asset metadata")
		return
	}
	var inputs []db.CoworkAssetInput
	if err := json.Unmarshal(encoded, &inputs); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid asset metadata")
		return
	}
	results, err := s.assetStore().RegisterCoworkAssets(taskID, inputs)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	response := make([]map[string]any, 0, len(results))
	for index, result := range results {
		response = append(response, map[string]any{"index": index, "id": result.ID, "type": result.Type})
	}
	activityErr := error(nil)
	if len(results) > 0 {
		activityID := fmt.Sprintf("cowork-assets-%s-%d", t.ID, results[0].ID)
		assetIDs := make([]int64, 0, len(results))
		for _, item := range results {
			assetIDs = append(assetIDs, item.ID)
		}
		_, activityErr = s.appendCoworkActivity(t, db.Activity{
			Worker: "cowork", Kind: "tool_result", Tool: "insert_assets", ToolUseID: activityID,
			Summary: fmt.Sprintf("Cowork가 이미 관찰한 자산 %d건을 ARTEx에 등록했습니다", len(results)),
			Detail:  fmt.Sprintf("asset_ids=%v", assetIDs),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": response, "errors": []any{}, "activity_updated": activityErr == nil, "activity_error": errorString(activityErr)})
}

func validateCoworkAsset(asset map[string]any, target string) error {
	typeName, _ := asset["type"].(string)
	allowed := map[string]map[string]bool{
		"ip":       {"type": true, "ip": true},
		"service":  {"type": true, "url": true, "technologies": true, "status_code": true, "content_length": true, "page_title": true, "favicon_mmh3": true},
		"endpoint": {"type": true, "url": true, "method": true},
	}
	fields, ok := allowed[typeName]
	if !ok {
		return fmt.Errorf("type must be ip, service, or endpoint")
	}
	for key := range asset {
		if !fields[key] {
			return fmt.Errorf("unsupported field %q", key)
		}
	}
	if typeName == "service" {
		if status, ok := asset["status_code"].(float64); ok && (status < 100 || status > 599 || status != float64(int(status))) {
			return fmt.Errorf("status_code must be an observed HTTP status from 100 to 599")
		}
		if size, ok := asset["content_length"].(float64); ok && (size < 0 || size != float64(int64(size))) {
			return fmt.Errorf("content_length must be a non-negative integer")
		}
		if title, ok := asset["page_title"].(string); ok && len([]rune(title)) > 512 {
			return fmt.Errorf("page_title must be at most 512 characters")
		}
		if title, ok := asset["page_title"].(string); ok && credentialLikeCoworkText(title) {
			return fmt.Errorf("page_title appears to contain credential-like data")
		}
		if favicon, ok := asset["favicon_mmh3"].(string); ok && len(favicon) > 128 {
			return fmt.Errorf("favicon_mmh3 must be at most 128 characters")
		}
		if technologies, ok := asset["technologies"].([]any); ok {
			if len(technologies) > 30 {
				return fmt.Errorf("technologies must contain at most 30 entries")
			}
			for _, value := range technologies {
				technology, ok := value.(string)
				if !ok || strings.TrimSpace(technology) == "" || len([]rune(technology)) > 128 {
					return fmt.Errorf("each technology must be a non-empty string of at most 128 characters")
				}
				if credentialLikeCoworkText(technology) {
					return fmt.Errorf("technology metadata appears to contain credential-like data")
				}
			}
		}
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid authorized target")
	}
	if typeName == "ip" {
		value, _ := asset["ip"].(string)
		ip, targetIP := net.ParseIP(value), net.ParseIP(targetURL.Hostname())
		if ip == nil || targetIP == nil || !ip.Equal(targetIP) {
			return fmt.Errorf("IP metadata must equal the authorized target IP")
		}
		return nil
	}
	value, _ := asset["url"].(string)
	assetURL, err := url.Parse(strings.TrimSpace(value))
	if err != nil || assetURL.Scheme == "" || assetURL.Hostname() == "" || assetURL.User != nil || assetURL.RawQuery != "" || assetURL.Fragment != "" {
		return fmt.Errorf("url must be an HTTP(S) URL on the authorized origin without credentials, query, or fragment")
	}
	if assetURL.Scheme != targetURL.Scheme || !strings.EqualFold(strings.TrimSuffix(assetURL.Hostname(), "."), strings.TrimSuffix(targetURL.Hostname(), ".")) || effectiveCoworkPort(assetURL) != effectiveCoworkPort(targetURL) {
		return fmt.Errorf("url must stay on the exact authorized origin")
	}
	if typeName == "service" && assetURL.Path != "" && assetURL.Path != "/" {
		return fmt.Errorf("service url must be the origin root")
	}
	if typeName == "endpoint" {
		method, _ := asset["method"].(string)
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("endpoint metadata accepts only observed GET, HEAD, or OPTIONS methods")
		}
		decodedPath, decodeErr := url.PathUnescape(assetURL.EscapedPath())
		if decodeErr != nil || len(decodedPath) > 2048 || strings.ContainsAny(decodedPath, "\\\x00\r\n") {
			return fmt.Errorf("invalid endpoint path")
		}
		for _, part := range strings.Split(decodedPath, "/") {
			if part == "." || part == ".." {
				return fmt.Errorf("endpoint path must not contain dot segments")
			}
		}
		asset["method"] = method
	}
	asset["url"] = assetURL.String()
	return nil
}

func credentialLikeCoworkText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "passwd", "api_key", "api-key", "access_token", "access-token", "authorization"} {
		if index := strings.Index(lower, marker); index >= 0 {
			remainder := strings.TrimSpace(lower[index+len(marker):])
			if strings.HasPrefix(remainder, ":") || strings.HasPrefix(remainder, "=") {
				return true
			}
		}
	}
	return strings.Contains(lower, "bearer ")
}

func effectiveCoworkPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}

// POST /api/tasks/{id}/cowork/intercepts/{pendingID}/decide applies an
// operator-confirmed decision to one pending request owned by this task.
func (s *Server) coworkDecideIntercept(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	taskID := r.PathValue("id")
	t, ok := s.m.Task(taskID)
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pendingID, err := strconv.ParseInt(r.PathValue("pendingID"), 10, 64)
	if err != nil || pendingID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid pending approval id")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Decision     string `json:"decision"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Decision != "allowed" && req.Decision != "denied" {
		writeErr(w, http.StatusBadRequest, "decision must be allowed or denied")
		return
	}
	expected := fmt.Sprintf("CONFIRM decide_intercept task=%s pending=%d decision=%s", taskID, pendingID, req.Decision)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	pending, err := s.m.pg.GetInterceptPending(pendingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pending == nil || pending.TaskID == nil || *pending.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "approval does not belong to this task")
		return
	}
	if pending.Status != "pending" {
		writeErr(w, http.StatusConflict, "approval is no longer pending")
		return
	}
	if err = s.m.interceptor.Decide(pendingID, req.Decision == "allowed"); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	_, activityErr := s.appendCoworkActivity(t, db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "decide_intercept", ToolUseID: fmt.Sprintf("cowork-intercept-%d", pendingID), Summary: "Cowork가 운영자 승인으로 대기 중 요청을 처리했습니다", Detail: fmt.Sprintf("pending_id=%d decision=%s", pendingID, req.Decision)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": taskID, "pending_id": pendingID, "decision": req.Decision, "activity_updated": activityErr == nil, "activity_error": errorString(activityErr)})
}

// POST /api/tasks/{id}/cowork/intents appends bounded Cowork planning items to
// the native exploration graph. Exact open-summary retries return the existing ID.
func (s *Server) coworkAddIntents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Intents      []struct {
			Summary   string  `json:"summary"`
			Priority  int     `json:"priority"`
			ParentIDs []int64 `json:"parent_ids"`
		} `json:"intents"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Confirmation != "CONFIRM add_cowork_intents task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if len(req.Intents) == 0 || len(req.Intents) > 20 {
		writeErr(w, http.StatusBadRequest, "intents must contain 1 to 20 items")
		return
	}
	existing, err := t.Store.ListByKind(db.KindIntent, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	openBySummary := map[string]int64{}
	for _, node := range existing {
		if node.State == "open" {
			var p map[string]any
			_ = json.Unmarshal(node.Payload, &p)
			if summary, ok := p["summary"].(string); ok {
				openBySummary[strings.TrimSpace(summary)] = node.ID
			}
		}
	}
	type preparedIntent struct {
		summary  string
		priority int
		parents  []int64
	}
	prepared := make([]preparedIntent, len(req.Intents))
	batchSummaries := map[string]struct{}{}
	for i, item := range req.Intents {
		summary := strings.TrimSpace(item.Summary)
		if !validCoworkText(summary) || item.Priority < 0 || item.Priority > 10 {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("intent %d has invalid summary or priority", i))
			return
		}
		if _, duplicate := batchSummaries[summary]; duplicate {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("intent %d duplicates a summary in this batch", i))
			return
		}
		batchSummaries[summary] = struct{}{}
		parents := make([]int64, 0, len(item.ParentIDs))
		for _, parentID := range item.ParentIDs {
			node, getErr := t.Store.GetNode(parentID)
			if getErr != nil || node == nil || (node.Kind != db.KindFact && node.Kind != db.KindFinding) {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("intent %d parent_ids must reference task-local fact/finding nodes", i))
				return
			}
			parents = append(parents, parentID)
		}
		prepared[i] = preparedIntent{summary: summary, priority: item.Priority, parents: parents}
	}
	existingIDs := make(map[int]int64)
	batchInputs := make([]db.CoworkIntentInput, 0, len(prepared))
	for i, item := range prepared {
		summary := item.summary
		if id := openBySummary[summary]; id > 0 {
			existingIDs[i] = id
		}
		batchInputs = append(batchInputs, db.CoworkIntentInput{Index: i, Summary: summary, Priority: item.priority, Parents: item.parents})
	}
	createdIDs, activity, addErr := t.Store.AddCoworkIntents(r.Context(), batchInputs, existingIDs, t.ID)
	if addErr != nil {
		writeErr(w, http.StatusInternalServerError, addErr.Error())
		return
	}
	s.publishCoworkActivity(t, activity)
	orderedIDs := make([]int64, len(req.Intents))
	for index, id := range createdIDs {
		if index < 0 || index >= len(orderedIDs) || id <= 0 {
			writeErr(w, http.StatusInternalServerError, "intent batch returned an invalid index or ID")
			return
		}
		orderedIDs[index] = id
	}
	for index, id := range orderedIDs {
		if id <= 0 {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("intent batch omitted item %d", index))
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "task_id": t.ID, "intent_ids": orderedIDs, "activity_updated": true})
}

// POST /api/tasks/{id}/cowork/intents/{intentID}/complete records the outcome
// of work Cowork actually performed and makes it visible in the native Worker
// session history. It never starts an ARTEx worker or target action.
func (s *Server) coworkCompleteIntent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	intentID, err := strconv.ParseInt(r.PathValue("intentID"), 10, 64)
	if err != nil || intentID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid intent id")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		State        string `json:"state"`
		Summary      string `json:"summary"`
		Evidence     string `json:"evidence"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.State != "done" && req.State != "blocked" {
		writeErr(w, http.StatusBadRequest, "state must be done or blocked")
		return
	}
	expected := fmt.Sprintf("CONFIRM complete_cowork_intent task=%s intent=%d state=%s", t.ID, intentID, req.State)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	if !validCoworkText(req.Summary) || len([]rune(req.Evidence)) > 128000 || (req.State == "done" && !validCoworkText(req.Evidence)) {
		writeErr(w, http.StatusBadRequest, "summary is required; done requires evidence; evidence must be at most 128000 characters")
		return
	}
	node, err := t.Store.GetNode(intentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindIntent {
		writeErr(w, http.StatusNotFound, "intent does not belong to this task")
		return
	}
	if node.State != "open" && node.State != "running" {
		writeErr(w, http.StatusConflict, "intent is not open or running")
		return
	}
	changed, activity, err := t.Store.CompleteCoworkIntent(
		r.Context(), intentID, node.State, req.State, strings.TrimSpace(req.Summary), strings.TrimSpace(req.Evidence),
		fmt.Sprintf("cowork-intent-%d", intentID),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !changed {
		writeErr(w, http.StatusConflict, "intent state changed concurrently")
		return
	}
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task_id": t.ID, "intent_id": strconv.FormatInt(intentID, 10), "state": req.State, "session_key": "intent:" + strconv.FormatInt(intentID, 10), "activity_updated": true})
}

// appendCoworkActivity persists a Cowork-originated event, then publishes the
// same row to ARTEx's live activity stream. The database remains authoritative;
// failed writes are never broadcast as if they were recorded.
func (s *Server) appendCoworkActivity(t *Task, activity db.Activity) (int64, error) {
	id, err := t.Store.AppendActivity(activity)
	if err != nil {
		return 0, err
	}
	activity.ID = id
	if activity.CreatedAt.IsZero() {
		activity.CreatedAt = time.Now()
	}
	s.publishCoworkActivity(t, activity)
	return id, nil
}

func (s *Server) publishCoworkActivity(t *Task, activity db.Activity) {
	if t == nil || s.engine == nil {
		return
	}
	s.engine.Broadcaster().Publish(t.ID, activity)
	s.engine.touch(t.ID)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
