package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// POST /api/tasks/{id}/cowork/findings/{findingID}/traffic binds only captures
// owned by this Cowork task to a Finding that belongs to the same task.
func (s *Server) coworkBindFindingTraffic(w http.ResponseWriter, r *http.Request) {
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
	finding, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read finding")
		return
	}
	if finding == nil || finding.TaskID == nil || strconv.FormatInt(*finding.TaskID, 10) != t.ID {
		writeErr(w, http.StatusNotFound, "finding does not belong to this task")
		return
	}
	var body struct {
		Confirmation string          `json:"confirmation"`
		Target       string          `json:"target"`
		Refs         []db.TrafficRef `json:"traffic_refs"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wantConfirmation := "CONFIRM bind_cowork_traffic task=" + t.ID + " finding=" + strconv.FormatInt(findingID, 10)
	if body.Confirmation != wantConfirmation {
		writeErr(w, http.StatusBadRequest, "operation-specific Cowork traffic binding confirmation required")
		return
	}
	_, status, message := s.validateCoworkTarget(t, body.Target)
	if status != 0 {
		writeErr(w, status, message)
		return
	}
	if len(body.Refs) == 0 || len(body.Refs) > 20 {
		writeErr(w, http.StatusBadRequest, "traffic_refs must contain between 1 and 20 captures")
		return
	}
	refs, err := db.NormalizeTrafficRefs(body.Refs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	capturePattern := regexp.MustCompile(`^cowork-t` + regexp.QuoteMeta(t.ID) + `-[a-f0-9]{32}-[1-9][0-9]*$`)
	for _, ref := range refs {
		if !capturePattern.MatchString(ref.TrafficID) {
			writeErr(w, http.StatusForbidden, "every traffic reference must be captured by this task's Cowork run")
			return
		}
		if len([]rune(ref.Note)) > 500 {
			writeErr(w, http.StatusBadRequest, "traffic reference note must be at most 500 characters")
			return
		}
	}
	out, err := s.evidenceStore().Bind(r.Context(), findingID, refs)
	if err != nil {
		evidenceError(w, err)
		return
	}
	bound := make(map[string]db.FindingTrafficBinding, len(out.Bindings))
	for _, binding := range out.Bindings {
		bound[binding.Snapshot.SourceTrafficID] = binding
	}
	for _, ref := range refs {
		binding, exists := bound[ref.TrafficID]
		if !exists {
			writeErr(w, http.StatusInternalServerError, "traffic binding read-back did not include every requested capture")
			return
		}
		if binding.Role != ref.Role || binding.Note != ref.Note {
			writeErr(w, http.StatusConflict, "capture is already bound to this Finding with different role or note")
			return
		}
	}
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		ids = append(ids, ref.TrafficID)
	}
	sort.Strings(ids)
	key := sha256.Sum256([]byte(t.ID + ":" + strconv.FormatInt(findingID, 10) + ":" + strings.Join(ids, ":")))
	toolUseID := "cowork-bind-traffic-" + hex.EncodeToString(key[:16])
	detail := fmt.Sprintf("finding_id=%d capture_count=%d", findingID, len(refs))
	activityID, activityCreated, activityErr := t.Store.AppendCoworkTrafficActivity(db.Activity{
		Worker: "cowork", Kind: "tool_result", Tool: "bind_cowork_traffic",
		ToolUseID: toolUseID,
		Summary:   "Cowork가 Task 캡처 트래픽을 Finding 증거로 연결했습니다",
		Detail:    detail,
	})
	if activityErr == nil && activityCreated {
		s.publishCoworkActivity(t, db.Activity{
			ID: activityID, Worker: "cowork", Kind: "tool_result", Tool: "bind_cowork_traffic",
			ToolUseID: toolUseID,
			Summary:   "Cowork가 Task 캡처 트래픽을 Finding 증거로 연결했습니다",
			Detail:    detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "verified": true, "task_id": t.ID, "finding_id": findingID,
		"traffic": out, "activity_id": strconv.FormatInt(activityID, 10),
		"tool_use_id":      toolUseID,
		"activity_updated": activityErr == nil, "activity_created": activityCreated,
		"activity_error": errorString(activityErr),
	})
}
