package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func coworkTaskSetupConfirmation(taskID, operation string, objectID int64, values ...string) string {
	noun := strings.TrimPrefix(strings.TrimPrefix(operation, "update_"), "delete_")
	// Keep the public confirmation spelling stable while binding updates to the
	// exact normalized values that will be persisted.
	base := fmt.Sprintf("CONFIRM %s task=%s %s=%d", operation, taskID, noun, objectID)
	if strings.HasPrefix(operation, "update_") {
		var canonical strings.Builder
		for _, value := range values {
			fmt.Fprintf(&canonical, "%d:%s", len([]byte(value)), value)
		}
		digest := sha256.Sum256([]byte(canonical.String()))
		base += " payload_sha256=" + hex.EncodeToString(digest[:])
	}
	return base
}

// Cowork task setup has separate append-only routes. In particular, adding a
// goal here must not call the UI handler that revives the ARTEx-native planner.
func (s *Server) coworkAddGoal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Text         string `json:"text"`
		VulnClass    string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Confirmation != "CONFIRM add_goal task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	text := strings.TrimSpace(req.Text)
	vulnClass := strings.TrimSpace(req.VulnClass)
	if !validCoworkText(text) || len([]rune(vulnClass)) > maxCoworkGraphField || credentialLikeCoworkText(text) || credentialLikeCoworkText(vulnClass) {
		writeErr(w, http.StatusBadRequest, "goal fields must be present, at most 12000 characters, and contain no credential-like values")
		return
	}
	payload := map[string]any{"text": text}
	if vulnClass != "" {
		payload["vulnclass"] = vulnClass
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "add_goal", Summary: "Cowork가 목표를 Task에 추가했습니다", Detail: text}
	goalID, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, activity *db.Activity) (int64, error) {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, err
		}
		var id int64
		if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES ($1,'goal',$2,0,'open','human') RETURNING id`, t.Store.ID(), string(raw)).Scan(&id); err != nil {
			return 0, err
		}
		var rootID int64
		err = tx.QueryRow(`SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`, t.Store.ID()).Scan(&rootID)
		if err != nil && err != sql.ErrNoRows {
			return 0, err
		}
		if err == nil {
			if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES ($1,$2,$3,$4) ON CONFLICT (exploration_id,src_id,rel,dst_id) DO NOTHING`, t.Store.ID(), rootID, db.RelSpawns, id); err != nil {
				return 0, err
			}
		}
		activity.ToolUseID = fmt.Sprintf("cowork-goal-%d", id)
		return id, nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	node, err := t.Store.GetNode(goalID)
	if err != nil || node == nil {
		writeErr(w, http.StatusInternalServerError, "goal saved but readback failed")
		return
	}
	activity = savedActivity
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusCreated, map[string]any{"goal": goalDTO(node), "task_may_resume": false, "activity_updated": true})
}

func (s *Server) coworkAddConstraint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Kind         string `json:"kind"`
		Text         string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Confirmation != "CONFIRM add_constraint task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	text := strings.TrimSpace(req.Text)
	kind := normalizeConstraintKind(req.Kind)
	if kind == "" || !validCoworkText(text) || credentialLikeCoworkText(text) {
		writeErr(w, http.StatusBadRequest, "constraint requires allow/deny kind, non-empty text up to 12000 characters, and no credential-like values")
		return
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "add_constraint", Summary: "Cowork가 Task 제약을 추가했습니다", Detail: kind + ": " + text}
	id, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, activity *db.Activity) (int64, error) {
		var id int64
		err := tx.QueryRow(`INSERT INTO task_constraints(exploration_id,kind,text,origin) VALUES ($1,$2,$3,'human') RETURNING id`, t.Store.ID(), kind, text).Scan(&id)
		if err == nil {
			activity.ToolUseID = fmt.Sprintf("cowork-constraint-%d", id)
		}
		return id, err
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	activity = savedActivity
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusCreated, map[string]any{"constraint": ConstraintDTO{ID: strconv.FormatInt(id, 10), Kind: kind, Text: text, Origin: "human"}, "activity_updated": true})
}

func (s *Server) coworkAddTaskScope(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
		Kind         string `json:"kind"`
		Value        string `json:"value"`
		Reason       string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Confirmation != "CONFIRM add_scope task="+t.ID {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	value, reason := strings.TrimSpace(req.Value), strings.TrimSpace(req.Reason)
	if value == "" || len([]rune(value)) > maxCoworkGraphField || len([]rune(reason)) > maxCoworkGraphField || credentialLikeCoworkText(value) || credentialLikeCoworkText(reason) {
		writeErr(w, http.StatusBadRequest, "scope value is required; value/reason must be at most 12000 characters and contain no credential-like values")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	store := s.assetStore()
	if store == nil {
		writeErr(w, http.StatusServiceUnavailable, "asset store unavailable")
		return
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "add_task_scope", Summary: "Cowork가 Task 범위를 추가했습니다", Detail: fmt.Sprintf("%s: %s", req.Kind, req.Value)}
	var scope db.TaskScope
	_, savedActivity, _, err := store.MutateCoworkScope(t.Store.ID(), activity, func(scoped *db.AssetStore, activity *db.Activity) (int64, error) {
		var err error
		scope, err = scoped.AddAgentScope(taskID, strings.ToLower(strings.TrimSpace(req.Kind)), value, reason, "manual")
		if err != nil {
			return 0, err
		}
		activity.ToolUseID = fmt.Sprintf("cowork-scope-%d-%d", taskID, scope.ID)
		return scope.ID, nil
	})
	if err != nil {
		var inputErr *db.TaskScopeInputError
		if errors.As(err, &inputErr) {
			writeErr(w, http.StatusBadRequest, inputErr.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, "unable to persist task scope")
		}
		return
	}
	s.publishCoworkActivity(t, savedActivity)
	writeJSON(w, http.StatusCreated, map[string]any{"scope": scope, "task_may_resume": false, "activity_updated": true})
}

// Cowork setup edits are separate from the native UI routes: they require an
// operation-specific confirmation and never revive or enqueue ARTEx workers.
func (s *Server) coworkManageGoal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, http.StatusConflict, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	goalID, err := strconv.ParseInt(r.PathValue("goalID"), 10, 64)
	if err != nil || goalID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad goal id")
		return
	}
	var req struct {
		Operation    string `json:"operation"`
		Confirmation string `json:"confirmation"`
		Text         string `json:"text"`
		VulnClass    string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Operation != "update" && req.Operation != "delete" {
		writeErr(w, http.StatusBadRequest, "operation must be update or delete")
		return
	}
	node, err := t.Store.GetNode(goalID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, http.StatusNotFound, "goal not found in task")
		return
	}
	old := goalDTO(node).Text
	if req.Operation == "update" {
		text, vulnClass := strings.TrimSpace(req.Text), strings.TrimSpace(req.VulnClass)
		if !validCoworkText(text) || len([]rune(vulnClass)) > maxCoworkGraphField || credentialLikeCoworkText(text) || credentialLikeCoworkText(vulnClass) {
			writeErr(w, http.StatusBadRequest, "invalid goal fields")
			return
		}
		expected := coworkTaskSetupConfirmation(t.ID, "update_goal", goalID, text, vulnClass)
		if req.Confirmation != expected {
			writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
			return
		}
		activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "update_goal", ToolUseID: fmt.Sprintf("cowork-goal-update-%d", goalID), Summary: "Cowork가 Task 목표를 수정했습니다", Detail: fmt.Sprintf("goal_id=%d; previous=%s; current=%s", goalID, old, text)}
		_, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, _ *db.Activity) (int64, error) {
			payloadMap := map[string]any{"text": text}
			if vulnClass != "" {
				payloadMap["vulnclass"] = vulnClass
			}
			payload, err := json.Marshal(payloadMap)
			if err != nil {
				return 0, err
			}
			res, err := tx.Exec(`UPDATE exploration_nodes SET payload=$1 WHERE id=$2 AND exploration_id=$3 AND kind='goal'`, string(payload), goalID, t.Store.ID())
			if err != nil {
				return 0, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, err
			}
			if n == 0 {
				return 0, fmt.Errorf("goal not found in task")
			}
			return goalID, nil
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		updated, err := t.Store.GetNode(goalID)
		if err != nil || updated == nil {
			writeErr(w, http.StatusInternalServerError, "goal updated but readback failed")
			return
		}
		activity = savedActivity
		s.publishCoworkActivity(t, activity)
		writeJSON(w, http.StatusOK, map[string]any{"goal": goalDTO(updated), "task_may_resume": false, "activity_updated": true})
		return
	}
	expected := coworkTaskSetupConfirmation(t.ID, "delete_goal", goalID)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "delete_goal", ToolUseID: fmt.Sprintf("cowork-goal-delete-%d", goalID), Summary: "Cowork가 Task 목표를 삭제했습니다", Detail: fmt.Sprintf("goal_id=%d; previous=%s", goalID, old)}
	_, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, _ *db.Activity) (int64, error) {
		res, err := tx.Exec(`DELETE FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal'`, goalID, t.Store.ID())
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, fmt.Errorf("goal not found in task")
		}
		return goalID, nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	activity = savedActivity
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted_goal_id": goalID, "task_may_resume": false, "activity_updated": true})
}

func (s *Server) coworkManageConstraint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, http.StatusConflict, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	constraintID, err := strconv.ParseInt(r.PathValue("constraintID"), 10, 64)
	if err != nil || constraintID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad constraint id")
		return
	}
	var req struct {
		Operation    string `json:"operation"`
		Confirmation string `json:"confirmation"`
		Kind         string `json:"kind"`
		Text         string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Operation != "update" && req.Operation != "delete" {
		writeErr(w, http.StatusBadRequest, "operation must be update or delete")
		return
	}
	rows, err := t.Store.ListConstraints()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var current *db.Constraint
	for i := range rows {
		if rows[i].ID == constraintID {
			current = &rows[i]
			break
		}
	}
	if current == nil {
		writeErr(w, http.StatusNotFound, "constraint not found in task")
		return
	}
	old := current.Kind + ": " + current.Text
	if req.Operation == "update" {
		text, kind := strings.TrimSpace(req.Text), normalizeConstraintKind(req.Kind)
		if kind == "" || !validCoworkText(text) || credentialLikeCoworkText(text) {
			writeErr(w, http.StatusBadRequest, "invalid constraint fields")
			return
		}
		expected := coworkTaskSetupConfirmation(t.ID, "update_constraint", constraintID, kind, text)
		if req.Confirmation != expected {
			writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
			return
		}
		activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "update_constraint", ToolUseID: fmt.Sprintf("cowork-constraint-update-%d", constraintID), Summary: "Cowork가 Task 제약을 수정했습니다", Detail: fmt.Sprintf("constraint_id=%d; previous=%s; current=%s: %s", constraintID, old, kind, text)}
		_, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, _ *db.Activity) (int64, error) {
			res, err := tx.Exec(`UPDATE task_constraints SET kind=$1,text=$2,updated_at=now() WHERE id=$3 AND exploration_id=$4`, kind, text, constraintID, t.Store.ID())
			if err != nil {
				return 0, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return 0, err
			}
			if n == 0 {
				return 0, fmt.Errorf("constraint not found in task")
			}
			return constraintID, nil
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		activity = savedActivity
		s.publishCoworkActivity(t, activity)
		writeJSON(w, http.StatusOK, map[string]any{"constraint": ConstraintDTO{ID: strconv.FormatInt(constraintID, 10), Kind: kind, Text: text, Origin: "human"}, "activity_updated": true})
		return
	}
	expected := coworkTaskSetupConfirmation(t.ID, "delete_constraint", constraintID)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "delete_constraint", ToolUseID: fmt.Sprintf("cowork-constraint-delete-%d", constraintID), Summary: "Cowork가 Task 제약을 삭제했습니다", Detail: fmt.Sprintf("constraint_id=%d; previous=%s", constraintID, old)}
	_, savedActivity, _, err := t.Store.MutateCoworkSetup(activity, func(tx *sql.Tx, _ *db.Activity) (int64, error) {
		res, err := tx.Exec(`DELETE FROM task_constraints WHERE id=$1 AND exploration_id=$2`, constraintID, t.Store.ID())
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, fmt.Errorf("constraint not found in task")
		}
		return constraintID, nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	activity = savedActivity
	s.publishCoworkActivity(t, activity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted_constraint_id": constraintID, "activity_updated": true})
}

func (s *Server) coworkDeleteTaskScope(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, http.StatusConflict, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	scopeID, err := strconv.ParseInt(r.PathValue("scopeID"), 10, 64)
	if err != nil || scopeID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	var req struct {
		Confirmation string `json:"confirmation"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	expected := fmt.Sprintf("CONFIRM delete_scope task=%s scope=%d", t.ID, scopeID)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	store := s.assetStore()
	if store == nil {
		writeErr(w, http.StatusServiceUnavailable, "asset store unavailable")
		return
	}
	activity := db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "delete_task_scope", ToolUseID: fmt.Sprintf("cowork-scope-delete-%d-%d", taskID, scopeID), Summary: "Cowork가 Task 범위를 삭제했습니다", Detail: fmt.Sprintf("scope_id=%d", scopeID)}
	_, savedActivity, _, err := store.MutateCoworkScope(t.Store.ID(), activity, func(scoped *db.AssetStore, _ *db.Activity) (int64, error) {
		deleted, err := scoped.DeleteTaskScope(taskID, scopeID)
		if err != nil {
			return 0, err
		}
		if !deleted {
			return 0, sql.ErrNoRows
		}
		return scopeID, nil
	})
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusNotFound, "scope not found in task")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.publishCoworkActivity(t, savedActivity)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted_scope_id": scopeID, "activity_updated": true})
}
