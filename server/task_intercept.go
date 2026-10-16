package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 任务级资产拦截/允许规则的 CRUD。规则按 task_id 归属，仅对该任务生效：
// action=block 拦截(禁止测试)，action=allow 允许(白名单)。执行判定见 db.EvaluateAssetGate。

type taskInterceptRuleReq struct {
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"` // block | allow
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Note    string `json:"note"`
}

// coworkManageTaskInterceptRule is the confirmation-gated mutation path used
// by Cowork. The standard task UI routes remain unchanged.
func (s *Server) coworkManageTaskInterceptRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t == nil || t.Store == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad task id")
		return
	}
	var req struct {
		Operation    string `json:"operation"`
		RuleID       int64  `json:"rule_id"`
		Confirmation string `json:"confirmation"`
		Enabled      bool   `json:"enabled"`
		Action       string `json:"action"`
		Kind         string `json:"kind"`
		Pattern      string `json:"pattern"`
		Note         string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Operation != "create" && req.Operation != "update" && req.Operation != "delete" && req.Operation != "toggle" {
		writeErr(w, http.StatusBadRequest, "operation must be create, update, delete, or toggle")
		return
	}
	if req.Operation != "create" && req.RuleID <= 0 {
		writeErr(w, http.StatusBadRequest, "rule_id must be positive")
		return
	}
	expected := coworkInterceptRuleConfirmation(taskID, req.Operation, req.RuleID, req.Enabled, req.Action, req.Kind, req.Pattern, req.Note)
	if req.Confirmation != expected {
		writeErr(w, http.StatusBadRequest, "operation-specific confirmation required")
		return
	}
	assets := s.assetStore()
	if assets == nil {
		writeErr(w, http.StatusServiceUnavailable, "asset store unavailable")
		return
	}
	var result any
	var detail string
	activityRuleID := req.RuleID
	switch req.Operation {
	case "create", "update":
		if req.Action != "block" && req.Action != "allow" {
			writeErr(w, http.StatusBadRequest, "action must be block or allow")
			return
		}
		ruleReq := taskInterceptRuleReq{Enabled: req.Enabled, Action: req.Action, Kind: req.Kind, Pattern: req.Pattern, Note: req.Note}
		if err := validateTaskInterceptRuleReq(&ruleReq); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		ruleReq.Note = strings.TrimSpace(ruleReq.Note)
		if len([]rune(ruleReq.Pattern)) > 2048 || len([]rune(ruleReq.Note)) > 500 {
			writeErr(w, http.StatusBadRequest, "pattern must be at most 2048 characters and note at most 500 characters")
			return
		}
		// Confirmations bind to normalized values, so normalize before comparing.
		expected = coworkInterceptRuleConfirmation(taskID, req.Operation, req.RuleID, ruleReq.Enabled, ruleReq.Action, ruleReq.Kind, ruleReq.Pattern, ruleReq.Note)
		if req.Confirmation != expected {
			writeErr(w, http.StatusBadRequest, "operation-specific confirmation required for normalized rule payload")
			return
		}
		var rule db.AssetInterceptRule
		if req.Operation == "create" {
			rule, err = assets.CreateTaskInterceptRule(taskID, ruleReq.Action, ruleReq.Kind, ruleReq.Pattern, ruleReq.Note, ruleReq.Enabled)
		} else {
			rule, err = assets.UpdateTaskInterceptRule(taskID, req.RuleID, ruleReq.Action, ruleReq.Kind, ruleReq.Pattern, ruleReq.Note, ruleReq.Enabled)
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		result = rule
		activityRuleID = rule.ID
		detail = fmt.Sprintf("operation=%s rule_id=%d action=%s kind=%s enabled=%t", req.Operation, rule.ID, rule.Action, rule.Kind, rule.Enabled)
	case "delete":
		deleted, deleteErr := assets.DeleteTaskInterceptRule(taskID, req.RuleID)
		if deleteErr != nil {
			writeErr(w, http.StatusInternalServerError, deleteErr.Error())
			return
		}
		if !deleted {
			writeErr(w, http.StatusNotFound, "task intercept rule not found")
			return
		}
		result = map[string]any{"deleted": true, "rule_id": req.RuleID}
		detail = fmt.Sprintf("operation=delete rule_id=%d", req.RuleID)
	case "toggle":
		if err := assets.ToggleTaskInterceptRule(taskID, req.RuleID, req.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		rules, listErr := assets.ListTaskInterceptRules(taskID)
		if listErr != nil {
			writeErr(w, http.StatusInternalServerError, "rule changed but readback failed")
			return
		}
		found := false
		for _, rule := range rules {
			if rule.ID == req.RuleID && rule.Enabled == req.Enabled {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusInternalServerError, "rule changed but readback did not match")
			return
		}
		result = map[string]any{"ok": true, "rule_id": req.RuleID, "enabled": req.Enabled}
		detail = fmt.Sprintf("operation=toggle rule_id=%d enabled=%t", req.RuleID, req.Enabled)
	}
	activityID := fmt.Sprintf("cowork-intercept-rule-%d-%s-%d-%d", taskID, req.Operation, activityRuleID, time.Now().UTC().UnixNano())
	_, activityErr := s.appendCoworkActivity(t, db.Activity{Worker: "cowork", Kind: "tool_result", Tool: "manage_task_intercept_rule", ToolUseID: activityID, Summary: "Cowork가 Task 인터셉트 규칙을 변경했습니다", Detail: detail})
	writeJSON(w, http.StatusOK, map[string]any{
		"result": result, "activity_updated": activityErr == nil,
		"activity_error": errorString(activityErr), "activity_tool_use_id": activityID,
	})
}

func coworkInterceptRuleConfirmation(taskID int64, operation string, ruleID int64, enabled bool, action, kind, pattern, note string) string {
	base := fmt.Sprintf("CONFIRM %s_intercept_rule task=%d", operation, taskID)
	if operation != "create" {
		base += fmt.Sprintf(" rule=%d", ruleID)
	}
	switch operation {
	case "toggle":
		return fmt.Sprintf("%s enabled=%t", base, enabled)
	case "create", "update":
		values := []string{strconv.FormatBool(enabled), action, kind, strings.TrimSpace(pattern), strings.TrimSpace(note)}
		var canonical strings.Builder
		for _, value := range values {
			fmt.Fprintf(&canonical, "%d:%s", len([]byte(value)), value)
		}
		digest := sha256.Sum256([]byte(canonical.String()))
		return fmt.Sprintf("%s payload_sha256=%s", base, hex.EncodeToString(digest[:]))
	default:
		return base
	}
}

// validateTaskInterceptRuleReq 归一并校验；复用全局规则的 kind/pattern 校验器。
func validateTaskInterceptRuleReq(req *taskInterceptRuleReq) error {
	if req.Action == "" {
		req.Action = "block"
	}
	if req.Action != "block" && req.Action != "allow" {
		return fmt.Errorf("action 必须是 block 或 allow")
	}
	v := assetInterceptRuleReq{Enabled: req.Enabled, Kind: req.Kind, Pattern: req.Pattern, Note: req.Note}
	if err := validateAssetInterceptRuleReq(&v); err != nil {
		return err
	}
	req.Pattern = v.Pattern // 已 trim
	return nil
}

// buildTaskInterceptRules 校验创建任务时录入的任务级规则并转换为 db 输入形态。
func buildTaskInterceptRules(reqs []taskInterceptRuleReq) ([]db.TaskInterceptRuleInput, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	out := make([]db.TaskInterceptRuleInput, 0, len(reqs))
	for i := range reqs {
		rq := reqs[i]
		if err := validateTaskInterceptRuleReq(&rq); err != nil {
			return nil, err
		}
		out = append(out, db.TaskInterceptRuleInput{
			Enabled: rq.Enabled,
			Action:  rq.Action,
			Kind:    rq.Kind,
			Pattern: rq.Pattern,
			Note:    rq.Note,
		})
	}
	return out, nil
}

func (s *Server) taskInterceptListRules(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	rules, err := pg.Assets().ListTaskInterceptRules(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rules == nil {
		rules = []db.AssetInterceptRule{}
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) taskInterceptCreateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	var req taskInterceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateTaskInterceptRuleReq(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.Assets().CreateTaskInterceptRule(taskID, req.Action, req.Kind, req.Pattern, req.Note, req.Enabled)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *Server) taskInterceptUpdateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	ruleID, ok := pathInt(r, "rid")
	if !ok || ruleID <= 0 {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req taskInterceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateTaskInterceptRuleReq(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.Assets().UpdateTaskInterceptRule(taskID, ruleID, req.Action, req.Kind, req.Pattern, req.Note, req.Enabled)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *Server) taskInterceptDeleteRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	ruleID, ok := pathInt(r, "rid")
	if !ok || ruleID <= 0 {
		writeErr(w, 400, "bad rule id")
		return
	}
	deleted, err := pg.Assets().DeleteTaskInterceptRule(taskID, ruleID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted})
}

func (s *Server) taskInterceptToggleRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	ruleID, ok := pathInt(r, "rid")
	if !ok || ruleID <= 0 {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := pg.Assets().ToggleTaskInterceptRule(taskID, ruleID, req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": req.Enabled})
}
