package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestCoworkInterceptRuleRequiresPayloadConfirmationAndRecordsActivity(t *testing.T) {
	s, finding, request := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load fixture finding task: finding=%+v err=%v", stored, err)
	}
	taskID := *stored.TaskID
	taskIDString := strconv.FormatInt(taskID, 10)
	assertRule := func(pattern string, enabled, present bool) {
		t.Helper()
		listing := request(http.MethodGet, fmt.Sprintf("/api/tasks/%s/intercept-rules", taskIDString), "")
		if listing.Code != http.StatusOK {
			t.Fatalf("native rule readback: %d %s", listing.Code, listing.Body)
		}
		var payload struct {
			Rules []struct {
				Pattern string `json:"pattern"`
				Enabled bool   `json:"enabled"`
				Note    string `json:"note"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(listing.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode native rule readback: %v", err)
		}
		for _, rule := range payload.Rules {
			if rule.Pattern == pattern {
				if !present || rule.Enabled != enabled {
					t.Fatalf("unexpected native rule state for %q: %+v", pattern, rule)
				}
				return
			}
		}
		if present {
			t.Fatalf("native rule %q missing from readback: %s", pattern, listing.Body)
		}
	}
	confirmation := coworkInterceptRuleConfirmation(taskID, "create", 0, true, "block", "exact_domain", "example.test", "fixture")
	body := fmt.Sprintf(`{"operation":"create","enabled":true,"action":"block","kind":"exact_domain","pattern":"example.test","note":" fixture  ","confirmation":%q}`, confirmation)
	wrong := strings.Replace(body, "example.test", "other.test", 1)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), wrong); got.Code != http.StatusBadRequest {
		t.Fatalf("changed payload must fail confirmation: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), `{"operation":"create","enabled":true,"action":"block","kind":"exact_domain","pattern":"no-confirm.test"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("create without confirmation must reject: %d %s", got.Code, got.Body)
	}
	created := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), body)
	if created.Code != http.StatusOK {
		t.Fatalf("confirmed rule create: %d %s", created.Code, created.Body)
	}
	var response struct {
		Result struct {
			ID      int64  `json:"id"`
			Pattern string `json:"pattern"`
			Note    string `json:"note"`
		} `json:"result"`
		ActivityUpdated   bool   `json:"activity_updated"`
		ActivityToolUseID string `json:"activity_tool_use_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Result.ID <= 0 || response.Result.Pattern != "example.test" || response.Result.Note != "fixture" || !response.ActivityUpdated || response.ActivityToolUseID == "" {
		t.Fatalf("created rule/activity response mismatch: response=%s err=%v", created.Body, err)
	}
	activityIDs := []string{response.ActivityToolUseID}
	assertRule("example.test", true, true)
	otherTask, err := s.m.CreateTask("Cowork intercept cross-task fixture", "isolated test only", nil, 0, 0)
	if err != nil {
		t.Fatalf("create second fixture task: %v", err)
	}
	otherTaskID, err := strconv.ParseInt(otherTask.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.m.pg.DeleteTaskCascade(otherTaskID, true, true); err != nil {
			t.Errorf("clean second fixture task: %v", err)
		}
	})
	otherTaskIDString := strconv.FormatInt(otherTaskID, 10)
	otherTaskUpdateConfirmation := coworkInterceptRuleConfirmation(otherTaskID, "update", response.Result.ID, false, "allow", "exact_domain", "cross-task.test", "cross-task")
	crossTaskUpdate := fmt.Sprintf(`{"operation":"update","rule_id":%d,"enabled":false,"action":"allow","kind":"exact_domain","pattern":"cross-task.test","note":"cross-task","confirmation":%q}`, response.Result.ID, otherTaskUpdateConfirmation)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", otherTaskIDString), crossTaskUpdate); got.Code == http.StatusOK {
		t.Fatalf("cross-task rule update must reject: %d %s", got.Code, got.Body)
	}
	otherTaskDeleteConfirmation := coworkInterceptRuleConfirmation(otherTaskID, "delete", response.Result.ID, false, "", "", "", "")
	crossTaskDelete := fmt.Sprintf(`{"operation":"delete","rule_id":%d,"confirmation":%q}`, response.Result.ID, otherTaskDeleteConfirmation)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", otherTaskIDString), crossTaskDelete); got.Code == http.StatusOK {
		t.Fatalf("cross-task rule delete must reject: %d %s", got.Code, got.Body)
	}
	otherTaskToggleConfirmation := coworkInterceptRuleConfirmation(otherTaskID, "toggle", response.Result.ID, false, "", "", "", "")
	crossTaskToggle := fmt.Sprintf(`{"operation":"toggle","rule_id":%d,"enabled":false,"confirmation":%q}`, response.Result.ID, otherTaskToggleConfirmation)
	if got := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", otherTaskIDString), crossTaskToggle); got.Code == http.StatusOK {
		t.Fatalf("cross-task rule toggle must reject: %d %s", got.Code, got.Body)
	}
	otherTaskListing := request(http.MethodGet, fmt.Sprintf("/api/tasks/%s/intercept-rules", otherTaskIDString), "")
	if otherTaskListing.Code != http.StatusOK || strings.Contains(otherTaskListing.Body.String(), "example.test") {
		t.Fatalf("cross-task request changed the other task's rules: %d %s", otherTaskListing.Code, otherTaskListing.Body)
	}
	assertRule("example.test", true, true)
	updateConfirmation := coworkInterceptRuleConfirmation(taskID, "update", response.Result.ID, false, "allow", "exact_domain", "updated.test", "updated")
	updatePayload := func(enabled bool, action, kind, pattern, note, confirmation string) string {
		payload, err := json.Marshal(map[string]any{
			"operation": "update", "rule_id": response.Result.ID, "enabled": enabled,
			"action": action, "kind": kind, "pattern": pattern, "note": note,
			"confirmation": confirmation,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	updateBody := updatePayload(false, "allow", "exact_domain", "updated.test", "updated", updateConfirmation)
	if rejected := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), updatePayload(false, "allow", "exact_domain", "updated.test", "updated", "")); rejected.Code != http.StatusBadRequest {
		t.Fatalf("update without confirmation must reject: %d %s", rejected.Code, rejected.Body)
	}
	for name, changed := range map[string]string{
		"enabled": updatePayload(true, "allow", "exact_domain", "updated.test", "updated", updateConfirmation),
		"action":  updatePayload(false, "block", "exact_domain", "updated.test", "updated", updateConfirmation),
		"kind":    updatePayload(false, "allow", "exact_url", "updated.test", "updated", updateConfirmation),
		"pattern": updatePayload(false, "allow", "exact_domain", "tampered.test", "updated", updateConfirmation),
		"note":    updatePayload(false, "allow", "exact_domain", "updated.test", "tampered note", updateConfirmation),
	} {
		if rejected := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), changed); rejected.Code != http.StatusBadRequest {
			t.Fatalf("changed %s update payload must fail its original confirmation: %d %s", name, rejected.Code, rejected.Body)
		}
	}
	updated := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), updateBody)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "updated.test") {
		t.Fatalf("confirmed rule update: %d %s", updated.Code, updated.Body)
	}
	var updateResult struct {
		ActivityUpdated   bool   `json:"activity_updated"`
		ActivityToolUseID string `json:"activity_tool_use_id"`
	}
	if err := json.Unmarshal(updated.Body.Bytes(), &updateResult); err != nil || !updateResult.ActivityUpdated || updateResult.ActivityToolUseID == "" {
		t.Fatalf("update activity result mismatch: %s err=%v", updated.Body, err)
	}
	activityIDs = append(activityIDs, updateResult.ActivityToolUseID)
	assertRule("updated.test", false, true)
	toggleConfirmation := coworkInterceptRuleConfirmation(taskID, "toggle", response.Result.ID, true, "", "", "", "")
	toggleBody := fmt.Sprintf(`{"operation":"toggle","rule_id":%d,"enabled":true,"confirmation":%q}`, response.Result.ID, toggleConfirmation)
	if rejected := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), fmt.Sprintf(`{"operation":"toggle","rule_id":%d,"enabled":true}`, response.Result.ID)); rejected.Code != http.StatusBadRequest {
		t.Fatalf("toggle without confirmation must reject: %d %s", rejected.Code, rejected.Body)
	}
	toggled := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), toggleBody)
	if toggled.Code != http.StatusOK || !strings.Contains(toggled.Body.String(), `"enabled":true`) {
		t.Fatalf("confirmed rule toggle: %d %s", toggled.Code, toggled.Body)
	}
	var toggleResult struct {
		ActivityUpdated   bool   `json:"activity_updated"`
		ActivityToolUseID string `json:"activity_tool_use_id"`
	}
	if err := json.Unmarshal(toggled.Body.Bytes(), &toggleResult); err != nil || !toggleResult.ActivityUpdated || toggleResult.ActivityToolUseID == "" {
		t.Fatalf("toggle activity result mismatch: %s err=%v", toggled.Body, err)
	}
	activityIDs = append(activityIDs, toggleResult.ActivityToolUseID)
	assertRule("updated.test", true, true)
	deleteConfirmation := coworkInterceptRuleConfirmation(taskID, "delete", response.Result.ID, false, "", "", "", "")
	deleteBody := fmt.Sprintf(`{"operation":"delete","rule_id":%d,"confirmation":%q}`, response.Result.ID, deleteConfirmation)
	if rejected := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), fmt.Sprintf(`{"operation":"delete","rule_id":%d}`, response.Result.ID)); rejected.Code != http.StatusBadRequest {
		t.Fatalf("delete without operation confirmation must reject: %d %s", rejected.Code, rejected.Body)
	}
	deleted := request(http.MethodPost, fmt.Sprintf("/api/tasks/%s/cowork/intercept-rules", taskIDString), deleteBody)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"deleted":true`) {
		t.Fatalf("confirmed rule delete: %d %s", deleted.Code, deleted.Body)
	}
	var deleteResult struct {
		ActivityUpdated   bool   `json:"activity_updated"`
		ActivityToolUseID string `json:"activity_tool_use_id"`
	}
	if err := json.Unmarshal(deleted.Body.Bytes(), &deleteResult); err != nil || !deleteResult.ActivityUpdated || deleteResult.ActivityToolUseID == "" {
		t.Fatalf("delete activity result mismatch: %s err=%v", deleted.Body, err)
	}
	activityIDs = append(activityIDs, deleteResult.ActivityToolUseID)
	assertRule("updated.test", false, false)
	history := request(http.MethodGet, fmt.Sprintf("/api/exploration/activity/history?task=%s&session=cowork&limit=20", taskIDString), "")
	var activityHistory struct {
		Items []struct {
			Tool      string `json:"tool"`
			ToolUseID string `json:"tool_use_id"`
		} `json:"items"`
	}
	if history.Code != http.StatusOK || json.Unmarshal(history.Body.Bytes(), &activityHistory) != nil || len(activityHistory.Items) != len(activityIDs) {
		t.Fatalf("Cowork mutation history count mismatch: %d %s", history.Code, history.Body)
	}
	seen := make(map[string]bool, len(activityHistory.Items))
	for _, item := range activityHistory.Items {
		if item.Tool != "manage_task_intercept_rule" {
			t.Fatalf("unexpected Cowork activity tool in intercept history: %+v", item)
		}
		seen[item.ToolUseID] = true
	}
	for _, id := range activityIDs {
		if !seen[id] {
			t.Fatalf("Cowork mutation %q missing from task activity history: %s", id, history.Body)
		}
	}
}
