package server

import (
	"fmt"
	"strconv"
	"testing"
)

func TestCoworkUpdateFindingReportIsTaskScopedAndConfirmed(t *testing.T) {
	s, finding, request := trafficEvidenceServer(t)
	tasks := s.m.List()
	if len(tasks) != 1 {
		t.Fatalf("expected one fixture task, got %d", len(tasks))
	}
	taskID := tasks[0].ID
	path := fmt.Sprintf("/api/tasks/%s/cowork/findings/%d/report", taskID, finding.NodeID)
	body := `{"report":"## Verified report\n\nEvidence-backed details.","confirmation":"CONFIRM update_finding_report task=` + fmt.Sprint(taskID) + `"}`
	if got := request("PUT", path, `{"report":"# no confirmation"}`); got.Code != 400 {
		t.Fatalf("missing confirmation status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request("PUT", path, body); got.Code != 200 {
		t.Fatalf("update status=%d body=%s", got.Code, got.Body.String())
	}
	stored, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || stored == nil || stored.Report != "## Verified report\n\nEvidence-backed details." {
		t.Fatalf("report not stored: finding=%+v err=%v", stored, err)
	}
	other, err := s.m.CreateTask("other task", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := strconv.ParseInt(other.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.m.pg.DeleteTaskCascade(otherID, true, true); err != nil {
			t.Errorf("clean second test task: %v", err)
		}
	})
	crossTaskPath := fmt.Sprintf("/api/tasks/%s/cowork/findings/%d/report", other.ID, finding.NodeID)
	crossBody := `{"report":"# cross task","confirmation":"CONFIRM update_finding_report task=` + other.ID + `"}`
	if got := request("PUT", crossTaskPath, crossBody); got.Code != 404 {
		t.Fatalf("cross-task write status=%d body=%s", got.Code, got.Body.String())
	}
}
