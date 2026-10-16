package server

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestActivityStreamReconnectUsesLastEventIDAndDeduplicatesReplayOverlap(t *testing.T) {
	s, finding, _ := trafficEvidenceServer(t)
	stored, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil || stored == nil || stored.TaskID == nil {
		t.Fatalf("load task for SSE fixture: finding=%+v err=%v", stored, err)
	}
	task, ok := s.m.Task(strconv.FormatInt(*stored.TaskID, 10))
	if !ok || task.Store == nil {
		t.Fatal("task store unavailable")
	}
	lastPersisted := db.Activity{
		Worker: "cowork", Kind: "tool_result", Tool: "sse_fixture",
		ToolUseID: "cowork-sse-reconnect-fixture", Summary: "persisted before reconnect",
	}
	lastPersisted.ID, err = s.appendCoworkActivity(task, lastPersisted)
	if err != nil {
		t.Fatalf("persist SSE reconnect fixture: %v", err)
	}

	server := httptest.NewServer(s.Handler())
	defer server.Close()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("%s/api/exploration/activity/stream?task=%s&since=0", server.URL, task.ID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// A browser reconnect cursor must win over a stale history-page query cursor.
	req.Header.Set("Last-Event-ID", strconv.FormatInt(lastPersisted.ID, 10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("SSE response status=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// The broadcaster may still hold the last row that the DB replay already
	// covered. Its ID must be skipped, while a genuinely newer live row is sent.
	s.engine.Broadcaster().Publish(task.ID, lastPersisted)
	newID := lastPersisted.ID + 1000
	s.engine.Broadcaster().Publish(task.ID, db.Activity{
		ID: newID, Worker: "cowork", Kind: "tool_result", Tool: "sse_fixture",
		Summary: "new live event after reconnect",
	})

	scanner := bufio.NewScanner(resp.Body)
	var ids []string
	deadline := time.After(2 * time.Second)
	for len(ids) == 0 {
		lineCh := make(chan string, 1)
		go func() {
			if scanner.Scan() {
				lineCh <- scanner.Text()
				return
			}
			lineCh <- ""
		}()
		select {
		case line := <-lineCh:
			if strings.HasPrefix(line, "id: ") {
				ids = append(ids, strings.TrimPrefix(line, "id: "))
			}
		case <-deadline:
			t.Fatal("timed out waiting for live SSE event")
		}
	}
	if len(ids) != 1 || ids[0] != strconv.FormatInt(newID, 10) {
		t.Fatalf("reconnect should skip replayed ID %d and emit only new ID %d; got %v", lastPersisted.ID, newID, ids)
	}
}
