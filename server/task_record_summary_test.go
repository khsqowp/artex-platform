package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLatestTaskEvidence(t *testing.T) {
	root := t.TempDir()
	server := &Server{m: &Manager{dir: root}}
	dir := filepath.Join(root, "tasks", "3", "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(dir, "older.md")
	newer := filepath.Join(dir, "newer.md")
	if err := os.WriteFile(older, []byte("# Older record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("# Latest visible record\n\nBody"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	newTime := time.Now()
	if err := os.Chtimes(older, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	summary, relPath, modified := server.latestTaskEvidence("3")
	if summary != "Latest visible record" {
		t.Fatalf("summary=%q, want newest Markdown heading", summary)
	}
	if relPath != "tasks/3/evidence/newer.md" {
		t.Fatalf("path=%q, want newest task evidence path", relPath)
	}
	if modified != newTime.Unix() {
		t.Fatalf("modified=%d, want %d", modified, newTime.Unix())
	}
	if summary, path, _ := server.latestTaskEvidence("../3"); summary != "" || path != "" {
		t.Fatalf("invalid task ID returned evidence: %q %q", summary, path)
	}
}
