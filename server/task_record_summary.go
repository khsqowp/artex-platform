package server

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// latestTaskEvidence returns a display-only summary for the newest regular
// Markdown evidence file belonging to a task. It never follows symlinks and
// reads only a small prefix to find a human-readable title.
func (s *Server) latestTaskEvidence(taskID string) (summary, relPath string, modified int64) {
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return "", "", 0
	}
	dir := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(id, 10), "evidence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", 0
	}
	var newest os.DirEntry
	var newestStamp int64
	var newestTime int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		stamp := info.ModTime().UnixNano()
		if newest == nil || stamp > newestStamp || (stamp == newestStamp && entry.Name() > newest.Name()) {
			newest, newestStamp, newestTime = entry, stamp, info.ModTime().Unix()
		}
	}
	if newest == nil {
		return "", "", 0
	}

	path := filepath.Join(dir, newest.Name())
	file, err := os.Open(path)
	if err != nil {
		return "", "", 0
	}
	defer file.Close()
	buf := make([]byte, 4096)
	n, _ := file.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimLeft(line, "#"))
		}
		if line != "" {
			summary = line
			break
		}
	}
	if summary == "" {
		summary = newest.Name()
	}
	return summary, filepath.ToSlash(filepath.Join("tasks", strconv.FormatInt(id, 10), "evidence", newest.Name())), newestTime
}
