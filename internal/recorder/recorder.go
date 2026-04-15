// Package recorder writes terminal sessions in asciinema v2 format (.cast).
//
// Format: first line is a JSON header. Subsequent lines are 3-element JSON
// arrays: [time_delta_seconds, stream, data]. Stream is "o" for terminal output,
// "i" for user input, "r" for resize (data = "cols height").
package recorder

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

type Recorder struct {
	mu    sync.Mutex
	w     io.WriteCloser
	start time.Time
}

// New creates a .cast file under dir and writes the header. Returns the full path on disk.
// The caller is expected to Close() the recorder at end of session.
func New(dir, sessionID, title string, cols, rows int) (*Recorder, string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, "", fmt.Errorf("mkdir sessions: %w", err)
	}
	path := filepath.Join(dir, sessionID+".cast")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, "", fmt.Errorf("open cast: %w", err)
	}
	now := time.Now()
	hdr := header{
		Version:   2,
		Width:     cols,
		Height:    rows,
		Timestamp: now.Unix(),
		Title:     title,
		Env:       map[string]string{"TERM": "xterm-256color", "SHELL": "/bin/bash"},
	}
	b, _ := json.Marshal(hdr)
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("write header: %w", err)
	}
	return &Recorder{w: f, start: now}, path, nil
}

// WriteOutput records bytes received from the SSH side (server → user screen).
func (r *Recorder) WriteOutput(b []byte) { r.writeFrame("o", b) }

// WriteInput records bytes sent by the user (browser → SSH stdin).
func (r *Recorder) WriteInput(b []byte) { r.writeFrame("i", b) }

// Resize records a terminal geometry change.
func (r *Recorder) Resize(cols, rows int) { r.writeFrame("r", []byte(fmt.Sprintf("%d %d", cols, rows))) }

func (r *Recorder) writeFrame(kind string, data []byte) {
	if r == nil || len(data) == 0 {
		return
	}
	delta := time.Since(r.start).Seconds()
	frame := []interface{}{delta, kind, string(data)}
	b, err := json.Marshal(frame)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.w.Write(append(b, '\n'))
}

// Close finalises the file on disk.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.w.Close()
}

// PruneOlderThan deletes .cast files under dir that were modified more than `days` ago.
// Returns (deleted_count, error). A days value of 0 means "keep forever" — no-op.
func PruneOlderThan(dir string, days uint32) (int, error) {
	if days == 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var n int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".cast" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				n++
			}
		}
	}
	return n, nil
}
