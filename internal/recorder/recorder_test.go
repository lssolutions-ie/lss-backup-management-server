package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPruneOlderThan_NoOpWhenDaysZero(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.cast")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// File modified 100 days ago.
	past := time.Now().Add(-100 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	n, err := PruneOlderThan(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("days=0 should be no-op, deleted %d", n)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("old file was deleted despite days=0")
	}
}

func TestPruneOlderThan_DeletesOldKeepsRecent(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.cast")
	recent := filepath.Join(dir, "recent.cast")
	for _, p := range []string{old, recent} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	n, err := PruneOlderThan(dir, 30)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deletion, got %d", n)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old file should have been deleted")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("recent file should have been kept")
	}
}

func TestPruneOlderThan_IgnoresNonCastFiles(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "old.txt")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(other, past, past)

	n, err := PruneOlderThan(dir, 30)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("non-.cast file should be ignored, deleted %d", n)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("non-.cast file was unexpectedly removed")
	}
}

func TestPruneOlderThan_MissingDirIsNoOp(t *testing.T) {
	n, err := PruneOlderThan("/does/not/exist", 30)
	if err != nil {
		t.Fatalf("missing dir should not error, got %v", err)
	}
	if n != 0 {
		t.Fatalf("missing dir should yield 0 deletions, got %d", n)
	}
}

// New() creates a header line in proper asciinema v2 JSON shape.
func TestNew_WritesHeader(t *testing.T) {
	dir := t.TempDir()
	rec, path, err := New(dir, "test-session", "title", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(string(b), "\n", 2)[0]
	if !strings.Contains(first, `"version":2`) ||
		!strings.Contains(first, `"width":80`) ||
		!strings.Contains(first, `"height":24`) ||
		!strings.Contains(first, `"title":"title"`) {
		t.Fatalf("header missing expected fields: %s", first)
	}
}

func TestRecorder_OutputAndInputFrames(t *testing.T) {
	dir := t.TempDir()
	rec, path, err := New(dir, "frames", "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	rec.WriteOutput([]byte("hello"))
	rec.WriteInput([]byte("ls\n"))
	rec.Resize(120, 40)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"o","hello"`) {
		t.Errorf("missing output frame: %s", s)
	}
	if !strings.Contains(s, `"i","ls\n"`) {
		t.Errorf("missing input frame: %s", s)
	}
	if !strings.Contains(s, `"r","120 40"`) {
		t.Errorf("missing resize frame: %s", s)
	}
}

func TestRecorder_NilSafe(t *testing.T) {
	// All write methods on a nil *Recorder must be safe no-ops — terminal.go
	// relies on this to avoid branching when recording is disabled.
	var r *Recorder
	r.WriteOutput([]byte("x"))
	r.WriteInput([]byte("y"))
	r.Resize(1, 1)
	if err := r.Close(); err != nil {
		t.Fatalf("Close on nil should be nil error, got %v", err)
	}
}
