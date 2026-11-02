package lidmon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClosed(t *testing.T) {
	dir := t.TempDir()
	m := &Monitor{glob: filepath.Join(dir, "*", "state")}

	if _, ok := m.closed(); ok {
		t.Fatal("expected ok=false with no lid")
	}

	os.MkdirAll(filepath.Join(dir, "LID"), 0o755)
	state := filepath.Join(dir, "LID", "state")
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{"state:      open\n", false},
		{"state:      closed\n", true},
	} {
		os.WriteFile(state, []byte(tc.content), 0o644)
		got, ok := m.closed()
		if !ok || got != tc.want {
			t.Errorf("%q: got closed=%v ok=%v, want %v", tc.content, got, ok, tc.want)
		}
	}
}
