// Package lidmon polls the ACPI lid switch so the virtual key can be
// disabled while the laptop lid (and its fingerprint reader) is closed.
package lidmon

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Monitor polls /proc/acpi/button/lid/*/state.
type Monitor struct {
	Interval time.Duration // poll interval (default 2s)
	OnChange func(closed bool)

	// glob is overridable for tests.
	glob string
}

// Available reports whether this machine exposes an ACPI lid switch.
func Available() bool {
	_, ok := (&Monitor{}).closed()
	return ok
}

// Run calls OnChange once with the initial state, then on every change,
// until ctx is cancelled. It returns immediately if no lid switch exists.
func (m *Monitor) Run(ctx context.Context) {
	interval := m.Interval
	if interval == 0 {
		interval = 2 * time.Second
	}

	last, ok := m.closed()
	if !ok {
		log.Printf("lidmon: no ACPI lid switch found, lid monitoring disabled")
		return
	}
	log.Printf("lidmon: lid closed=%v on start", last)
	m.OnChange(last)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, ok := m.closed()
			if ok && cur != last {
				last = cur
				log.Printf("lidmon: lid closed=%v", cur)
				m.OnChange(cur)
			}
		}
	}
}

// closed returns true if any lid reports "closed". ok is false when no
// lid state file can be read.
func (m *Monitor) closed() (closed, ok bool) {
	pattern := m.glob
	if pattern == "" {
		pattern = "/proc/acpi/button/lid/*/state"
	}
	paths, _ := filepath.Glob(pattern)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ok = true
		if strings.Contains(string(data), "closed") {
			return true, true
		}
	}
	return false, ok
}
