// Package usbmon polls sysfs for USB device insertion/removal events.
package usbmon

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Monitor polls /sys/bus/usb/devices/ for USB devices matching a vendor ID.
type Monitor struct {
	VendorID string        // e.g. "1050" (Yubico)
	Interval time.Duration // poll interval (default 2s)
	OnInsert func(product string)
	OnRemove func()
}

// Run polls sysfs until ctx is cancelled. It calls OnInsert when a device
// with the matching vendor ID appears and OnRemove when it disappears.
// It blocks until the context is done.
func (m *Monitor) Run(ctx context.Context) {
	interval := m.Interval
	if interval == 0 {
		interval = 2 * time.Second
	}

	var present bool
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Check immediately on start.
	if name, found := m.scan(); found {
		present = true
		if m.OnInsert != nil {
			log.Printf("usbmon: device detected on start: %s", name)
			m.OnInsert(name)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			name, found := m.scan()
			if found && !present {
				present = true
				if m.OnInsert != nil {
					log.Printf("usbmon: device inserted: %s", name)
					m.OnInsert(name)
				}
			} else if !found && present {
				present = false
				if m.OnRemove != nil {
					log.Printf("usbmon: device removed")
					m.OnRemove()
				}
			}
		}
	}
}

// scan checks /sys/bus/usb/devices/*/idVendor for a match.
// Returns the product name and true if found.
func (m *Monitor) scan() (string, bool) {
	matches, err := filepath.Glob("/sys/bus/usb/devices/*/idVendor")
	if err != nil {
		return "", false
	}

	for _, vendorPath := range matches {
		data, err := os.ReadFile(vendorPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) != m.VendorID {
			continue
		}

		// Read the product name from the sibling file.
		dir := filepath.Dir(vendorPath)
		productData, err := os.ReadFile(filepath.Join(dir, "product"))
		if err != nil {
			return "Unknown device", true
		}
		return strings.TrimSpace(string(productData)), true
	}

	return "", false
}
