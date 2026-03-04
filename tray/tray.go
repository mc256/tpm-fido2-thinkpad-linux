// Package tray provides a GNOME system tray icon for toggling the
// tpm-fido virtual FIDO2 device on and off.
//
// It uses fyne.io/systray which implements the D-Bus StatusNotifierItem
// protocol in pure Go — no CGo or GTK required. Works with Ubuntu's
// pre-installed gnome-shell-extension-appindicator.
package tray

import (
	_ "embed"
	"log"

	"fyne.io/systray"
)

//go:embed icons/active.png
var iconActive []byte

//go:embed icons/inactive.png
var iconInactive []byte

// Tray manages the system tray icon and menu for toggling the virtual
// FIDO2 device.
type Tray struct {
	onEnable  func()
	onDisable func()
	onQuit    func()

	toggle *systray.MenuItem
	status *systray.MenuItem
	active bool
}

// New creates a new Tray. The callbacks are invoked when the user clicks
// the corresponding menu items. onEnable/onDisable toggle the virtual
// HID device; onQuit stops the daemon.
func New(onEnable, onDisable, onQuit func()) *Tray {
	return &Tray{
		onEnable:  onEnable,
		onDisable: onDisable,
		onQuit:    onQuit,
		active:    true, // device starts enabled
	}
}

// Run starts the system tray icon. It blocks until the tray exits.
// Must be called from the main goroutine on some platforms.
func (t *Tray) Run() {
	systray.Run(t.onReady, t.onExit)
}

// SetActive updates the tray icon and menu labels to reflect whether
// the virtual FIDO2 device is currently active.
func (t *Tray) SetActive(active bool) {
	t.active = active
	if active {
		systray.SetIcon(iconActive)
		systray.SetTooltip("TPM FIDO: Active")
		t.status.SetTitle("TPM FIDO: Active")
		t.toggle.SetTitle("Disable (use YubiKey)")
	} else {
		systray.SetIcon(iconInactive)
		systray.SetTooltip("TPM FIDO: Disabled")
		t.status.SetTitle("TPM FIDO: Disabled")
		t.toggle.SetTitle("Enable virtual key")
	}
}

func (t *Tray) onReady() {
	systray.SetTitle("TPM FIDO")

	t.status = systray.AddMenuItem("TPM FIDO: Active", "")
	t.status.Disable() // non-clickable status line

	systray.AddSeparator()

	t.toggle = systray.AddMenuItem("Disable (use YubiKey)", "Toggle virtual FIDO2 device")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Stop the tpm-fido daemon")

	// Set initial state (must be after menu items are created)
	t.SetActive(true)

	go func() {
		for {
			select {
			case <-t.toggle.ClickedCh:
				if t.active {
					log.Printf("tray: user requested disable")
					t.onDisable()
					t.SetActive(false)
				} else {
					log.Printf("tray: user requested enable")
					t.onEnable()
					t.SetActive(true)
				}
			case <-mQuit.ClickedCh:
				log.Printf("tray: user requested quit")
				t.onQuit()
				systray.Quit()
				return
			}
		}
	}()
}

func (t *Tray) onExit() {
	log.Printf("tray: exiting")
}
