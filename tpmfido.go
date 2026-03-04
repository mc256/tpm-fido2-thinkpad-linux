package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/nativemsg"
	"github.com/psanford/tpm-fido/tpm"
	"github.com/psanford/tpm-fido/tray"
	"github.com/psanford/tpm-fido/usbmon"
	"github.com/psanford/tpm-fido/userpresence"
	"github.com/psanford/tpm-fido/webauthn"
)

var (
	backend  = flag.String("backend", "tpm", "Backend to use: tpm or memory")
	device   = flag.String("device", "/dev/tpmrm0", "TPM device path")
	mode     = flag.String("mode", "native", "Operating mode: native (Chrome extension) or daemon (virtual HID device)")
	showTray   = flag.Bool("tray", false, "Show system tray icon for toggling the virtual device (daemon mode only)")
	autoSwitch = flag.Bool("auto-switch", true, "Automatically disable virtual key when a YubiKey is plugged in (tray mode only)")
)

func main() {
	flag.Parse()

	// Set up logging to stderr (Native Messaging uses stdout for communication)
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("tpm-fido starting with backend=%s mode=%s", *backend, *mode)

	// Initialize the signer backend
	var signer ctap2.Signer
	var err error

	switch *backend {
	case "tpm":
		signer, err = tpm.New(*device)
		if err != nil {
			log.Fatalf("Failed to initialize TPM backend: %v", err)
		}
		log.Printf("TPM backend initialized using %s", *device)
	case "memory":
		signer, err = memory.New()
		if err != nil {
			log.Fatalf("Failed to initialize memory backend: %v", err)
		}
		log.Printf("Memory backend initialized (for testing only)")
	default:
		log.Fatalf("Unknown backend: %s (use 'tpm' or 'memory')", *backend)
	}

	// Initialize user presence handler
	presence := userpresence.New()
	log.Printf("User presence handler initialized")

	// Initialize credential storage for resident keys
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	storagePath := filepath.Join(homeDir, ".local", "share", "tpm-fido", "credentials.json")
	storage, err := ctap2.NewCredentialStorage(storagePath)
	if err != nil {
		log.Fatalf("Failed to create credential storage: %v", err)
	}
	log.Printf("Credential storage initialized at %s (%d credentials)", storagePath, storage.Count())

	// Create CTAP2 handler
	ctap2Handler := ctap2.NewHandler(signer, presence, storage)
	log.Printf("CTAP2 handler initialized")

	switch *mode {
	case "native":
		runNativeMode(ctap2Handler)
	case "daemon":
		runDaemonMode(ctap2Handler)
	default:
		log.Fatalf("Unknown mode: %s (use 'native' or 'daemon')", *mode)
	}
}

// runNativeMode runs as a Chrome Native Messaging host
func runNativeMode(ctap2Handler *ctap2.Handler) {
	ctap2Handler.IsPlatform = true

	handler := webauthn.NewHandler(ctap2Handler)
	log.Printf("WebAuthn handler initialized")

	ctx := context.Background()
	runNativeMessaging(ctx, handler)
}

// runDaemonMode creates a virtual FIDO2 HID device and handles CTAPHID traffic.
// If --tray is set, it also shows a system tray icon for toggling the device.
func runDaemonMode(ctap2Handler *ctap2.Handler) {
	ctap2Handler.IsPlatform = false

	if *showTray {
		runDaemonWithTray(ctap2Handler)
	} else {
		runDaemonHeadless(ctap2Handler)
	}
}

// runDaemonHeadless runs the virtual FIDO2 device without a tray icon.
func runDaemonHeadless(ctap2Handler *ctap2.Handler) {
	dev, err := fidohid.New("tpm-fido", ctap2Handler)
	if err != nil {
		log.Fatalf("Failed to create virtual FIDO2 device: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down", sig)
		cancel()
	}()

	log.Printf("Virtual FIDO2 HID device daemon started")

	if err := dev.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Device error: %v", err)
	}

	dev.Close()
	log.Printf("Daemon stopped")
}

// runDaemonWithTray runs the virtual FIDO2 device with a system tray icon.
// The tray event loop runs on the main goroutine; the uhid device runs in
// a background goroutine and can be toggled on/off from the tray menu.
func runDaemonWithTray(ctap2Handler *ctap2.Handler) {
	var (
		mu              sync.Mutex
		dev             *fidohid.Device
		devCancel       context.CancelFunc
		autoSwitchOn    = *autoSwitch
		stoppedByAuto   bool // true if auto-switch disabled the device
		yubiKeyPresent  bool
	)

	// startDevice creates and runs the virtual HID device in a goroutine.
	startDevice := func() {
		mu.Lock()
		defer mu.Unlock()

		if dev != nil {
			return // already running
		}

		d, err := fidohid.New("tpm-fido", ctap2Handler)
		if err != nil {
			log.Printf("Failed to create virtual FIDO2 device: %v", err)
			return
		}

		ctx, c := context.WithCancel(context.Background())
		dev = d
		devCancel = c

		go func() {
			log.Printf("Virtual FIDO2 HID device started")
			if err := d.Run(ctx); err != nil && err != context.Canceled {
				log.Printf("Device error: %v", err)
			}
			d.Close()
			log.Printf("Virtual FIDO2 HID device stopped")
		}()
	}

	// stopDevice destroys the virtual HID device.
	stopDevice := func() {
		mu.Lock()
		defer mu.Unlock()

		if devCancel != nil {
			devCancel()
			devCancel = nil
		}
		if dev != nil {
			dev.Close()
			dev = nil
		}
	}

	// Handle SIGTERM/SIGINT for clean shutdown
	monCtx, monCancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down", sig)
		monCancel()
		stopDevice()
		os.Exit(0)
	}()

	// Start the device immediately
	startDevice()

	// Create the tray with auto-switch callback.
	// Declare t first so closures can reference it.
	var t *tray.Tray
	t = tray.New(
		func() { // onEnable
			stoppedByAuto = false
			startDevice()
		},
		func() { // onDisable
			stoppedByAuto = false
			stopDevice()
		},
		func() { // onQuit
			monCancel()
			stopDevice()
		},
		func(enabled bool) { // onAutoSwitchChanged
			mu.Lock()
			autoSwitchOn = enabled
			wasStoppedByAuto := stoppedByAuto
			present := yubiKeyPresent
			mu.Unlock()

			if !enabled && wasStoppedByAuto {
				log.Printf("auto-switch disabled, re-enabling virtual device")
				stoppedByAuto = false
				startDevice()
				t.SetActive(true)
			} else if enabled && present {
				log.Printf("auto-switch enabled with YubiKey present, disabling virtual device")
				stoppedByAuto = true
				stopDevice()
				t.SetActive(false)
			}
		},
	)
	t.SetAutoSwitch(autoSwitchOn)

	// Start the USB monitor for YubiKey detection
	mon := &usbmon.Monitor{
		VendorID: "1050", // Yubico
		Interval: 2 * time.Second,
		OnInsert: func(product string) {
			mu.Lock()
			yubiKeyPresent = true
			enabled := autoSwitchOn
			mu.Unlock()

			t.SetYubiKeyDetected(true, product)
			if enabled {
				log.Printf("YubiKey inserted, auto-disabling virtual device")
				stoppedByAuto = true
				stopDevice()
				t.SetActive(false)
			}
		},
		OnRemove: func() {
			mu.Lock()
			yubiKeyPresent = false
			enabled := autoSwitchOn
			wasStoppedByAuto := stoppedByAuto
			mu.Unlock()

			t.SetYubiKeyDetected(false, "")
			if enabled && wasStoppedByAuto {
				log.Printf("YubiKey removed, auto-enabling virtual device")
				stoppedByAuto = false
				startDevice()
				t.SetActive(true)
			}
		},
	}

	go mon.Run(monCtx)

	log.Printf("Starting system tray icon (auto-switch=%v)", autoSwitchOn)
	t.Run()
	log.Printf("Daemon stopped")
}

// runNativeMessaging runs the Native Messaging I/O loop
func runNativeMessaging(ctx context.Context, handler *webauthn.Handler) {
	log.Printf("Starting Native Messaging loop")

	for {
		// Read request from stdin
		msg, err := nativemsg.Read(os.Stdin)
		if err != nil {
			if err == io.EOF {
				log.Printf("Extension closed connection (EOF)")
				return
			}
			log.Printf("Read error: %v", err)
			return
		}

		log.Printf("Received message: %d bytes", len(msg))

		// Handle the request
		response := handler.HandleRequest(ctx, msg)

		// Write response to stdout
		if err := nativemsg.Write(os.Stdout, response); err != nil {
			log.Printf("Write error: %v", err)
			return
		}

		log.Printf("Response sent")
	}
}
