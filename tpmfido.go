package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/nativemsg"
	"github.com/psanford/tpm-fido/tpm"
	"github.com/psanford/tpm-fido/userpresence"
	"github.com/psanford/tpm-fido/webauthn"
)

var (
	backend = flag.String("backend", "tpm", "Backend to use: tpm or memory")
	device  = flag.String("device", "/dev/tpmrm0", "TPM device path")
	mode    = flag.String("mode", "native", "Operating mode: native (Chrome extension) or daemon (virtual HID device)")
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

// runDaemonMode creates a virtual FIDO2 HID device and handles CTAPHID traffic
func runDaemonMode(ctap2Handler *ctap2.Handler) {
	ctap2Handler.IsPlatform = false

	dev, err := fidohid.New("tpm-fido", ctap2Handler)
	if err != nil {
		log.Fatalf("Failed to create virtual FIDO2 device: %v", err)
	}

	// Set up signal handling for clean shutdown
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
