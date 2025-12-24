package userpresence

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout          time.Duration
	pendingResult    chan Result
	extendTimeout    chan time.Duration
	challengeParam   [32]byte
	applicationParam [32]byte
}

// Result represents the outcome of a user presence check
type Result struct {
	OK    bool
	Error error
}

// New creates a new UserPresence handler
func New() *UserPresence {
	return &UserPresence{}
}

// ConfirmPresence requests user presence confirmation via fingerprint
func (up *UserPresence) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	timeout := 30 * time.Second

	if up.activeRequest != nil {
		if challengeParam != up.activeRequest.challengeParam || applicationParam != up.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := up.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(2 * time.Second):
			}
		}()

		return up.activeRequest.pendingResult, nil
	}

	up.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go up.promptFingerprint(up.activeRequest, prompt)

	return up.activeRequest.pendingResult, nil
}

func (up *UserPresence) promptFingerprint(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(2 * time.Second):
			// Client likely gone
		}

		up.mu.Lock()
		up.activeRequest = nil
		up.mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.timeout)
	defer cancel()

	log.Printf("userpresence: prompt=%s", prompt)

	// Send notification to user (non-blocking)
	notifyCmd := exec.Command("notify-send", "-u", "critical", "-t", "30000",
		"TPM-FIDO", prompt+"\n\nTouch fingerprint sensor to confirm.")
	if err := notifyCmd.Start(); err != nil {
		log.Printf("userpresence: notify-send failed to start: %v", err)
		// Continue anyway - fingerprint verification is the important part
	}

	// Run fprintd-verify with context timeout
	log.Printf("userpresence: launching fprintd-verify")
	fprintCmd := exec.CommandContext(ctx, "fprintd-verify")
	fprintCmd.Stdout = os.Stderr // Must not use stdout - Native Messaging uses it
	fprintCmd.Stderr = os.Stderr

	err := fprintCmd.Run()
	if err != nil {
		log.Printf("userpresence: fprintd-verify failed: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			sendResult(Result{OK: false, Error: errors.New("fingerprint verification timed out")})
		} else {
			sendResult(Result{OK: false, Error: err})
		}
		return
	}

	log.Printf("userpresence: fingerprint verified successfully")
	sendResult(Result{OK: true, Error: nil})
}
