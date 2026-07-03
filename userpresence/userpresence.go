package userpresence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const touchSensorPrompt = "Touch fingerprint sensor to confirm."

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request

	// finger is the fprintd finger name to pass via `fprintd-verify -f`.
	// Empty means let fprintd pick automatically (original behavior).
	finger string
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

// New creates a new UserPresence handler. finger, if non-empty, is passed to
// `fprintd-verify -f <finger>` to pin verification to a specific enrolled
// finger. If empty, fprintd chooses automatically (original behavior).
func New(finger string) *UserPresence {
	return &UserPresence{finger: finger}
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
	notify("30000", prompt+"\n\n"+touchSensorPrompt)

	// Run fprintd-verify with context timeout
	var args []string
	if up.finger != "" {
		args = []string{"-f", up.finger}
	}
	log.Printf("userpresence: launching fprintd-verify %v", args)
	fprintCmd := exec.CommandContext(ctx, "fprintd-verify", args...)
	var output bytes.Buffer
	// Must not use stdout - Native Messaging uses it. Also capture the
	// output (in addition to logging it) so the failure notification can
	// include fprintd-verify's own error message.
	fprintCmd.Stdout = io.MultiWriter(os.Stderr, &output)
	fprintCmd.Stderr = io.MultiWriter(os.Stderr, &output)

	err := fprintCmd.Run()
	if err != nil {
		log.Printf("userpresence: fprintd-verify failed: %v", err)

		if ctx.Err() == context.DeadlineExceeded {
			notify("10000", "Fingerprint verification failed: timed out waiting for touch.")
			sendResult(Result{OK: false, Error: errors.New("fingerprint verification timed out")})
		} else {
			notify("10000", "Fingerprint verification failed: "+lastLine(output.String(), err))
			sendResult(Result{OK: false, Error: err})
		}
		return
	}

	log.Printf("userpresence: fingerprint verified successfully")
	sendResult(Result{OK: true, Error: nil})
}

// lastLine returns the last non-empty line of fprintd-verify's captured
// output, which usually holds its actual error message (e.g. "Finger
// 'left-thumb' not enrolled for user ."). Falls back to err if output is
// empty.
func lastLine(output string, err error) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return err.Error()
	}
	lines := strings.Split(trimmed, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// notify shows a desktop notification (non-blocking).
func notify(timeoutMs, body string) {
	notifyCmd := exec.Command("notify-send", "-u", "critical", "-t", timeoutMs, "TPM-FIDO", body)
	if err := notifyCmd.Start(); err != nil {
		log.Printf("userpresence: notify-send failed to start: %v", err)
		// Continue anyway - fingerprint verification is the important part
	}
}
