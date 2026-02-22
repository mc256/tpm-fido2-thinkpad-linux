package webauthn

import (
	"fmt"
	"net/url"
	"strings"
)

// validateOrigin checks that origin is a well-formed HTTPS URL.
// It rejects http, file, javascript, data URIs, and any other non-HTTPS scheme.
func validateOrigin(origin string) error {
	if origin == "" {
		return fmt.Errorf("origin is empty")
	}

	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("origin is not a valid URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("origin scheme must be https, got %q", u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("origin has no host")
	}

	// Reject origins with paths, query strings, or fragments
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("origin must not contain a path")
	}

	return nil
}

// validateRPID checks that rpID is a valid registrable domain suffix of the
// origin's effective domain, per the WebAuthn specification (Section 7.1, step 8).
//
// For example:
//   - origin "https://login.example.com" with rpID "example.com" -> valid
//   - origin "https://login.example.com" with rpID "login.example.com" -> valid
//   - origin "https://example.com" with rpID "example.com" -> valid
//   - origin "https://evil.com" with rpID "example.com" -> invalid
//   - origin "https://notexample.com" with rpID "example.com" -> invalid
func validateRPID(origin, rpID string) error {
	if rpID == "" {
		return fmt.Errorf("rpId is empty")
	}

	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("origin is not a valid URL: %w", err)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("origin has no hostname")
	}

	// Normalize to lowercase for comparison
	hostname = strings.ToLower(hostname)
	rpID = strings.ToLower(rpID)

	// RP ID must be either equal to the hostname or a registrable domain suffix.
	// "suffix" means the hostname ends with "."+rpID.
	if hostname == rpID {
		return nil
	}

	if strings.HasSuffix(hostname, "."+rpID) {
		return nil
	}

	return fmt.Errorf("rpId %q is not a valid domain suffix of origin hostname %q", rpID, hostname)
}
