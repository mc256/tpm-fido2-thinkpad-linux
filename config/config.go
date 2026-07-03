// Package config reads tpm-fido's optional user configuration file.
//
// The file lives at ~/.config/tpm-fido/config and uses a simple KEY=VALUE
// format with '#' comments. Any problem reading or parsing it (missing
// file, unreadable file, unknown/invalid values) is non-fatal: Load logs a
// message and returns a zero-value Config so callers fall back to the
// program's default behavior.
package config

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ValidFingers lists the finger names accepted by fprintd-verify's -f flag.
var ValidFingers = []string{
	"left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
	"right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
}

// Config holds tpm-fido's user-configurable settings.
type Config struct {
	// Finger is the fprintd finger name to pass to `fprintd-verify -f`.
	// Empty means "let fprintd choose automatically" (the original behavior).
	Finger string
}

// Load reads the config file at ~/.config/tpm-fido/config relative to the
// given home directory. If the file does not exist, cannot be read, or
// contains an invalid value, Load logs the reason and returns a zero-value
// Config so the caller reproduces the original (unconfigured) behavior.
func Load(homeDir string) Config {
	path := filepath.Join(homeDir, ".config", "tpm-fido", "config")

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("config: could not read %s: %v (using defaults)", path, err)
		}
		return Config{}
	}

	var cfg Config

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip a trailing inline comment, if any.
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("config: %s: ignoring malformed line %q", path, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)

		switch key {
		case "FPRINTD_FINGER":
			if isValidFinger(value) {
				cfg.Finger = value
			} else {
				log.Printf("config: %s: invalid FPRINTD_FINGER %q, using automatic selection", path, value)
			}
		default:
			log.Printf("config: %s: ignoring unknown key %q", path, key)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("config: error parsing %s: %v (using defaults)", path, err)
		return Config{}
	}

	return cfg
}

func isValidFinger(name string) bool {
	for _, f := range ValidFingers {
		if f == name {
			return true
		}
	}
	return false
}
