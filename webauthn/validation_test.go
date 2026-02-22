package webauthn

import "testing"

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid https with port", "https://example.com:443", false},
		{"valid https subdomain", "https://login.example.com", false},
		{"empty", "", true},
		{"http rejected", "http://example.com", true},
		{"file rejected", "file:///etc/passwd", true},
		{"javascript rejected", "javascript:alert(1)", true},
		{"data rejected", "data:text/html,<h1>hi</h1>", true},
		{"no scheme", "example.com", true},
		{"with path", "https://example.com/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrigin(tt.origin)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOrigin(%q) error = %v, wantErr %v", tt.origin, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRPID(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		rpID    string
		wantErr bool
	}{
		{"exact match", "https://example.com", "example.com", false},
		{"subdomain match", "https://login.example.com", "example.com", false},
		{"deep subdomain match", "https://a.b.example.com", "example.com", false},
		{"full subdomain as rpID", "https://login.example.com", "login.example.com", false},
		{"case insensitive", "https://Login.Example.COM", "example.com", false},
		{"different domain", "https://evil.com", "example.com", true},
		{"suffix but not domain boundary", "https://notexample.com", "example.com", true},
		{"superdomain rejected", "https://example.com", "login.example.com", true},
		{"empty rpID", "https://example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRPID(tt.origin, tt.rpID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRPID(%q, %q) error = %v, wantErr %v", tt.origin, tt.rpID, err, tt.wantErr)
			}
		})
	}
}
