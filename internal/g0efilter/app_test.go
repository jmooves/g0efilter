//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestGetenvDefault(t *testing.T) {
	tests := []struct {
		name string
		key  string
		def  string
		set  bool
		val  string
		want string
	}{
		{name: "unset", key: "TEST_UNSET_VAR", def: "default", want: "default"},
		{name: "set", key: "TEST_SET_VAR", def: "default", set: true, val: "env", want: "env"},
		{name: "empty uses default", key: "TEST_EMPTY_VAR", def: "default", set: true, val: "", want: "default"},
		{name: "whitespace uses default", key: "TEST_WS_VAR", def: "default", set: true, val: "   ", want: "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(tt.key, tt.val)
			}

			got := getenvDefault(tt.key, tt.def)
			if got != tt.want {
				t.Fatalf("getenvDefault(%q, %q) = %q, want %q", tt.key, tt.def, got, tt.want)
			}
		})
	}
}

func compareConfig(t *testing.T, got, want config) {
	t.Helper()

	if got.policyPath != want.policyPath {
		t.Errorf("policyPath = %v, want %v", got.policyPath, want.policyPath)
	}

	if got.httpPort != want.httpPort {
		t.Errorf("httpPort = %v, want %v", got.httpPort, want.httpPort)
	}

	if got.httpsPort != want.httpsPort {
		t.Errorf("httpsPort = %v, want %v", got.httpsPort, want.httpsPort)
	}

	if got.dnsPort != want.dnsPort {
		t.Errorf("dnsPort = %v, want %v", got.dnsPort, want.dnsPort)
	}

	if got.logLevel != want.logLevel {
		t.Errorf("logLevel = %v, want %v", got.logLevel, want.logLevel)
	}

	if got.logFile != want.logFile {
		t.Errorf("logFile = %v, want %v", got.logFile, want.logFile)
	}

	if got.hostname != want.hostname {
		t.Errorf("hostname = %v, want %v", got.hostname, want.hostname)
	}

	if got.mode != want.mode {
		t.Errorf("mode = %v, want %v", got.mode, want.mode)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("HOSTNAME", "")

	want := config{
		policyPath: "/app/policy.yaml",
		httpPort:   "8080",
		httpsPort:  "8443",
		dnsPort:    "53",
		logLevel:   "INFO",
		logFile:    "",
		hostname:   "",
		mode:       "https",
	}

	got := loadConfig()
	compareConfig(t, got, want)
}

func TestLoadConfigCustomValues(t *testing.T) {
	t.Setenv("POLICY_PATH", "/custom/policy.yaml")
	t.Setenv("HTTP_PORT", "9080")
	t.Setenv("HTTPS_PORT", "9443")
	t.Setenv("DNS_PORT", "5353")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("LOG_FILE", "/var/log/g0efilter.log")
	t.Setenv("HOSTNAME", "test-host")
	t.Setenv("FILTER_MODE", "DNS")

	want := config{
		policyPath: "/custom/policy.yaml",
		httpPort:   "9080",
		httpsPort:  "9443",
		dnsPort:    "5353",
		logLevel:   "DEBUG",
		logFile:    "/var/log/g0efilter.log",
		hostname:   "test-host",
		mode:       "dns",
	}

	got := loadConfig()
	compareConfig(t, got, want)
}

func TestLoadConfigFilterModeTrimsAndLowercases(t *testing.T) {
	t.Setenv("FILTER_MODE", "  HtTpS  ")
	t.Setenv("HOSTNAME", "")

	got := loadConfig()
	if got.mode != "https" {
		t.Fatalf("loadConfig().mode = %q, want %q", got.mode, "https")
	}
}

func TestNormalizeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   config
		want string
	}{
		{name: "dns ok", in: config{mode: "dns"}, want: "dns"},
		{name: "https ok", in: config{mode: "https"}, want: "https"},
		{name: "invalid defaults to https", in: config{mode: "nope"}, want: "https"},
		{name: "empty defaults to https", in: config{mode: ""}, want: "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeMode(tt.in, discardLogger())
			if got.mode != tt.want {
				t.Fatalf("normalizeMode().mode = %q, want %q", got.mode, tt.want)
			}
		})
	}
}

func TestValidatePortsHTTPSConflict(t *testing.T) {
	t.Parallel()

	cfg := config{
		mode:      "https",
		httpPort:  "8080",
		httpsPort: "8080",
	}

	err := validatePorts(cfg, discardLogger())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, errPortConflict) {
		t.Fatalf("expected errors.Is(..., %v) true, got %v", errPortConflict, err)
	}
}

func TestValidatePortsOK(t *testing.T) {
	t.Parallel()

	tests := []config{
		{mode: "https", httpPort: "8080", httpsPort: "8443"},
		{mode: "dns", dnsPort: "53", httpPort: "53", httpsPort: "53"},
	}

	for _, cfg := range tests {
		t.Run(cfg.mode, func(t *testing.T) {
			t.Parallel()

			err := validatePorts(cfg, discardLogger())
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestFileSHA256HexEmptyOrWhitespaceReturnsError(t *testing.T) {
	t.Parallel()

	paths := []string{"", "   ", "\n\t  "}
	for _, p := range paths {
		t.Run(strings.ReplaceAll(p, "\n", "\\n"), func(t *testing.T) {
			t.Parallel()

			_, err := fileSHA256Hex(p)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", p)
			}
		})
	}
}

func TestFileSHA256HexMatchesSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	content := []byte("hello\n")

	err := os.WriteFile(p, content, 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := fileSHA256Hex(" \t" + p + "\n")
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestFileSHA256HexChangesWhenContentChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")

	err := os.WriteFile(p, []byte("a\n"), 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h1, err := fileSHA256Hex(p)
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	err = os.WriteFile(p, []byte("b\n"), 0o600)
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	h2, err := fileSHA256Hex(p)
	if err != nil {
		t.Fatalf("fileSHA256Hex: %v", err)
	}

	if h1 == h2 {
		t.Fatalf("expected hash to change, but both were %q", h1)
	}
}

func TestSendLatestKeepsMostRecent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ch := make(chan policyUpdate, 1)

	upd1 := policyUpdate{hash: "h1", domains: []string{"a"}, ips: []string{"1.1.1.1"}}
	upd2 := policyUpdate{hash: "h2", domains: []string{"b"}, ips: []string{"2.2.2.2"}}

	sendLatest(ctx, ch, upd1)
	sendLatest(ctx, ch, upd2)

	got := <-ch
	if got.hash != "h2" {
		t.Fatalf("expected latest hash %q, got %q", "h2", got.hash)
	}
}
