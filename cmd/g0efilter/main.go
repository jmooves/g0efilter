// Package main is the entrypoint for g0efilter.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/g0lab/g0efilter/internal/logging"
	"github.com/g0lab/g0efilter/internal/nftables"
	"github.com/g0lab/g0efilter/internal/policy"
)

const (
	name         = "g0efilter"
	licenseYear  = "2025"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultDialTimeout = 5000
	defaultIdleTimeout = 600000
	retryDelay         = 5 * time.Second

	policyPollInterval = 5 * time.Second
)

var (
	errPortConflict    = errors.New("port conflict detected")
	errPolicyPathEmpty = errors.New("policy path is empty")
)

// Set by GoReleaser via ldflags.
var (
	version = ""
	commit  = "" //nolint:gochecknoglobals
	date    = "" //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	if version == "" {
		version = "0.0.0-dev"
	}

	if date == "" {
		date = "unknown"
	}

	if commit == "" {
		commit = "none"
	}
}

type policyUpdate struct {
	hash    string
	domains []string
	ips     []string
}

func main() {
	if handleVersionFlag() {
		return
	}

	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg := loadConfig()

	lg := logging.NewWithContext(context.Background(), cfg.logLevel, os.Stdout, version)
	slog.SetDefault(lg)

	cfg = normalizeMode(cfg, lg)

	logStartupInfo(lg, cfg)
	logDashboardInfo(lg)
	logNotificationInfo(lg)

	err := validatePorts(cfg, lg)
	if err != nil {
		lg.Error("config.port_validation_failed", "err", err)

		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	domains, initialHash, err := loadInitialPolicy(ctx, cfg, lg)
	if err != nil {
		return err
	}

	svcCancel := startServiceGroup(ctx, cfg, domains, lg)

	defer func() {
		if svcCancel != nil {
			svcCancel()
		}
	}()

	startNflogStream(ctx, lg)

	reloadCh := make(chan policyUpdate, 1)

	lg.Info("policy.watcher_started", "path", cfg.policyPath, "interval", policyPollInterval.String())

	go pollPolicyChanges(ctx, cfg, lg, initialHash, policyPollInterval, reloadCh)

	lg.Info("startup.ready", "mode", cfg.mode, "filter_count", len(domains))

	supervise(ctx, cancel, sigCh, reloadCh, cfg, lg, &svcCancel)
	shutdownGracefully(lg)

	return nil
}

func supervise(
	ctx context.Context,
	cancel context.CancelFunc,
	sigCh <-chan os.Signal,
	reloadCh <-chan policyUpdate,
	cfg config,
	lg *slog.Logger,
	svcCancel *context.CancelFunc,
) {
	for {
		select {
		case sig := <-sigCh:
			lg.Info("shutdown.signal", "signal", sig.String())
			cancel()
			stopServices(svcCancel)

			return

		case upd := <-reloadCh:
			if ctx.Err() != nil {
				stopServices(svcCancel)

				return
			}

			lg.Info("policy.reloaded",
				"hash", upd.hash,
				"domain_count", len(upd.domains),
				"ip_count", len(upd.ips),
			)

			restartServices(ctx, cfg, upd.domains, lg, svcCancel)
			lg.Info("policy.applied", "mode", cfg.mode, "filter_count", len(upd.domains))

		case <-ctx.Done():
			stopServices(svcCancel)

			return
		}
	}
}

func startServiceGroup(ctx context.Context, cfg config, domains []string, lg *slog.Logger) context.CancelFunc {
	svcCtx, cancel := context.WithCancel(ctx)
	startServices(svcCtx, cfg, domains, lg)

	return cancel
}

func stopServices(svcCancel *context.CancelFunc) {
	if svcCancel == nil {
		return
	}

	if *svcCancel == nil {
		return
	}

	(*svcCancel)()
}

func restartServices(
	ctx context.Context,
	cfg config,
	domains []string,
	lg *slog.Logger,
	svcCancel *context.CancelFunc) {
	stopServices(svcCancel)
	*svcCancel = startServiceGroup(ctx, cfg, domains, lg)
}

func shutdownGracefully(lg *slog.Logger) {
	const shutdownGracePeriod = 3 * time.Second
	lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod.String())
	time.Sleep(shutdownGracePeriod)

	lg.Info("shutdown.complete")
	logging.Shutdown(1 * time.Second)
}

func loadInitialPolicy(ctx context.Context, cfg config, lg *slog.Logger) ([]string, string, error) {
	domains, _, err := loadAndApplyPolicy(ctx, cfg, lg)
	if err != nil {
		return nil, "", err
	}

	hash, err := fileSHA256Hex(cfg.policyPath)
	if err != nil {
		lg.Warn("policy.hash_read_failed", "path", cfg.policyPath, "err", err)

		return domains, "", nil
	}

	return domains, hash, nil
}

func handleVersionFlag() bool {
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "--version" || arg == "version" || arg == "-V" || arg == "-v" {
			printVersion()

			return true
		}
	}

	return false
}

// config holds application configuration from environment variables.
type config struct {
	policyPath string
	httpPort   string
	httpsPort  string
	dnsPort    string
	logLevel   string
	logFile    string
	hostname   string
	mode       string
}

// loadConfig reads configuration from environment variables.
func loadConfig() config {
	return config{
		policyPath: getenvDefault("POLICY_PATH", "/app/policy.yaml"),
		httpPort:   getenvDefault("HTTP_PORT", "8080"),
		httpsPort:  getenvDefault("HTTPS_PORT", "8443"),
		dnsPort:    getenvDefault("DNS_PORT", "53"),
		logLevel:   getenvDefault("LOG_LEVEL", "INFO"),
		logFile:    getenvDefault("LOG_FILE", ""),
		hostname:   getenvDefault("HOSTNAME", ""),
		mode:       strings.ToLower(getenvDefault("FILTER_MODE", "https")),
	}
}

// getGoVersion returns the Go version used to build the binary.
func getGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}

	return "unknown"
}

// printVersion prints version information to stderr.
func printVersion() {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, short, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

// logStartupInfo logs application startup information and configuration.
func logStartupInfo(lg *slog.Logger, cfg config) {
	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = commit[:7]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	nftVersion, err := nftables.Version(ctx)
	if err != nil {
		nftVersion = "unavailable"

		lg.Debug("startup.nftables_version_error", "error", err.Error())
	}

	kv := []any{
		"name", name,
		"version", version,
		"commit", shortCommit,
		"go_version", getGoVersion(),
		"nft_version", nftVersion,
		"build_date", date,
		"mode", cfg.mode,
		"policy_path", cfg.policyPath,
		"log_level", cfg.logLevel,
	}

	if cfg.hostname != "" {
		kv = append(kv, "hostname", cfg.hostname)
	}

	if cfg.logFile != "" {
		kv = append(kv, "log_file", cfg.logFile)
	}

	lg.Info("startup.info", kv...)

	if cfg.mode == filter.ModeHTTPS {
		lg.Debug("startup.ports", "http_port", cfg.httpPort, "https_port", cfg.httpsPort)
	}

	if cfg.mode == filter.ModeDNS {
		lg.Debug("startup.ports", "dns_port", cfg.dnsPort)
	}
}

func logDashboardInfo(lg *slog.Logger) {
	dhost := strings.TrimSpace(getenvDefault("DASHBOARD_HOST", ""))
	if dhost != "" {
		disp := dhost
		if !strings.HasPrefix(disp, "http://") && !strings.HasPrefix(disp, "https://") {
			disp = "http://" + disp
		}

		lg.Info("dashboard.logging_enabled", "host", disp)
	} else {
		lg.Info("dashboard.logging_disabled")
	}
}

// logNotificationInfo logs notification configuration status.
func logNotificationInfo(lg *slog.Logger) {
	nhost := strings.TrimSpace(getenvDefault("NOTIFICATION_HOST", ""))
	ntoken := strings.TrimSpace(getenvDefault("NOTIFICATION_KEY", ""))

	if nhost != "" && ntoken != "" {
		lg.Info("notifications.enabled", "host", nhost)
	} else {
		lg.Info("notifications.disabled")
	}
}

// normalizeMode validates and normalizes the filter mode configuration.
func normalizeMode(cfg config, lg *slog.Logger) config {
	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	validModes := map[string]bool{
		filter.ModeHTTPS: true,
		filter.ModeDNS:   true,
	}

	if !validModes[mode] && mode != "" {
		lg.Warn("filter_mode.invalid", "mode", cfg.mode, "defaulting_to", filter.ModeHTTPS)
		cfg.mode = filter.ModeHTTPS
	} else if mode == "" {
		cfg.mode = filter.ModeHTTPS
	}

	return cfg
}

// validatePorts checks for port conflicts in the configuration.
func validatePorts(cfg config, lg *slog.Logger) error {
	if cfg.mode == filter.ModeHTTPS {
		if cfg.httpPort == cfg.httpsPort {
			return fmt.Errorf("%w: HTTP_PORT and HTTPS_PORT cannot be the same (%s)",
				errPortConflict, cfg.httpPort)
		}
	}

	if cfg.mode == filter.ModeDNS {
		if cfg.dnsPort == cfg.httpPort {
			lg.Warn("config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTP_PORT", cfg.httpPort,
				"note", "DNS mode active, HTTP port not used",
			)
		}

		if cfg.dnsPort == cfg.httpsPort {
			lg.Warn("config.port_overlap",
				"DNS_PORT", cfg.dnsPort,
				"HTTPS_PORT", cfg.httpsPort,
				"note", "DNS mode active, HTTPS port not used",
			)
		}
	}

	return nil
}

// loadAndApplyPolicy loads the policy file and applies nftables rules.
func loadAndApplyPolicy(ctx context.Context, cfg config, lg *slog.Logger) ([]string, []string, error) {
	ips, domains, err := policy.ReadPolicy(cfg.policyPath)
	if err != nil {
		lg.Error("policy.read_error", "path", cfg.policyPath, "err", err)

		return nil, nil, fmt.Errorf("failed to read policy: %w", err)
	}

	lg.Info("policy.loaded", "domain_count", len(domains), "ip_count", len(ips))
	lg.Debug("policy.loaded.details", "domains", domains, "ips", ips)

	err = nftables.ApplyNftRulesWithContext(ctx, ips, cfg.httpsPort, cfg.httpPort, cfg.dnsPort)
	if err != nil {
		lg.Error("nftables.apply_failed", "err", err)

		return nil, nil, fmt.Errorf("apply nftables rules: %w", err)
	}

	lg.Info("nftables.applied")

	return domains, ips, nil
}

// runServiceWithRetry runs a service in a goroutine and restarts it on failure.
func runServiceWithRetry(ctx context.Context, serviceName string, lg *slog.Logger, serviceFunc func() error) {
	go func() {
		for {
			if ctx.Err() != nil {
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			}

			err := serviceFunc()
			if err == nil {
				continue
			}

			if ctx.Err() != nil {
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			}

			lg.Error(serviceName+".stopped", "err", err, "action", "retrying")

			select {
			case <-ctx.Done():
				lg.Info(serviceName+".shutdown", "reason", "context cancelled")

				return
			case <-time.After(retryDelay):
			}
		}
	}()
}

// startServices starts the appropriate filtering services based on mode.
func startServices(
	ctx context.Context,
	cfg config,
	domains []string,
	lg *slog.Logger,
) {
	opts := filter.Options{
		DialTimeout: defaultDialTimeout,
		IdleTimeout: defaultIdleTimeout,
		DropWithRST: true,
		Logger:      lg,
	}

	switch cfg.mode {
	case filter.ModeDNS:
		startDNSService(ctx, cfg.dnsPort, domains, opts, lg)
	case filter.ModeHTTPS:
		startHTTPSServices(ctx, cfg, domains, opts, lg)
	default:
		lg.Warn("filter_mode.invalid", "mode", cfg.mode, "defaulting_to", filter.ModeHTTPS)
		startHTTPSServices(ctx, cfg, domains, opts, lg)
	}
}

func startDNSService(
	ctx context.Context,
	dnsPort string,
	domains []string,
	opts filter.Options,
	lg *slog.Logger,
) {
	lg.Debug("dns.starting", "addr", ":"+dnsPort)

	dnsOpts := opts
	dnsOpts.ListenAddr = ":" + dnsPort

	runServiceWithRetry(ctx, "dns", lg, func() error {
		return filter.Serve53(ctx, domains, dnsOpts)
	})
}

func startHTTPSServices(
	ctx context.Context,
	cfg config,
	domains []string,
	opts filter.Options,
	lg *slog.Logger,
) {
	lg.Debug("https.starting", "addr", ":"+cfg.httpsPort)

	httpsOpts := opts
	httpsOpts.ListenAddr = ":" + cfg.httpsPort

	runServiceWithRetry(ctx, "https", lg, func() error {
		return filter.Serve443(ctx, domains, httpsOpts)
	})

	lg.Debug("http.starting", "addr", ":"+cfg.httpPort)

	httpOpts := opts
	httpOpts.ListenAddr = ":" + cfg.httpPort

	runServiceWithRetry(ctx, "http", lg, func() error {
		return filter.Serve80(ctx, domains, httpOpts)
	})
}

func startNflogStream(ctx context.Context, lg *slog.Logger) {
	lg.Info("nflog.listen")

	go func() {
		err := nftables.StreamNfLogWithLogger(ctx, lg)
		if err != nil {
			lg.Warn("nflog.stream_error", "err", err)
		}
	}()
}

// pollPolicyChanges polls the policy file hash and reloads on change.
func pollPolicyChanges(
	ctx context.Context,
	cfg config,
	lg *slog.Logger,
	initialHash string,
	interval time.Duration,
	reloadCh chan policyUpdate,
) {
	lastHash := initialHash

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-t.C:
			newHash, err := fileSHA256Hex(cfg.policyPath)
			if err != nil {
				lg.Warn("policy.hash_read_failed", "path", cfg.policyPath, "err", err)

				continue
			}

			if lastHash == "" {
				lastHash = newHash

				continue
			}

			if newHash == lastHash {
				continue
			}

			lg.Info("policy.change_detected", "old_hash", lastHash, "new_hash", newHash)

			domains, ips, err := loadAndApplyPolicy(ctx, cfg, lg)
			if err != nil {
				lg.Error("policy.reload_failed", "err", err)

				continue
			}

			lastHash = newHash

			upd := policyUpdate{
				hash:    newHash,
				domains: append([]string(nil), domains...),
				ips:     append([]string(nil), ips...),
			}

			sendLatest(ctx, reloadCh, upd)
		}
	}
}

func sendLatest(ctx context.Context, reloadCh chan policyUpdate, upd policyUpdate) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	select {
	case reloadCh <- upd:
		return
	default:
	}

	select {
	case <-ctx.Done():
		return
	case <-reloadCh:
	default:
	}

	select {
	case <-ctx.Done():
		return
	case reloadCh <- upd:
	}
}

func fileSHA256Hex(path string) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return "", errPolicyPathEmpty
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", cleanPath, err)
	}

	h := sha256.New()

	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()

	if copyErr != nil {
		if closeErr != nil {
			return "", fmt.Errorf("read %q: %w (close error: %w)", cleanPath, copyErr, closeErr)
		}

		return "", fmt.Errorf("read %q: %w", cleanPath, copyErr)
	}

	if closeErr != nil {
		return "", fmt.Errorf("close %q: %w", cleanPath, closeErr)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// getenvDefault gets an environment variable with a default value if empty.
func getenvDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}

	return v
}
