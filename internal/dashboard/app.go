package dashboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

const (
	name         = "g0efilter-dashboard"
	licenseYear  = "2026"
	licenseOwner = "g0lab"
	licenseType  = "MIT"

	defaultBufferSize = 5000
	defaultReadLimit  = 500
	defaultSERetryMs  = 2000
	defaultRateRPS    = 50.0
	defaultRateBurst  = 100.0

	shutdownGracePeriod = 3 * time.Second
)

var (
	errMissingAPIKey = errors.New("API_KEY is required but not set")
)

// RunDashboard is the dashboard entrypoint used by cmd/g0efilter-.
func RunDashboard(args []string, version, date, commit string) error {
	if handleVersionFlag(args, version, date, commit) {
		return nil
	}

	cfg := buildConfig(version, date, commit)
	normalizeAddr(&cfg)

	lg, err := setupLogging(cfg, version, date, commit)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, cfg)
	}()

	select {
	case err = <-errCh:
		cancel()

		if err != nil {
			lg.Error("failed", "err", err)

			return err
		}

		return nil

	case sig := <-sigCh:
		lg.Info("shutdown.signal", "signal", sig.String())
		cancel()

		lg.Info("shutdown.graceful", "grace_period", shutdownGracePeriod.String())

		select {
		case <-errCh:
		case <-time.After(shutdownGracePeriod):
			lg.Warn("shutdown.timeout", "timeout", shutdownGracePeriod.String())
		}

		logging.Shutdown(1 * time.Second)
		lg.Info("shutdown.complete")

		return nil
	}
}

func handleVersionFlag(args []string, version, date, commit string) bool {
	if len(args) > 1 {
		switch args[1] {
		case "--version", "version", "-V", "-v":
			printVersion(version, date, commit)

			return true
		}
	}

	return false
}

func getGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}

	return "unknown"
}

func printVersion(version, date, commit string) {
	short := commit
	if len(short) >= 7 {
		short = commit[:7]
	}

	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, short, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	return v
}

func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}

	return i
}

func getenvFloat(k string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}

	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}

	return f
}

func buildConfig(version, _, _ string) Config {
	return Config{
		Addr:         getenv("PORT", ":8081"),
		APIKey:       getenv("API_KEY", ""),
		LogLevel:     getenv("LOG_LEVEL", "INFO"),
		BufferSize:   getenvInt("BUFFER_SIZE", defaultBufferSize),
		ReadLimit:    getenvInt("READ_LIMIT", defaultReadLimit),
		SERetryMs:    getenvInt("SSE_RETRY_MS", defaultSERetryMs),
		RateRPS:      getenvFloat("RATE_RPS", defaultRateRPS),
		RateBurst:    getenvFloat("RATE_BURST", defaultRateBurst),
		WriteTimeout: getenvInt("WRITE_TIMEOUT", 0), // 0 = no timeout for SSE
		Version:      version,
	}
}

func normalizeAddr(cfg *Config) {
	if cfg.Addr != "" && !strings.Contains(cfg.Addr, ":") {
		_, aerr := strconv.Atoi(cfg.Addr)
		if aerr == nil {
			cfg.Addr = ":" + cfg.Addr
		}
	}
}

func setupLogging(cfg Config, version, date, commit string) (*slog.Logger, error) {
	lg := logging.NewWithContext(context.Background(), cfg.LogLevel, os.Stdout, version)
	slog.SetDefault(lg)

	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "ERROR: API_KEY environment variable is required but not set")
		fmt.Fprintln(os.Stderr, "The dashboard requires an API key for secure log ingestion")
		fmt.Fprintln(os.Stderr, "Please set API_KEY to a secure random string")

		lg.Error("config.missing_api_key", "msg", "API_KEY is required")

		return nil, errMissingAPIKey
	}

	shortCommit := commit
	if len(shortCommit) > 7 {
		shortCommit = commit[:7]
	}

	lg.Info(
		"starting",
		"version", version,
		"commit", shortCommit,
		"go_version", getGoVersion(),
		"build_date", date,
		"addr", cfg.Addr,
		"buffer_size", cfg.BufferSize,
		"read_limit", cfg.ReadLimit,
		"sse_retry_ms", cfg.SERetryMs,
		"rate_rps", cfg.RateRPS,
		"rate_burst", cfg.RateBurst,
		"write_timeout", cfg.WriteTimeout,
	)

	return lg, nil
}
