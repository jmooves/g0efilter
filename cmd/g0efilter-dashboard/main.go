// Package main is the entrypoint for g0efilter-dashboard.
package main

import (
	"fmt"
	"os"

	"github.com/g0lab/g0efilter/internal/dashboard"
)

var (
	// Set by GoReleaser via -ldflags.
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

func main() {
	err := dashboard.RunDashboard(os.Args, version, date, commit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
