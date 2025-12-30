// Package main is the entrypoint for g0efilter-dashboard.
package main

import (
	"fmt"
	"os"

	"github.com/g0lab/g0efilter/internal/g0efilterdashboard"
)

func main() {
	err := g0efilterdashboard.Run(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
