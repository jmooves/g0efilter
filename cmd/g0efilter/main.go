// Package main is the entrypoint for g0efilter.
package main

import (
	"fmt"
	"os"

	"github.com/g0lab/g0efilter/internal/g0efilter"
)

func main() {
	if g0efilter.HandleVersionFlag(os.Args) {
		return
	}

	err := g0efilter.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
