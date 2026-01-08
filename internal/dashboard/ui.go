package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/*
var uiFiles embed.FS

// IndexHandler serves the embedded dashboard HTML/JS/CSS.
func IndexHandler() http.Handler {
	uiFS, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err) // Should never happen at runtime with valid embed
	}

	return http.FileServer(http.FS(uiFS))
}
