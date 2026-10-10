// Package webui embeds the built SvelteKit SPA (web/build copied to dist/ by `make web`).
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the static file tree rooted at the SPA's index.html.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
