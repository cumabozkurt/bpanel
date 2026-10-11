// Package version is stamped at build time with -ldflags "-X .../version.Version=...".
package version

var (
	Version = "1.2.1"
	Commit  = "dev"
)
