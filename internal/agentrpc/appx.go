// SPDX-License-Identifier: Apache-2.0

package agentrpc

import "github.com/cumabozkurt/bpanel/internal/appx"

// v0.4 appx: Application Manager (Node.js / Python), app installer and
// WordPress toolkit.
const (
	MAppxRuntimes     = "appx.runtimes"      // server-level: detected node/python binaries, systemd, WP-CLI
	MAppxAppApply     = "appx.app.apply"     // write unit drop-in + env, re-render the proxy of the given domains
	MAppxAppRemove    = "appx.app.remove"    // stop, drop the unit files, re-render the given domains
	MAppxAppCtl       = "appx.app.ctl"       // start|stop|restart|status (systemd only)
	MAppxAppLogs      = "appx.app.logs"      // journal tail (systemd only)
	MAppxAppDeps      = "appx.app.deps"      // npm install / pip install -r as the account, with a timeout
	MAppxInstall      = "appx.install"       // download a catalogue app, verify the pinned checksum, extract as the account
	MAppxWP           = "appx.wp"            // info|maintenance_on|maintenance_off|core_update
	MAppxWPCLIInstall = "appx.wpcli.install" // server-level: official WP-CLI phar, verified against its published sha512
)

type AppxRuntime struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type AppxRuntimesResult struct {
	Runtimes []AppxRuntime `json:"runtimes"`
	Systemd  bool          `json:"systemd"`
	WPCLI    bool          `json:"wpcli"`
	PHPCLI   bool          `json:"php_cli"`
}

// AppxDomain is one domain whose proxy locations are re-rendered: Proxies
// is the complete list for that domain after the change.
type AppxDomain struct {
	Vhost   Vhost        `json:"vhost"`
	Proxies []appx.Proxy `json:"proxies"`
}

type AppxAppApplyParams struct {
	User    string       `json:"user"`
	App     appx.App     `json:"app"`
	Domains []AppxDomain `json:"domains,omitempty"`
}

type AppxAppResult struct {
	Status  string `json:"status"` // applied | removed
	Systemd bool   `json:"systemd"`
	Unit    string `json:"unit"`
	Wired   bool   `json:"wired"`
}

type AppxAppRef struct {
	User    string       `json:"user"`
	ID      int64        `json:"id"`
	Action  string       `json:"action,omitempty"`
	Lines   int          `json:"lines,omitempty"`
	Domains []AppxDomain `json:"domains,omitempty"`
}

type AppxCtlResult struct {
	Active string `json:"active"`
	Sub    string `json:"sub"`
	PID    int    `json:"pid"`
}

type AppxOutput struct {
	Output string `json:"output"`
}

type AppxInstallParams struct {
	User string        `json:"user"`
	App  string        `json:"app"`
	Dest string        `json:"dest"` // relative to the home
	DB   appx.WPConfig `json:"db"`   // WordPress: written into wp-config.php
}

type AppxInstallResult struct {
	Version string `json:"version"`
	Files   int    `json:"files"`
	Config  bool   `json:"config"` // wp-config.php written
}

type AppxWPParams struct {
	User   string `json:"user"`
	Path   string `json:"path"` // relative to the home
	Action string `json:"action"`
}

type AppxWPResult struct {
	Version     string `json:"version"`
	Maintenance bool   `json:"maintenance"`
	WPCLI       bool   `json:"wpcli"`
	Output      string `json:"output,omitempty"`
}
