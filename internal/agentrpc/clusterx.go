// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 clusterx: PowerDNS primary/secondary cluster and signed plugins.
const (
	MClusterApply  = "cluster.apply"  // write pdns.d/bpanel-cluster.conf (backup, restart, health check, rollback) + zones kind Master + notify
	MPluginInstall = "plugin.install" // re-validate a plugin archive and install it under /usr/local/bpanel/plugins/<name>
	MPluginRemove  = "plugin.remove"  // delete /usr/local/bpanel/plugins/<name>
)

type ClusterApplyReq struct {
	Secondaries []string `json:"secondaries"` // IPs; empty = remove the managed config
	Zones       []string `json:"zones"`       // zones to switch to kind Master and notify
}

// ClusterApplyResult: status ok | not_installed.
type ClusterApplyResult struct {
	Status     string            `json:"status"`
	Reason     string            `json:"reason,omitempty"`
	ConfPath   string            `json:"conf_path,omitempty"`
	ZoneErrors map[string]string `json:"zone_errors,omitempty"`
	Notified   int               `json:"notified"`
}

type PluginInstallReq struct {
	Name    string `json:"name"`
	Archive []byte `json:"archive"` // the verified .tar.gz (base64 on the wire)
}

type PluginRemoveReq struct {
	Name string `json:"name"`
}

type PluginResult struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
}
