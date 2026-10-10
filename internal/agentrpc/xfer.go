// SPDX-License-Identifier: Apache-2.0

package agentrpc

import (
	"encoding/json"

	"github.com/cumabozkurt/bpanel/internal/xfer"
)

// v0.4 xfer (spec §10): account transfer archives. Archives live only in the
// agent's xfer directory and are named by a generated basename, never a path.
const (
	MXferList        = "xfer.list"         // archives in the xfer directory
	MXferAnalyse     = "xfer.analyse"      // parse + verify an archive into an import model (read-only)
	MXferFetch       = "xfer.fetch"        // pull an archive from a remote host over SFTP
	MXferDelete      = "xfer.delete"       // remove an archive
	MXferRestoreHome = "xfer.restore_home" // extract the archive's home directory into the account's home
	MXferRestoreDB   = "xfer.restore_db"   // load one SQL dump into an existing <owner>_ database
	MXferExport      = "xfer.export"       // write a BPanel account archive
)

type XferArchiveRef struct {
	Archive string `json:"archive"`
}

type XferArchive struct {
	Name    string `json:"name"`
	Bytes   int64  `json:"bytes"`
	ModTime int64  `json:"mtime"`
}

type XferArchiveList struct {
	Archives []XferArchive `json:"archives"`
	Dir      string        `json:"dir"`
}

type XferAnalyseResult struct {
	Model xfer.Model `json:"model"`
	// MailHashes carries mailbox crypt hashes to the API only (the API never
	// returns them to a browser).
	MailHashes map[string]string `json:"mail_hashes,omitempty"`
}

type XferFetch struct {
	Remote       xfer.Remote `json:"remote"`
	Secret       string      `json:"secret"` // private key (auth=key) or password (auth=password)
	Archive      string      `json:"archive"`
	AllowPrivate bool        `json:"allow_private"`
	MaxBytes     int64       `json:"max_bytes"`
}

type XferFetchResult struct {
	Bytes int64 `json:"bytes"`
}

type XferRestoreHome struct {
	User    string `json:"user"`
	Archive string `json:"archive"`
	Prefix  string `json:"prefix"`
}

type XferRestoreDB struct {
	Owner   string `json:"owner"`
	Archive string `json:"archive"`
	Member  string `json:"member"`
	DB      string `json:"db"`
}

type XferRestoreResult struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

// XferBlob is a small generated member (zone text, mail config) added to an export.
type XferBlob struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type XferExport struct {
	User      string          `json:"user"`
	Archive   string          `json:"archive"`
	Databases []string        `json:"databases"`
	Blobs     []XferBlob      `json:"blobs"`
	Manifest  json.RawMessage `json:"manifest"` // xfer.Manifest without Files (filled in by the agent)
}

type XferExportResult struct {
	Archive string `json:"archive"`
	Bytes   int64  `json:"bytes"`
	Files   int    `json:"files"`
}
