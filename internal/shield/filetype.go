package shield

import (
	"bytes"
	"path/filepath"
	"strings"
)

// FileClass drives the policy engine.
type FileClass string

const (
	ClassScript     FileClass = "script"
	ClassExecutable FileClass = "executable"
	ClassArchive    FileClass = "archive"
	ClassOther      FileClass = "other"
)

// FileType is the result of magic-byte detection.
type FileType struct {
	Kind      string    `json:"kind"` // php, shell, elf, zip, gzip, tar, png, jpeg, gif, pdf, text, unknown
	Class     FileClass `json:"class"`
	ExtKind   string    `json:"ext_kind,omitempty"`  // what the extension claims
	Disguised bool      `json:"disguised,omitempty"` // content kind contradicts the extension (e.g. PHP in .jpg)
}

var scriptExts = map[string]bool{".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true,
	".phps": true, ".phar": true, ".pht": true, ".inc": true, ".pl": true, ".py": true, ".cgi": true, ".sh": true, ".bash": true,
	".asp": true, ".aspx": true, ".jsp": true, ".rb": true}

var imageExts = map[string]string{".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp", ".ico": "ico", ".bmp": "bmp", ".svg": "svg"}

func extKind(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if k, ok := imageExts[ext]; ok {
		return k
	}
	if scriptExts[ext] {
		return "script"
	}
	switch ext {
	case ".zip", ".jar":
		return "zip"
	case ".gz", ".tgz":
		return "gzip"
	case ".tar":
		return "tar"
	case ".pdf":
		return "pdf"
	}
	return ""
}

// IsImageName reports whether the name has an image extension.
func IsImageName(name string) bool {
	_, ok := imageExts[strings.ToLower(filepath.Ext(name))]
	return ok
}

// IsScriptName reports whether the name has a server-side script extension.
func IsScriptName(name string) bool { return scriptExts[strings.ToLower(filepath.Ext(name))] }

// ContainsPHPTag finds a PHP open tag ("<?php" or "<?=").
func ContainsPHPTag(b []byte) bool {
	return bytes.Contains(bytes.ToLower(b), []byte("<?php")) || bytes.Contains(b, []byte("<?="))
}

// DetectType classifies content by magic bytes; head should be the first
// few KiB (PHP-in-image is only searched for inside head).
func DetectType(head []byte, name string) FileType {
	ft := FileType{Kind: "unknown", Class: ClassOther, ExtKind: extKind(name)}
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		ft.Kind = "elf"
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		ft.Kind = "zip"
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		ft.Kind = "gzip"
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
		ft.Kind = "tar"
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		ft.Kind = "png"
	case bytes.HasPrefix(head, []byte{0xff, 0xd8, 0xff}):
		ft.Kind = "jpeg"
	case bytes.HasPrefix(head, []byte("GIF87a")) || bytes.HasPrefix(head, []byte("GIF89a")):
		ft.Kind = "gif"
	case bytes.HasPrefix(head, []byte("%PDF-")):
		ft.Kind = "pdf"
	case bytes.HasPrefix(head, []byte("#!")):
		ft.Kind = "shell"
		if bytes.Contains(firstLine(head), []byte("php")) {
			ft.Kind = "php"
		}
	case ContainsPHPTag(head):
		ft.Kind = "php"
	case isText(head):
		ft.Kind = "text"
	}
	// PHP hidden inside an image (polyglot GIF89a<?php ...)
	if (ft.Kind == "png" || ft.Kind == "jpeg" || ft.Kind == "gif") && ContainsPHPTag(head) {
		ft.Kind = "php"
		ft.Disguised = true
	}
	if ft.Kind == "php" && ft.ExtKind != "" && ft.ExtKind != "script" {
		ft.Disguised = true
	}
	if ft.Kind == "elf" && ft.ExtKind != "" {
		ft.Disguised = true
	}
	switch ft.Kind {
	case "php", "shell":
		ft.Class = ClassScript
	case "elf":
		ft.Class = ClassExecutable
	case "zip", "gzip", "tar":
		ft.Class = ClassArchive
	}
	if ft.Class == ClassOther && IsScriptName(name) {
		ft.Class = ClassScript
	}
	return ft
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

func isText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 9 || (c > 13 && c < 32) {
			bad++
		}
	}
	return bad*20 < len(b)
}
