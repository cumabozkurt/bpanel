package shield

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestBacktickInputCodeOnly(t *testing.T) {
	for s, want := range map[string]bool{
		"<?php echo `$_GET[c]`; ?>":           true,
		"  $o = `ls $_POST[\"d\"]`;":          true,
		"/**\n * Uses `$_POST` for the form.": false,
		"// see `$_GET` above":                false,
		"# `$_REQUEST['history']`":            false,
	} {
		got := false
		for _, id := range MatchHeuristics([]byte(s), "x.php") {
			got = got || id == "php_backtick_input"
		}
		if got != want {
			t.Errorf("%q: got %v want %v", s, got, want)
		}
	}
}

// BPANEL_WP_TREE=/path/to/wordpress runs every heuristic over WordPress core:
// none may fire (v1.0 quarantined 19 core files).
func TestHeuristicsCleanOnWordPress(t *testing.T) {
	root := os.Getenv("BPANEL_WP_TREE")
	if root == "" {
		t.Skip("BPANEL_WP_TREE not set")
	}
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".php" {
			return nil
		}
		b, _ := os.ReadFile(p)
		n++
		if ids := MatchHeuristics(b, filepath.Base(p)); len(ids) > 0 {
			t.Errorf("%s: %v", p, ids)
		}
		return nil
	})
	t.Logf("%d PHP files scanned", n)
}
