package installer

import (
	"os"
	"path/filepath"
	"testing"
)

// go test -run TestWritePackaging -args -write  (regenerates packaging/)
func TestWritePackaging(t *testing.T) {
	if os.Getenv("BPANEL_WRITE_PACKAGING") != "1" {
		t.Skip("set BPANEL_WRITE_PACKAGING=1 to regenerate packaging/")
	}
	for name, content := range packagedFiles() {
		p := filepath.Join("..", "..", "packaging", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
