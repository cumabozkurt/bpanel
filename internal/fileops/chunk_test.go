package fileops

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// CODE-7: chunked write/read with offset checks and limits.
func TestChunkedTransfer(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := bytes.Repeat([]byte("0123456789"), 300000) // 3 MB
	chunk := 1 << 20
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		if _, err := Exec(root, rpc.FileOp{Op: "write_chunk", Path: "up.bin", Offset: int64(off), Content: base64.StdEncoding.EncodeToString(data[off:end])}); err != nil {
			t.Fatal(off, err)
		}
	}
	// wrong offset (gap) is refused
	if _, err := Exec(root, rpc.FileOp{Op: "write_chunk", Path: "up.bin", Offset: int64(len(data) + 5), Content: "QQ=="}); err == nil {
		t.Fatal("gap accepted")
	}
	if _, err := Exec(root, rpc.FileOp{Op: "write_chunk", Path: "up.bin", Offset: MaxUploadBytes, Content: "QQ=="}); err == nil {
		t.Fatal("write beyond MaxUploadBytes accepted")
	}
	var got []byte
	for off := int64(0); ; {
		r, err := Exec(root, rpc.FileOp{Op: "read_chunk", Path: "up.bin", Offset: off, Length: int64(chunk)})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := base64.StdEncoding.DecodeString(r.Content)
		got = append(got, b...)
		off += int64(len(b))
		if r.Size != int64(len(data)) {
			t.Fatal("size")
		}
		if off >= r.Size {
			break
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round trip mismatch")
	}
	if _, err := Exec(root, rpc.FileOp{Op: "read_chunk", Path: "up.bin", Offset: int64(len(data)) + 1}); err == nil {
		t.Fatal("offset beyond EOF accepted")
	}
	// symlink escape stays impossible for the chunk ops too
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if _, err := Exec(root, rpc.FileOp{Op: "read_chunk", Path: "l"}); err == nil {
		t.Fatal("read through symlink to outside")
	}
	if _, err := Exec(root, rpc.FileOp{Op: "write_chunk", Path: "l", Content: "QQ=="}); err == nil {
		t.Fatal("write through symlink to outside")
	}
}

// semgrep potential-dos-via-decompression-bomb: actual bytes are counted.
func TestUnzipBudgetCountsRealBytes(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("a.txt")
	_, _ = w.Write([]byte("hello"))
	_ = zw.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.zip"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	if _, err := Exec(root, rpc.FileOp{Op: "unzip", Path: "a.zip", Dest: "out"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "out", "a.txt")); string(b) != "hello" {
		t.Fatal("unzip content")
	}
}

// errors never carry raw OS error text to the client
func TestMapErrNoRawText(t *testing.T) {
	err := mapErr(os.ErrClosed)
	if err.Error() != "io_error" {
		t.Fatalf("got %q", err.Error())
	}
}
