// SPDX-License-Identifier: Apache-2.0

// Command sign creates ed25519 key pairs and signed BPanel plugin archives.
//
//	go run ./examples/plugins/sign keygen -out mykey          # writes mykey (private, 0600) and mykey.pub (base64)
//	go run ./examples/plugins/sign pack -key mykey -dir examples/plugins/hello -out hello-1.0.0.tar.gz
//
// Paste the content of mykey.pub into Plugins -> Trusted signing keys, then
// upload the .tar.gz. The archive is validated with the same code the panel
// uses (internal/clusterx) before it is written.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cumabozkurt/bpanel/internal/clusterx"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: sign keygen -out NAME | sign pack -key NAME -dir PLUGIN_DIR -out FILE.tar.gz")
	}
	switch os.Args[1] {
	case "keygen":
		fl := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fl.String("out", "plugin-signing", "key file prefix")
		fl.Parse(os.Args[2:])
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("keygen: %v", err)
		}
		if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(*out+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("private key: %s\npublic key:  %s (key id %s)\n", *out, *out+".pub", clusterx.KeyID(pub))
	case "pack":
		fl := flag.NewFlagSet("pack", flag.ExitOnError)
		key := fl.String("key", "plugin-signing", "private key file (base64 seed)")
		dir := fl.String("dir", "", "plugin directory (plugin.json + ui/)")
		out := fl.String("out", "", "output .tar.gz")
		fl.Parse(os.Args[2:])
		if *dir == "" || *out == "" {
			die("pack needs -dir and -out")
		}
		b, err := os.ReadFile(*key)
		if err != nil {
			die("%v", err)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			die("%s is not a base64 ed25519 seed", *key)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		files := map[string][]byte{}
		err = filepath.WalkDir(*dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("%s: symlinks are not allowed", p)
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(*dir, p)
			rel = filepath.ToSlash(rel)
			if rel == clusterx.SignatureFile {
				return nil
			}
			data, err := os.ReadFile(p)
			files[rel] = data
			return err
		})
		if err != nil {
			die("%v", err)
		}
		files[clusterx.SignatureFile] = clusterx.Sign(files, priv)
		archive := clusterx.PackTarGz(files)
		got, m, err := clusterx.Load(archive)
		if err != nil {
			die("plugin rejected: %v", err)
		}
		if _, err := clusterx.Verify(got, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}); err != nil {
			die("signature check failed: %v", err)
		}
		if err := os.WriteFile(*out, archive, 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("%s %s: %d file(s) signed by key %s -> %s\n", m.Name, m.Version, len(files), clusterx.KeyID(priv.Public().(ed25519.PublicKey)), *out)
	default:
		die("unknown command %q", os.Args[1])
	}
}
