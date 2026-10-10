// Package backup is BPanel's restic integration layer (master spec §14):
// storage target adapters (local dir, SFTP, S3-compatible), retention policy,
// a backup-time file manifest and real restore verification.
//
// restic (BSD-2-Clause) is an external program run as a child process with
// exec.CommandContext and an argv; it is never linked into the Go binary.
//
// Secrets (repository password, S3 keys) only ever travel to restic through
// its environment (RESTIC_PASSWORD_FILE, AWS_*), never through argv, logs or
// error strings: every error returned by this package is passed through
// Runner.scrub, which removes every secret value the runner knows about.
package backup

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Target kinds.
const (
	KindLocal = "local"
	KindSFTP  = "sftp"
	KindS3    = "s3"
)

// Target describes where the restic repositories live. One repository per
// hosting account: <base>/<account>. Credentials are NOT part of Target;
// they come from Creds (root-only file / secret store).
type Target struct {
	Kind string `json:"kind"`
	// local: absolute directory.  sftp: absolute remote directory.
	// s3: optional key prefix inside the bucket.
	Path string `json:"path"`
	// sftp
	Host string `json:"host,omitempty"`
	User string `json:"user,omitempty"`
	Port int    `json:"port,omitempty"`
	// s3 (any S3-compatible endpoint: AWS, MinIO, Ceph RGW, Wasabi, B2-S3, R2 ...)
	Endpoint string `json:"endpoint,omitempty"` // https://s3.example.com
	Bucket   string `json:"bucket,omitempty"`
	Region   string `json:"region,omitempty"`
	// ObjectLock records that the bucket/credentials are append-only or have
	// S3 Object Lock enabled (documentation/UI only; enforced by the provider).
	ObjectLock bool `json:"object_lock,omitempty"`
}

var (
	accountRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)
	userRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	bucketRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	segRe     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ValidAccount reports whether name is a safe account/repository name.
func ValidAccount(name string) bool { return accountRe.MatchString(name) }

func cleanAbs(p string) (string, error) {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", errors.New("path must be absolute")
	}
	c := path.Clean(p)
	for _, seg := range strings.Split(strings.Trim(c, "/"), "/") {
		if seg == "" {
			continue
		}
		if !segRe.MatchString(seg) || seg == ".." {
			return "", fmt.Errorf("invalid path segment %q", seg)
		}
	}
	return c, nil
}

// Validate checks the target for well-formedness (no shell metacharacters,
// absolute paths, known kind).
func (t Target) Validate() error {
	switch t.Kind {
	case KindLocal:
		_, err := cleanAbs(t.Path)
		return err
	case KindSFTP:
		if !hostRe.MatchString(t.Host) || strings.Contains(t.Host, "..") {
			return errors.New("invalid sftp host")
		}
		if t.User != "" && !userRe.MatchString(t.User) {
			return errors.New("invalid sftp user")
		}
		if t.Port < 0 || t.Port > 65535 {
			return errors.New("invalid sftp port")
		}
		_, err := cleanAbs(t.Path)
		return err
	case KindS3:
		u, err := url.Parse(t.Endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" && u.Path != "/" || u.User != nil || u.RawQuery != "" {
			return errors.New("invalid s3 endpoint (want https://host[:port])")
		}
		if !bucketRe.MatchString(t.Bucket) {
			return errors.New("invalid s3 bucket")
		}
		if t.Path != "" {
			for _, seg := range strings.Split(strings.Trim(t.Path, "/"), "/") {
				if !segRe.MatchString(seg) || seg == ".." || seg == "." {
					return errors.New("invalid s3 prefix")
				}
			}
		}
		return nil
	}
	return fmt.Errorf("unknown target kind %q", t.Kind)
}

// RepoURL is the restic repository string for one account. It never contains
// credentials (S3 keys go into the environment, SSH keys in root's ssh config).
func (t Target) RepoURL(account string) (string, error) {
	if !ValidAccount(account) {
		return "", errors.New("invalid account name")
	}
	if err := t.Validate(); err != nil {
		return "", err
	}
	switch t.Kind {
	case KindLocal:
		p, _ := cleanAbs(t.Path)
		return filepath.Join(p, account), nil
	case KindSFTP:
		p, _ := cleanAbs(t.Path)
		host := t.Host
		if t.User != "" {
			host = t.User + "@" + host
		}
		if t.Port != 0 && t.Port != 22 {
			// sftp://user@host:port//abs/path (double slash = absolute path)
			return "sftp://" + host + ":" + strconv.Itoa(t.Port) + "/" + path.Join(p, account), nil
		}
		return "sftp:" + host + ":" + path.Join(p, account), nil
	case KindS3:
		u, _ := url.Parse(t.Endpoint)
		parts := []string{t.Bucket}
		if pre := strings.Trim(t.Path, "/"); pre != "" {
			parts = append(parts, pre)
		}
		parts = append(parts, account)
		return "s3:" + u.Scheme + "://" + u.Host + "/" + strings.Join(parts, "/"), nil
	}
	return "", errors.New("unreachable")
}

// Creds are the target credentials. Only the root agent reads them.
type Creds struct {
	S3AccessKey string `json:"s3_access_key,omitempty"`
	S3SecretKey string `json:"s3_secret_key,omitempty"`
}

// Env returns the environment entries carrying credentials for restic.
func (t Target) Env(c Creds) []string {
	var env []string
	if t.Kind == KindS3 {
		if c.S3AccessKey != "" {
			env = append(env, "AWS_ACCESS_KEY_ID="+c.S3AccessKey)
		}
		if c.S3SecretKey != "" {
			env = append(env, "AWS_SECRET_ACCESS_KEY="+c.S3SecretKey)
		}
		if t.Region != "" {
			env = append(env, "AWS_DEFAULT_REGION="+t.Region)
		}
	}
	return env
}

// secrets returns the secret values that must never appear in output.
func (c Creds) secrets() []string {
	var s []string
	for _, v := range []string{c.S3AccessKey, c.S3SecretKey} {
		if len(v) >= 4 {
			s = append(s, v)
		}
	}
	return s
}
