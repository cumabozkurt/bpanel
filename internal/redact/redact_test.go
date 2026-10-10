package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const secret = "S3cr3t-Value-XYZ-123"

func TestString(t *testing.T) {
	in := []string{
		"Authorization: Bearer " + secret,
		`{"password":"` + secret + `","user":"bob"}`,
		"dsn=mysql://root:" + secret + "@localhost/x",
		"smtp_password=" + secret + "&x=1",
		"token bpt_" + secret,
		"-----BEGIN RSA PRIVATE KEY-----\n" + secret + "\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\n" + secret,
		"bpsec:v1:k1:" + secret + ":abc",
		`{"recovery_code":"` + secret + `"}`,
	}
	for _, s := range in {
		if out := String(s); strings.Contains(out, secret) {
			t.Errorf("leak: %q -> %q", s, out)
		}
	}
	if String("user=bob ip=1.2.3.4") != "user=bob ip=1.2.3.4" {
		t.Fatal("over-redaction")
	}
}

func TestHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewTextHandler(&buf, nil)))
	log.Info("login "+"Authorization: Bearer "+secret, "password", secret, "Authorization", "Bearer "+secret,
		"err", errors.New("dial: password="+secret), "nested", slog.Group("g", "api_key", secret, "msg", "x token="+secret),
		"totp_required", true, "user", "bob")
	log.With("secret", secret).Warn("x")
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret in log: %s", out)
	}
	if !strings.Contains(out, "user=bob") || !strings.Contains(out, "totp_required=true") {
		t.Fatalf("too much removed: %s", out)
	}
}
