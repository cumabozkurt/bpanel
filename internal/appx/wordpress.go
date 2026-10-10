// SPDX-License-Identifier: Apache-2.0

package appx

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var (
	dbIdentRe  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	prefixRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,14}_$`)
	wpVersionR = regexp.MustCompile(`\$wp_version\s*=\s*'([0-9][0-9A-Za-z.\-]{0,30})'`)
)

// WP-CLI official build: https://github.com/wp-cli/builds (phar + .sha512).
const (
	WPCLIPharURL   = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
	WPCLISHA512URL = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar.sha512"
	WPCLIPath      = "/usr/local/lib/bpanel/wp-cli.phar"
)

// saltChars are the characters WordPress' own secret-key service uses,
// minus ' and \ so the value is a plain single-quoted PHP string.
const saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_[]{}<>~`+=,.;:/?|"

// RandomString draws n characters from alphabet with crypto/rand.
func RandomString(n int, alphabet string) (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[x.Int64()])
	}
	return b.String(), nil
}

// WPConfig is what wp-config.php needs.
type WPConfig struct {
	DBName, DBUser, DBPassword, DBHost, TablePrefix string
}

func phpQuoteOK(s string) bool { return !strings.ContainsAny(s, `'\`+"\x00\r\n") }

// RenderWPConfig renders wp-config.php with 8 fresh 64-char salts.
func RenderWPConfig(c WPConfig) (string, error) {
	if c.DBHost == "" {
		c.DBHost = "localhost"
	}
	if c.TablePrefix == "" {
		c.TablePrefix = "wp_"
	}
	if !dbIdentRe.MatchString(c.DBName) || !dbIdentRe.MatchString(c.DBUser) || !prefixRe.MatchString(c.TablePrefix) ||
		!phpQuoteOK(c.DBPassword) || !phpQuoteOK(c.DBHost) || len(c.DBHost) > 255 {
		return "", errf("appx_invalid", "invalid database settings for wp-config.php")
	}
	var b strings.Builder
	b.WriteString("<?php\n// Written by BOZKURT PANEL App Installer. Salts generated with crypto/rand.\n")
	fmt.Fprintf(&b, "define( 'DB_NAME', '%s' );\ndefine( 'DB_USER', '%s' );\ndefine( 'DB_PASSWORD', '%s' );\n", c.DBName, c.DBUser, c.DBPassword)
	fmt.Fprintf(&b, "define( 'DB_HOST', '%s' );\ndefine( 'DB_CHARSET', 'utf8mb4' );\ndefine( 'DB_COLLATE', '' );\n\n", c.DBHost)
	for _, k := range []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"} {
		s, err := RandomString(64, saltChars)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "define( '%s', '%s' );\n", k, s)
	}
	fmt.Fprintf(&b, "\n$table_prefix = '%s';\n\ndefine( 'WP_DEBUG', false );\ndefine( 'DISALLOW_FILE_EDIT', true );\n\n", c.TablePrefix)
	b.WriteString("if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n\nrequire_once ABSPATH . 'wp-settings.php';\n")
	return b.String(), nil
}

// ParseWPVersion extracts $wp_version from wp-includes/version.php.
func ParseWPVersion(src []byte) string {
	if m := wpVersionR.FindSubmatch(src); m != nil {
		return string(m[1])
	}
	return ""
}

// MaintenanceFile is the .maintenance content WP-CLI's maintenance-mode
// writes: time() is evaluated on every request, so WordPress' 10-minute
// stale-file cut-off never ends the maintenance until the file is removed.
func MaintenanceFile() []byte { return []byte("<?php $upgrading = time(); ?>\n") }
