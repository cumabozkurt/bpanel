// Package templates embeds the versioned configuration templates the agent
// and installer render. Bump Version when a template changes so the agent
// knows to regenerate managed files.
package templates

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"

	"github.com/cumabozkurt/bpanel/internal/validate"
)

// Version 2: quoted paths, the "safe" guard on every interpolation,
// nginx disable_symlinks and no Apache "AllowOverride All" (SEC-1, SEC-4).
const Version = 2

//go:embed nginx apache php-fpm suspended
var FS embed.FS

// safe refuses any value that could break out of a configuration token
// (newline, quote, brace, semicolon, '$', backslash, whitespace, '#').
// Every value a template interpolates goes through it, so even a validation
// bug upstream cannot inject directives (defence in depth for SEC-1/CODE-1).
func safe(v any) (string, error) {
	s := fmt.Sprint(v)
	if !validate.ConfigSafe(s) {
		return "", fmt.Errorf("unsafe value %q refused by template", s)
	}
	return s, nil
}

var tpl = template.Must(template.New("").Funcs(template.FuncMap{"safe": safe}).
	ParseFS(FS, "nginx/*.tmpl", "apache/*.tmpl", "php-fpm/*.tmpl"))

// Render executes the named template (file base name) with data.
func Render(name string, data any) ([]byte, error) {
	var b bytes.Buffer
	if err := tpl.ExecuteTemplate(&b, name, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
