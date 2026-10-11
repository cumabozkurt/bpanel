// SPDX-License-Identifier: Apache-2.0

// Package sitepub is the Site Publisher: a handful of free, self-contained
// one-page templates (no external assets, no JavaScript) rendered with
// html/template, so every user-supplied field is escaped.
package sitepub

import (
	"bytes"
	"fmt"
	"html/template"
	"net/mail"
	"regexp"
	"strings"
)

// Fields are the values a template uses; all are optional except Title.
type Fields struct {
	Title   string `json:"title"`
	Tagline string `json:"tagline"`
	About   string `json:"about"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
	Accent  string `json:"accent"` // #rrggbb
}

// Template describes one layout.
type Template struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // business | personal | maintenance | coming_soon
}

var Templates = []Template{
	{ID: "business", Name: "Business card", Kind: "business"},
	{ID: "personal", Name: "Personal page", Kind: "personal"},
	{ID: "maintenance", Name: "Under maintenance", Kind: "maintenance"},
	{ID: "coming_soon", Name: "Launch page", Kind: "coming_soon"},
}

type Error struct{ Code, Field string }

func (e *Error) Error() string { return e.Code + ": " + e.Field }

var (
	reAccent = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	rePhone  = regexp.MustCompile(`^[0-9+() .-]{3,40}$`)
)

// Validate checks the fields and fills defaults.
func (f *Fields) Validate() error {
	trim := func(s *string, max int, field string) error {
		*s = strings.TrimSpace(*s)
		if len(*s) > max {
			return &Error{Code: "site_field_too_long", Field: field}
		}
		return nil
	}
	for _, x := range []struct {
		p     *string
		max   int
		field string
	}{{&f.Title, 120, "title"}, {&f.Tagline, 200, "tagline"}, {&f.About, 4000, "about"}, {&f.Email, 254, "email"}, {&f.Phone, 40, "phone"}, {&f.Address, 300, "address"}} {
		if err := trim(x.p, x.max, x.field); err != nil {
			return err
		}
	}
	if f.Title == "" {
		return &Error{Code: "site_title_required", Field: "title"}
	}
	if f.Email != "" {
		if a, err := mail.ParseAddress(f.Email); err != nil || a.Address != f.Email {
			return &Error{Code: "invalid_email", Field: "email"}
		}
	}
	if f.Phone != "" && !rePhone.MatchString(f.Phone) {
		return &Error{Code: "invalid_phone", Field: "phone"}
	}
	if f.Accent == "" {
		f.Accent = "#2563eb"
	}
	if !reAccent.MatchString(f.Accent) {
		return &Error{Code: "invalid_color", Field: "accent"}
	}
	return nil
}

const page = `<!doctype html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="BOZKURT PANEL Site Publisher">
<title>{{.F.Title}}</title>
<style>
:root{--a:{{.Accent}}}
*{box-sizing:border-box}body{margin:0;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1f2937;background:#f8fafc}
main{max-width:760px;margin:0 auto;padding:12vh 24px 48px}
h1{font-size:clamp(2rem,5vw,3rem);line-height:1.15;margin:0 0 .4em;color:#0f172a}
.tag{font-size:1.2rem;color:#475569;margin:0 0 2em}
.badge{display:inline-block;background:var(--a);color:#fff;border-radius:999px;padding:.25em .9em;font-size:.85rem;margin-bottom:1.2em}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;margin:0 0 20px}
.about{white-space:pre-line}
a{color:var(--a)}dl{display:grid;grid-template-columns:auto 1fr;gap:.4em 1.2em;margin:0}dt{color:#64748b}dd{margin:0}
footer{margin-top:40px;color:#94a3b8;font-size:.85rem}
</style>
</head>
<body>
<main>
{{if .Badge}}<span class="badge">{{.Badge}}</span>{{end}}
<h1>{{.F.Title}}</h1>
{{if .F.Tagline}}<p class="tag">{{.F.Tagline}}</p>{{end}}
{{if .F.About}}<section class="card about">{{.F.About}}</section>{{end}}
{{if or .F.Email .F.Phone .F.Address}}<section class="card"><dl>
{{if .F.Email}}<dt>{{.L.Email}}</dt><dd><a href="mailto:{{.F.Email}}">{{.F.Email}}</a></dd>{{end}}
{{if .F.Phone}}<dt>{{.L.Phone}}</dt><dd>{{.F.Phone}}</dd>{{end}}
{{if .F.Address}}<dt>{{.L.Address}}</dt><dd>{{.F.Address}}</dd>{{end}}
</dl></section>{{end}}
<footer>© {{.F.Title}}</footer>
</main>
</body>
</html>
`

var tpl = template.Must(template.New("page").Parse(page))

// Render returns the index.html of template id in lang ("en" or "tr").
func Render(id, lang string, f Fields) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	var kind string
	for _, t := range Templates {
		if t.ID == id {
			kind = t.Kind
		}
	}
	if kind == "" {
		return nil, &Error{Code: "site_template_unknown", Field: "template"}
	}
	if lang != "tr" {
		lang = "en"
	}
	labels := map[string]map[string]string{
		"en": {"Email": "Email", "Phone": "Phone", "Address": "Address", "maintenance": "Under maintenance", "coming_soon": "Coming soon"},
		"tr": {"Email": "E-posta", "Phone": "Telefon", "Address": "Adres", "maintenance": "Bakımdayız", "coming_soon": "Çok yakında"},
	}[lang]
	var b bytes.Buffer
	err := tpl.Execute(&b, map[string]any{"Lang": lang, "F": f, "Accent": template.CSS(f.Accent), "Badge": labels[kind],
		"L": map[string]string{"Email": labels["Email"], "Phone": labels["Phone"], "Address": labels["Address"]}})
	if err != nil {
		return nil, fmt.Errorf("sitepub: %w", err)
	}
	return b.Bytes(), nil
}
