# Contributing to BOZKURT PANEL

Thank you for helping! BPANEL is Apache-2.0 licensed; by sending a contribution you agree that it is
licensed under the same terms.

## Ground rules

- **Free software only.** No paid component, licence key or paid API may be required
  (`docs/architecture.md` §3). New third-party components go into `docs/third-party-licenses.md`.
- **The root agent stays small and typed.** New privileged work is a new typed agent action with
  strict parameter decoding and validation; external programs run as argv, never through a shell,
  and there is no generic "run command" action.
- **Never fake success.** A feature whose engine is missing answers `not_installed` / `unsupported`
  with a reason.
- **Both languages.** Every UI string and error code exists in `web/src/lib/i18n/locales/en.json`
  and `tr.json` (`make i18n` checks it).
- Report security issues privately — see [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Go 1.27+ (the toolchain in `go.mod` is fetched automatically with `GOTOOLCHAIN=auto`),
Node 20+, pnpm 10.

```bash
git clone https://github.com/cumabozkurt/bpanel.git && cd bpanel
make web embed       # build the SvelteKit SPA into internal/webui/dist
make dev             # API + mock agent on http://127.0.0.1:2083 (user) and :2087 (admin)
```

Dev logins: admin `bpadmin` / `Demo-Pass-2026` (2087), user `demo` / `Demo-User-2026` (2083).
For UI work run `cd web && pnpm dev` next to `make dev` (Vite proxies `/api` to :2083).

## Before you open a pull request

```bash
gofmt -l . | grep -v '^web/'          # must print nothing
make vet test                         # go vet + go test ./...
go test -race ./...                   # when you touched concurrent code
make test-installer                   # when you touched internal/installer or installer/
make i18n                             # when you touched UI strings or error codes
make openapi                          # when you added or changed a route (a test checks it)
make web embed                        # when you changed web/ (commit internal/webui/dist too)
```

- Keep pull requests focused; describe what changed and how you tested it.
- Add or update tests (`*_test.go`; fuzz targets for parsers of untrusted input).
- Update the docs in `docs/` and add a line to `CHANGELOG.md` under an "Unreleased" heading.
- `packaging/` mirrors files the installer generates; a test keeps them identical.

## Release process (maintainers)

1. Bump `internal/version/version.go`, `Makefile` `VERSION`, `installer/install.sh`
   `BPANEL_DEFAULT_VERSION`, `web/package.json`; add the CHANGELOG section; `make openapi`.
2. `make web embed vet test test-installer`.
3. `make release VERSION=x.y.z` (signs with the offline minisign key) and `make verify-release`.
4. Tag `vx.y.z`, upload `dist/bpanel-x.y.z-linux-*.tar.gz*` to the GitHub release.
