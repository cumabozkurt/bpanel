# BOZKURT PANEL — build helpers. Requires Go 1.27+, Node 20+ and pnpm.
# SPDX-License-Identifier: Apache-2.0
VERSION ?= 1.2.1
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/cumabozkurt/bpanel/internal/version.Version=$(VERSION) -X github.com/cumabozkurt/bpanel/internal/version.Commit=$(COMMIT)
GOOS    ?= linux
ARCHES  ?= amd64 arm64
CMDS    := bpanel-api bpanel-agent bpanel bpanel-installer
# Reproducible archives (R2-WB-18): fixed mtime/order/owner in every tarball.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 1767225600)
TARFLAGS := --sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner

.PHONY: all web embed build dist release release-unsigned release-check release-keygen verify-release test test-installer validate-configs vet i18n dev clean openapi

# ---- release signing (SEC-10) -------------------------------------------------
# Releases are signed with minisign (https://jedisct1.github.io/minisign/).
# The PRIVATE key lives offline, never in this repository; the PUBLIC key is
# embedded in installer/install.sh (BPANEL_RELEASE_PUBKEY) and published as
# docs/release-key.pub. install.sh is served from get.bozkurtpanel.com / the git
# repository, the archives from GitHub Releases: two different origins.
#
# One-time setup (maintainer, on an offline or hardware-backed machine):
#   make release-keygen                 # creates $(MINISIGN_KEY) (password protected)
#   git add installer/install.sh docs/release-key.pub && git commit
# Every release:
#   make release VERSION=x.y.z          # builds, checksums and signs every archive
#   make verify-release VERSION=x.y.z   # re-checks each signature with install.sh's own verifier
#   upload dist/bpanel-x.y.z-linux-*.tar.gz and *.minisig to the GitHub release v x.y.z
#   publish installer/install.sh (with the key) at https://get.bozkurtpanel.com
# Key rotation: generate a new key, ship an install.sh with the new key, and
# keep signing with the old key until the old install.sh is out of circulation.
MINISIGN_KEY ?= $(HOME)/.minisign/bpanel-release.key
MINISIGN     ?= minisign

all: web embed build

web:            ## build the SvelteKit SPA
	cd web && pnpm install --frozen-lockfile && pnpm run i18n:check && pnpm run build

embed: ## copy the SPA into the Go embed directory
	rm -rf internal/webui/dist && cp -r web/build internal/webui/dist

build:          ## build all binaries for the host
	@mkdir -p bin
	for c in $(CMDS); do CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$c ./cmd/$$c || exit 1; done

dist:           ## cross-compile static linux binaries for every arch
	@for a in $(ARCHES); do rm -rf dist/linux-$$a; mkdir -p dist/linux-$$a; \
	  for c in $(CMDS); do CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$$a go build -trimpath -ldflags "$(LDFLAGS)" -o dist/linux-$$a/$$c ./cmd/$$c || exit 1; done; \
	  (cd dist/linux-$$a && sha256sum bpanel bpanel-api bpanel-agent bpanel-installer > SHA256SUMS); done

release: release-check dist   ## signed tarballs in the layout install.sh downloads
	@test -r "$(MINISIGN_KEY)" || { echo "release signing key $(MINISIGN_KEY) not found (make release-keygen, or MINISIGN_KEY=...)"; exit 1; }
	@! grep -q '^BPANEL_RELEASE_PUBKEY="UNSET"' installer/install.sh || { echo "installer/install.sh has no release public key: run make release-keygen first"; exit 1; }
	@for a in $(ARCHES); do n=bpanel-$(VERSION)-linux-$$a; rm -rf dist/$$n; mkdir -p dist/$$n; \
	  cp dist/linux-$$a/* installer/install.sh LICENSE NOTICE README.md dist/$$n/; \
	  (cd dist/$$n && rm -f SHA256SUMS && sha256sum bpanel bpanel-api bpanel-agent bpanel-installer > SHA256SUMS) || exit 1; \
	  $(MINISIGN) -S -s "$(MINISIGN_KEY)" -m dist/$$n/SHA256SUMS -x dist/$$n/SHA256SUMS.minisig \
	    -t "bpanel-release file:SHA256SUMS version:$(VERSION) arch:$$a" || exit 1; \
	  tar -C dist $(TARFLAGS) -cf - $$n | gzip -n -9 > dist/$$n.tar.gz || exit 1; \
	  $(MINISIGN) -S -s "$(MINISIGN_KEY)" -m dist/$$n.tar.gz -x dist/$$n.tar.gz.minisig \
	    -t "bpanel-release file:$$n.tar.gz version:$(VERSION)" || exit 1; \
	  (cd dist && sha256sum $$n.tar.gz > $$n.tar.gz.sha256); done
	@$(MAKE) --no-print-directory verify-release VERSION=$(VERSION)

release-unsigned: release-check dist ## UNSIGNED tarballs + .sha256 (what v1.x publishes until a release key exists)
	@for a in $(ARCHES); do n=bpanel-$(VERSION)-linux-$$a; rm -rf dist/$$n; mkdir -p dist/$$n; \
	  cp dist/linux-$$a/* installer/install.sh LICENSE NOTICE README.md dist/$$n/; \
	  (cd dist/$$n && rm -f SHA256SUMS && sha256sum bpanel bpanel-api bpanel-agent bpanel-installer > SHA256SUMS) || exit 1; \
	  tar -C dist $(TARFLAGS) -cf - $$n | gzip -n -9 > dist/$$n.tar.gz || exit 1; \
	  (cd dist && sha256sum $$n.tar.gz > $$n.tar.gz.sha256); done
	@cat dist/bpanel-$(VERSION)-linux-*.tar.gz.sha256

# R2-WB-18: refuse to sign a release whose version strings disagree (the
# install.sh inside would download another version than the archive holds),
# that lacks the embedded web UI, or that is built from a dirty tree.
release-check:
	@test -n "$(VERSION)" || { echo "VERSION is required"; exit 1; }
	@grep -q '^BPANEL_DEFAULT_VERSION="$(VERSION)"' installer/install.sh || { echo "installer/install.sh BPANEL_DEFAULT_VERSION is not $(VERSION)"; exit 1; }
	@grep -q 'Version = "$(VERSION)"' internal/version/version.go || { echo "internal/version Version is not $(VERSION)"; exit 1; }
	@grep -qE '^## v?$(VERSION)( |$$)' CHANGELOG.md || { echo "CHANGELOG.md has no $(VERSION) section"; exit 1; }
	@test -s internal/webui/dist/index.html || { echo "web UI not embedded: run make web embed first"; exit 1; }
	@test -z "$$(git status --porcelain 2>/dev/null)" || [ "$(ALLOW_DIRTY)" = 1 ] || { echo "working tree is dirty (ALLOW_DIRTY=1 to override)"; exit 1; }

release-keygen: ## create the minisign release key and embed its public half in install.sh
	@test ! -e "$(MINISIGN_KEY)" || { echo "$(MINISIGN_KEY) already exists; refusing to overwrite"; exit 1; }
	@mkdir -p "$$(dirname "$(MINISIGN_KEY)")" && chmod 700 "$$(dirname "$(MINISIGN_KEY)")"
	$(MINISIGN) -G -p docs/release-key.pub -s "$(MINISIGN_KEY)"
	@pub="$$(sed -n 2p docs/release-key.pub)"; \
	  sed -i "s|^BPANEL_RELEASE_PUBKEY=\".*\"|BPANEL_RELEASE_PUBKEY=\"$$pub\"|" installer/install.sh; \
	  grep -n '^BPANEL_RELEASE_PUBKEY=' installer/install.sh
	@echo "Back up $(MINISIGN_KEY) offline. Commit installer/install.sh and docs/release-key.pub."

verify-release: ## check every archive signature with the verifier embedded in install.sh
	@for a in $(ARCHES); do n=bpanel-$(VERSION)-linux-$$a; \
	  BPANEL_INSTALL_SH_LIB=1 BPANEL_VERIFY_WITH_OPENSSL=1 bash -c '. installer/install.sh; k=$$(pubkey) || exit 1; \
	    minisign_verify "dist/$$0.tar.gz" "dist/$$0.tar.gz.minisig" "$$k" "file:$$0.tar.gz" "version:$$1" && \
	    minisign_verify "dist/$$0/SHA256SUMS" "dist/$$0/SHA256SUMS.minisig" "$$k" "file:SHA256SUMS"' $$n $(VERSION) || exit 1; done

vet:
	go vet ./...

test:
	go test ./...

test-installer: ## installer unit tests + install.sh signature tests
	go test ./internal/installer/ ./cmd/bpanel-installer/
	bash installer/test/test-install-sh.sh

validate-configs: build ## check generated configs with nginx -t, apache2ctl, php-fpm -t, postfix check, sshd -t ... (root, scratch machine)
	sudo installer/test/validate-configs.sh bin/bpanel-installer

i18n:
	cd web && node scripts/check-i18n.mjs

dev:            ## run the API with the in-process mock agent (no root needed; dev build tag)
	go run -tags dev ./cmd/bpanel-api --dev --plain-http

openapi:        ## regenerate docs/openapi.json
	go run ./cmd/bpanel openapi > docs/openapi.json

clean:
	rm -rf bin dist web/build web/.svelte-kit
