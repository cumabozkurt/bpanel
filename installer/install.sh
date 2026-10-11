#!/usr/bin/env bash
# BOZKURT PANEL (BPANEL) bootstrap installer.
# SPDX-License-Identifier: Apache-2.0
#
#   curl -fsSL https://github.com/cumabozkurt/bpanel/releases/latest/download/install.sh | sudo bash
#   curl -fsSL https://github.com/cumabozkurt/bpanel/releases/latest/download/install.sh | sudo bash -s -- \
#        --hostname panel.example.com --email admin@example.com --profile full --lang en --yes
#   curl -fsSL https://github.com/cumabozkurt/bpanel/releases/latest/download/install.sh | sudo bash -s -- upgrade     # existing server
#
# (https://get.bozkurtpanel.com will serve the same script once that host is online.)
#
# Running the installer on a server with an older BOZKURT PANEL upgrades it
# (binaries, hardening, configuration, database migrations); `upgrade` does
# the same explicitly and re-applies an up-to-date installation.
#
# This script only downloads and VERIFIES the static Go installer, then hands
# over to it (`bpanel-installer install "$@"`). All real work, which is staged
# and resumable, happens in bpanel-installer.
#
# Trust model (SEC-10): this script is served from get.bozkurtpanel.com (or
# the git repository) and carries the release public key below. The release
# archives come from a different origin (GitHub Releases or a mirror). Every
# archive has a detached minisign signature made with the offline release key;
# its trusted comment names the file and the version, so a mirror can neither
# alter an archive nor pass off an older signed release as a newer one.
# Compromising the download host alone is therefore not enough.
#
# Verification uses `minisign` when installed, otherwise OpenSSL 3 (present on
# Ubuntu 24.04 and AlmaLinux 9): Ed25519 over the file, or over its BLAKE2b-512
# hash for prehashed ("ED") signatures, plus the trusted-comment signature.
#
# If bpanel-installer, bpanel-api, bpanel-agent and bpanel already sit next to
# this script (an unpacked release archive), they are used after checking
# SHA256SUMS against SHA256SUMS.minisig; nothing is downloaded.
#
# Environment overrides:
#   BPANEL_VERSION      release to install (default below)
#   BPANEL_BASE_URL     where release archives live; <base>/<version>/<file>
#                       (default: GitHub Releases, https://github.com/cumabozkurt/bpanel/releases/download/v<version>)
#   BPANEL_PUBKEY       a different minisign public key (own builds/mirrors)
#   BPANEL_ALLOW_UNSIGNED=1  run an UNSIGNED local build (development only)
set -euo pipefail

BPANEL_DEFAULT_VERSION="1.2.1"
# Release signing public key (minisign). Set by `make release-keygen`; the
# private key never enters the repository. "UNSET" makes this script refuse
# to install anything (fail closed).
BPANEL_RELEASE_PUBKEY="RWRYNqiQUKrmEa/dZKHRQ5gTv0kDzO3ftQbvQS4RyllwlLS0C/vbPMWx"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- minisign --

# hex FILE: lowercase hex of a binary file
hex() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# minisign_verify FILE SIGFILE PUBKEY EXPECTED...
# Verifies a minisign signature and that the trusted comment contains every
# EXPECTED word. Prints the trusted comment. Returns non-zero on any failure.
minisign_verify() {
  local file="$1" sigfile="$2" pubkey="$3"; shift 3
  local tc
  [ -s "$file" ] && [ -s "$sigfile" ] || { echo "missing file or signature" >&2; return 1; }
  [ "$(sed -n 1p "$sigfile" | cut -c1-19)" = "untrusted comment: " ] || { echo "not a minisign signature" >&2; return 1; }
  tc="$(sed -n 3p "$sigfile")"
  [ "${tc#trusted comment: }" != "$tc" ] || { echo "signature has no trusted comment" >&2; return 1; }
  tc="${tc#trusted comment: }"

  if [ -z "${BPANEL_VERIFY_WITH_OPENSSL:-}" ] && command -v minisign >/dev/null 2>&1; then
    minisign -V -q -P "$pubkey" -m "$file" -x "$sigfile" >/dev/null || return 1
  else
    command -v openssl >/dev/null 2>&1 || { echo "neither minisign nor openssl is available" >&2; return 1; }
    local d; d="$(mktemp -d)"
    (
      set -e
      printf '%s' "$pubkey" | base64 -d > "$d/pk" 2>/dev/null
      sed -n 2p "$sigfile" | base64 -d > "$d/sig" 2>/dev/null
      sed -n 4p "$sigfile" | base64 -d > "$d/gsig" 2>/dev/null
      [ "$(wc -c < "$d/pk")" -eq 42 ] && [ "$(wc -c < "$d/sig")" -eq 74 ] && [ "$(wc -c < "$d/gsig")" -eq 64 ] || { echo "malformed key or signature" >&2; exit 1; }
      head -c 2 "$d/pk" > "$d/pkalg"; [ "$(cat "$d/pkalg")" = "Ed" ] || { echo "unsupported key algorithm" >&2; exit 1; }
      tail -c +3 "$d/pk" | head -c 8 > "$d/pkid"
      tail -c 32 "$d/pk" > "$d/pkraw"
      head -c 2 "$d/sig" > "$d/alg"
      tail -c +3 "$d/sig" | head -c 8 > "$d/sigid"
      tail -c 64 "$d/sig" > "$d/sig64"
      [ "$(hex "$d/pkid")" = "$(hex "$d/sigid")" ] || { echo "signed with a different key" >&2; exit 1; }
      # SubjectPublicKeyInfo for Ed25519 = fixed 12-byte DER prefix + raw key
      { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; cat "$d/pkraw"; } > "$d/pk.der"
      openssl pkey -pubin -inform DER -in "$d/pk.der" -out "$d/pk.pem" 2>/dev/null
      case "$(cat "$d/alg")" in
        Ed) cp "$file" "$d/msg" ;;                                          # legacy: signs the file
        ED) openssl dgst -blake2b512 -binary "$file" > "$d/msg" ;;          # prehashed (minisign >= 0.11 default)
        *)  echo "unsupported signature algorithm" >&2; exit 1 ;;
      esac
      openssl pkeyutl -verify -pubin -inkey "$d/pk.pem" -rawin -in "$d/msg" -sigfile "$d/sig64" >/dev/null 2>&1 \
        || { echo "signature does not match the file" >&2; exit 1; }
      { cat "$d/sig64"; printf '%s' "$tc"; } > "$d/gmsg"
      openssl pkeyutl -verify -pubin -inkey "$d/pk.pem" -rawin -in "$d/gmsg" -sigfile "$d/gsig" >/dev/null 2>&1 \
        || { echo "trusted comment signature is invalid" >&2; exit 1; }
    ) || { rm -rf "$d"; return 1; }
    rm -rf "$d"
  fi
  local w
  for w in "$@"; do
    case " $tc " in *" $w "*) ;; *) echo "trusted comment '$tc' does not contain '$w'" >&2; return 1 ;; esac
  done
  printf '%s\n' "$tc"
}

pubkey() {
  local k="${BPANEL_PUBKEY:-$BPANEL_RELEASE_PUBKEY}"
  if [ "$k" = "UNSET" ] || [ -z "$k" ]; then
    return 1
  fi
  printf '%s' "$k"
}

# ----------------------------------------------------------------- main ----

main() {
  local BPANEL_VERSION="${BPANEL_VERSION:-$BPANEL_DEFAULT_VERSION}"
  local BPANEL_BASE_URL="${BPANEL_BASE_URL:-https://github.com/cumabozkurt/bpanel/releases/download/v$BPANEL_VERSION}"
  local ARCH HERE NAME WORK KEY SUB=install
  case "${1:-}" in
    install|upgrade) SUB="$1"; shift ;;
  esac

  [ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"

  # --- operating system -----------------------------------------------------
  [ -r /etc/os-release ] || die "/etc/os-release not found"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.04|almalinux:9*|rocky:9*|rhel:9*) ;;
    *)
      case " $* " in
        *" --allow-unsupported "*) say "unsupported OS ${PRETTY_NAME:-unknown}; continuing because --allow-unsupported was given" ;;
        *) die "supported: Ubuntu 24.04 LTS, AlmaLinux 9 (found ${PRETTY_NAME:-unknown}). Use --allow-unsupported to try anyway." ;;
      esac ;;
  esac

  # --- architecture ---------------------------------------------------------
  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac

  # --- local release archive? -----------------------------------------------
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)"
  if [ -x "$HERE/bpanel-installer" ] && [ -x "$HERE/bpanel-api" ] && [ -x "$HERE/bpanel-agent" ] && [ -x "$HERE/bpanel" ]; then
    if [ -s "$HERE/SHA256SUMS.minisig" ] && KEY="$(pubkey)"; then
      minisign_verify "$HERE/SHA256SUMS" "$HERE/SHA256SUMS.minisig" "$KEY" "file:SHA256SUMS" >/dev/null \
        || die "SHA256SUMS signature check failed; refusing to run these binaries"
      ( cd "$HERE" && sha256sum -c --status SHA256SUMS ) || die "binary checksum mismatch; refusing to continue"
      say "signature and checksums verified; using binaries in $HERE"
    elif [ "${BPANEL_ALLOW_UNSIGNED:-}" = 1 ]; then
      warn "running UNSIGNED binaries from $HERE (BPANEL_ALLOW_UNSIGNED=1)"
    else
      die "the binaries in $HERE are not signed (no SHA256SUMS.minisig or no release key in this script). Set BPANEL_ALLOW_UNSIGNED=1 only for your own development builds."
    fi
    # Keep a copy so upgrade/uninstall work without this archive (R2-SYS-17).
    install -d -m 0755 /usr/local/lib/bpanel
    local b
    for b in bpanel-installer bpanel-api bpanel-agent bpanel; do
      [ "$HERE/$b" -ef "/usr/local/lib/bpanel/$b" ] || install -m 0755 "$HERE/$b" /usr/local/lib/bpanel/
    done
    ln -sfn /usr/local/lib/bpanel/bpanel-installer /usr/local/sbin/bpanel-installer
    exec /usr/local/lib/bpanel/bpanel-installer "$SUB" --bin-dir /usr/local/lib/bpanel "$@"
  fi

  KEY="$(pubkey)" || die "this install.sh carries no release public key (BPANEL_RELEASE_PUBKEY is UNSET); download the official script from https://github.com/cumabozkurt/bpanel/releases/latest/download/install.sh"

  # --- prerequisites --------------------------------------------------------
  if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1 \
     || { ! command -v minisign >/dev/null 2>&1 && ! command -v openssl >/dev/null 2>&1; }; then
    say "installing curl, tar, openssl and ca-certificates"
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq curl ca-certificates tar coreutils openssl
    else
      dnf -y -q install curl ca-certificates tar coreutils openssl
    fi
  fi

  # --- download and verify --------------------------------------------------
  NAME="bpanel-${BPANEL_VERSION}-linux-${ARCH}"
  WORK="$(mktemp -d /tmp/bpanel-install.XXXXXX)"
  # shellcheck disable=SC2064
  trap "rm -rf '$WORK'" EXIT
  say "downloading BOZKURT PANEL ${BPANEL_VERSION} (linux-${ARCH})"
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$WORK/$NAME.tar.gz"         "$BPANEL_BASE_URL/$NAME.tar.gz"
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$WORK/$NAME.tar.gz.minisig" "$BPANEL_BASE_URL/$NAME.tar.gz.minisig"
  say "verifying the release signature"
  minisign_verify "$WORK/$NAME.tar.gz" "$WORK/$NAME.tar.gz.minisig" "$KEY" "file:$NAME.tar.gz" "version:$BPANEL_VERSION" >/dev/null \
    || die "signature check failed for $NAME.tar.gz; refusing to continue"
  tar -xzf "$WORK/$NAME.tar.gz" -C "$WORK" --no-same-owner
  ( cd "$WORK/$NAME" && sha256sum -c --status SHA256SUMS ) || die "binary checksum mismatch; refusing to continue"

  # Keep the binaries in a stable place so `bpanel-installer uninstall` can be run later.
  install -d -m 0755 /usr/local/lib/bpanel
  install -m 0755 "$WORK/$NAME"/bpanel-installer "$WORK/$NAME"/bpanel-api "$WORK/$NAME"/bpanel-agent "$WORK/$NAME"/bpanel /usr/local/lib/bpanel/
  ln -sfn /usr/local/lib/bpanel/bpanel-installer /usr/local/sbin/bpanel-installer

  exec /usr/local/lib/bpanel/bpanel-installer "$SUB" --bin-dir /usr/local/lib/bpanel "$@"
}

# The whole script is parsed before anything runs, so a truncated download
# (curl | bash) cannot execute half a script. Tests source it with
# BPANEL_INSTALL_SH_LIB=1 to call minisign_verify directly.
if [ "${BPANEL_INSTALL_SH_LIB:-}" != 1 ]; then
  main "$@"
fi
