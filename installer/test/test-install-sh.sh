#!/usr/bin/env bash
# Tests the signature verification in installer/install.sh (SEC-10) with both
# verifiers (minisign and the OpenSSL fallback), prehashed and legacy
# signatures, and the failure cases. Needs minisign and openssl.
#   installer/test/test-install-sh.sh
# With root it also runs install.sh end-to-end on a fake local release archive.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../install.sh"
command -v minisign >/dev/null && command -v openssl >/dev/null || { echo "SKIP: needs minisign and openssl"; exit 0; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAILS=0
ok()  { printf '  PASS %s\n' "$*"; }
bad() { printf '  FAIL %s\n' "$*"; FAILS=$((FAILS+1)); }

minisign -G -W -f -p "$T/k.pub" -s "$T/k.key" >/dev/null 2>&1
minisign -G -W -f -p "$T/other.pub" -s "$T/other.key" >/dev/null 2>&1
PUB="$(sed -n 2p "$T/k.pub")"; OTHER="$(sed -n 2p "$T/other.pub")"
head -c 300000 /dev/urandom > "$T/bpanel-9.9.9-linux-amd64.tar.gz"
F="$T/bpanel-9.9.9-linux-amd64.tar.gz"
minisign -S -s "$T/k.key" -m "$F" -x "$F.minisig" -t "bpanel-release file:bpanel-9.9.9-linux-amd64.tar.gz version:9.9.9" >/dev/null 2>&1
cp "$F" "$T/legacy.bin"
minisign -S -l -s "$T/k.key" -m "$T/legacy.bin" -x "$T/legacy.bin.minisig" -t "bpanel-release file:legacy.bin version:9.9.9" >/dev/null 2>&1

# shellcheck disable=SC1090
BPANEL_INSTALL_SH_LIB=1 . "$SCRIPT"
set +e  # install.sh enables errexit; the tests expect failures
for mode in minisign openssl; do
  if [ "$mode" = openssl ]; then export BPANEL_VERIFY_WITH_OPENSSL=1; else unset BPANEL_VERIFY_WITH_OPENSSL; fi
  minisign_verify "$F" "$F.minisig" "$PUB" file:bpanel-9.9.9-linux-amd64.tar.gz version:9.9.9 >/dev/null 2>&1 && ok "$mode: valid prehashed signature" || bad "$mode: valid prehashed signature rejected"
  minisign_verify "$T/legacy.bin" "$T/legacy.bin.minisig" "$PUB" file:legacy.bin >/dev/null 2>&1 && ok "$mode: valid legacy signature" || bad "$mode: legacy signature rejected"
  cp "$F" "$T/tampered"; printf 'x' | dd of="$T/tampered" bs=1 seek=1000 conv=notrunc 2>/dev/null
  minisign_verify "$T/tampered" "$F.minisig" "$PUB" >/dev/null 2>&1 && bad "$mode: tampered file accepted" || ok "$mode: tampered file rejected"
  minisign_verify "$F" "$F.minisig" "$OTHER" >/dev/null 2>&1 && bad "$mode: wrong key accepted" || ok "$mode: wrong key rejected"
  minisign_verify "$F" "$F.minisig" "$PUB" version:9.9.10 >/dev/null 2>&1 && bad "$mode: version mismatch accepted" || ok "$mode: older release under a new version rejected"
  minisign_verify "$F" "$F.minisig" "$PUB" file:other.tar.gz >/dev/null 2>&1 && bad "$mode: file name mismatch accepted" || ok "$mode: file name mismatch rejected"
  sed '3s/version:9.9.9/version:9.9.10/' "$F.minisig" > "$T/forged.minisig"
  minisign_verify "$F" "$T/forged.minisig" "$PUB" version:9.9.10 >/dev/null 2>&1 && bad "$mode: forged trusted comment accepted" || ok "$mode: forged trusted comment rejected"
  printf 'garbage\n' > "$T/garbage.minisig"
  minisign_verify "$F" "$T/garbage.minisig" "$PUB" >/dev/null 2>&1 && bad "$mode: garbage signature accepted" || ok "$mode: garbage signature rejected"
done
unset BPANEL_VERIFY_WITH_OPENSSL

if grep -q '^BPANEL_RELEASE_PUBKEY="UNSET"' "$SCRIPT"; then
  ( unset BPANEL_PUBKEY; pubkey >/dev/null ) && bad "UNSET key accepted" || ok "UNSET release key fails closed"
fi

# End-to-end on a fake unpacked release (needs root: install.sh insists on it).
if [ "$(id -u)" -eq 0 ]; then
  R="$T/rel"; mkdir -p "$R"
  for b in bpanel-installer bpanel-api bpanel-agent bpanel; do printf '#!/bin/sh\necho "RAN %s $*"\n' "$b" > "$R/$b"; chmod +x "$R/$b"; done
  cp "$SCRIPT" "$R/install.sh"
  (cd "$R" && sha256sum bpanel bpanel-api bpanel-agent bpanel-installer > SHA256SUMS)
  out="$(BPANEL_PUBKEY="$PUB" bash "$R/install.sh" --allow-unsupported --yes 2>&1)"
  echo "$out" | grep -q "not signed" && ok "local archive without signature refused" || bad "unsigned local archive ran: $out"
  minisign -S -s "$T/k.key" -m "$R/SHA256SUMS" -x "$R/SHA256SUMS.minisig" -t "bpanel-release file:SHA256SUMS version:9.9.9" >/dev/null 2>&1
  out="$(BPANEL_PUBKEY="$PUB" bash "$R/install.sh" --allow-unsupported --yes 2>&1)"
  # R2-SYS-17: install.sh copies the verified binaries to /usr/local/lib/bpanel
  # and runs the installer from there, so upgrade/uninstall work without the archive.
  echo "$out" | grep -q "RAN bpanel-installer install --bin-dir /usr/local/lib/bpanel --allow-unsupported --yes" && ok "signed local archive runs bpanel-installer" || bad "signed local archive: $out"
  cmp -s "$R/bpanel-installer" /usr/local/lib/bpanel/bpanel-installer && ok "verified binaries copied to /usr/local/lib/bpanel" || bad "binaries not copied to /usr/local/lib/bpanel"
  printf '\n# evil\n' >> "$R/bpanel-agent"
  out="$(BPANEL_PUBKEY="$PUB" bash "$R/install.sh" --allow-unsupported --yes 2>&1)"
  echo "$out" | grep -q "checksum mismatch" && ok "modified binary refused" || bad "modified binary ran: $out"
  out="$(BPANEL_PUBKEY="$OTHER" bash "$R/install.sh" --allow-unsupported --yes 2>&1)"
  echo "$out" | grep -q "signature check failed" && ok "archive signed by another key refused" || bad "wrong key: $out"
else
  echo "  (not root: skipping the end-to-end local archive checks)"
fi

[ "$FAILS" -eq 0 ] && echo "ALL install.sh CHECKS PASSED" || echo "$FAILS install.sh CHECK(S) FAILED"
exit "$FAILS"
