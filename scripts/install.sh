#!/bin/sh
# Install the CensorPulse probe client on Linux or macOS (amd64 / arm64).
#
#   curl -fsSL https://raw.githubusercontent.com/xarvel/CensorPulseCli/main/scripts/install.sh | sh
#   sh scripts/install.sh       # from a checkout: build that checkout
#
# Standalone installation downloads the latest checksum-verified release
# binary. If no release exists yet, it falls back to a source build. Running
# from a checkout always builds the checked-out code.
#
# Environment:
#   CPPROBE_INSTALL_DIR   target directory (default /usr/local/bin or ~/.local/bin)
#   CPPROBE_BUILD=1       force a source build instead of a release binary
#   CPPROBE_GIT_URL       repository used by the source fallback
#   CPPROBE_REF           git ref for the source fallback (default main)
#   CPPROBE_GO_VERSION    Go downloaded for the source fallback (default 1.26.8)
#   CPPROBE_SKIP_PKGS=1   never touch the package manager
set -eu

BIN=cpprobe
GO_VERSION="${CPPROBE_GO_VERSION:-1.26.8}"
GIT_URL="${CPPROBE_GIT_URL:-https://github.com/xarvel/CensorPulseCli.git}"
REF="${CPPROBE_REF:-main}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then SUDO="sudo"; else warn "not root and no sudo: installing into the user directory"; fi
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in linux|darwin) ;; *) die "unsupported OS: $OS (download a Windows binary from GitHub Releases)" ;; esac
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU: $ARCH" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

install_pkg() {
  [ "${CPPROBE_SKIP_PKGS:-0}" != 1 ] || return 1
  if have apt-get; then $SUDO apt-get update -qq && $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif have dnf; then $SUDO dnf install -y -q "$@"
  elif have yum; then $SUDO yum install -y -q "$@"
  elif have apk; then $SUDO apk add --no-cache "$@"
  elif have brew; then brew install "$@"
  else return 1
  fi
}

if ! have curl && ! have wget; then
  log "installing curl"
  install_pkg curl ca-certificates || die "need curl or wget"
fi
fetch() {
  if have curl; then curl -fsSL --retry 3 -o "$2" "$1"
  else wget -qO "$2" "$1"
  fi
}

# When piped (curl | sh) $0 is the shell, not a file, and SCRIPT_DIR would be
# $PWD: never mistake an unrelated Go module next to the caller for a checkout.
SRC=""
if [ -f "$0" ]; then
  SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../go.mod" ] \
     && grep -q '^module github.com/xarvel/CensorPulseCli$' "$SCRIPT_DIR/../go.mod"; then
    SRC=$(cd "$SCRIPT_DIR/.." && pwd)
  fi
fi

# Prefer a checksum-verified release when the installer is piped/downloaded
# on its own. GitHub's latest/download endpoint avoids an API or jq dependency.
if [ -z "$SRC" ] && [ "${CPPROBE_BUILD:-0}" != 1 ]; then
  ASSET="cpprobe-${OS}-${ARCH}"
  BASE="https://github.com/xarvel/CensorPulseCli/releases/latest/download"
  log "downloading the latest release for ${OS}/${ARCH}"
  if fetch "$BASE/$ASSET" "$TMP/$BIN" 2>/dev/null && fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
    EXPECTED=$(awk -v name="$ASSET" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP/SHA256SUMS")
    [ -n "$EXPECTED" ] || die "$ASSET is missing from SHA256SUMS"
    if have sha256sum; then ACTUAL=$(sha256sum "$TMP/$BIN" | awk '{print $1}')
    elif have shasum; then ACTUAL=$(shasum -a 256 "$TMP/$BIN" | awk '{print $1}')
    elif have openssl; then ACTUAL=$(openssl dgst -sha256 "$TMP/$BIN" | awk '{print $NF}')
    else die "need sha256sum, shasum, or openssl to verify the release"; fi
    [ "$ACTUAL" = "$EXPECTED" ] || die "checksum mismatch for $ASSET"
    chmod 0755 "$TMP/$BIN"
  else
    warn "no downloadable release found; falling back to a source build"
    SRC=clone
  fi
elif [ -n "$SRC" ]; then
  log "building from checkout $SRC"
else
  SRC=clone
fi

if [ "$SRC" = clone ]; then
  for tool in git tar; do
    if ! have "$tool"; then
      log "installing $tool for the source build"
      install_pkg "$tool" ca-certificates || die "$tool is required for a source build"
    fi
  done
  log "cloning $GIT_URL@$REF"
  git clone -q --depth 1 -b "$REF" "$GIT_URL" "$TMP/src" || die "clone failed; check network access or set CPPROBE_GIT_URL"
  [ -f "$TMP/src/go.mod" ] || die "no go.mod found in the clone"
  SRC="$TMP/src"
fi

if [ -n "$SRC" ]; then
  go_ok() { "$1" version 2>/dev/null | grep -qE 'go1\.(2[6-9]|[3-9][0-9])'; }
  GO=""
  for cand in go /usr/local/go/bin/go "$HOME/.cpprobe/go/bin/go"; do
    if [ "$cand" = go ]; then have go && go_ok go && GO=go && break
    elif [ -x "$cand" ] && go_ok "$cand"; then GO="$cand"; break; fi
  done
  if [ -z "$GO" ]; then
    log "downloading Go $GO_VERSION for the source build"
    fetch "https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz" "$TMP/go.tgz"
    mkdir -p "$HOME/.cpprobe"
    # This directory is owned by this installer and only contains its Go SDK.
    rm -rf "$HOME/.cpprobe/go"
    tar -C "$HOME/.cpprobe" -xzf "$TMP/go.tgz"
    GO="$HOME/.cpprobe/go/bin/go"
  fi
  VERSION=$(git -C "$SRC" describe --tags --always --dirty 2>/dev/null || echo dev)
  log "building cpprobe $VERSION with $($GO version)"
  ( cd "$SRC" && CGO_ENABLED=0 "$GO" build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$TMP/$BIN" ./cmd/cpprobe )
fi

"$TMP/$BIN" version >/dev/null || die "installed binary does not run"

if [ -n "${CPPROBE_INSTALL_DIR:-}" ]; then DIR="$CPPROBE_INSTALL_DIR"
elif [ -w /usr/local/bin ] || [ -n "$SUDO" ]; then DIR=/usr/local/bin
else DIR="$HOME/.local/bin"; fi
mkdir -p "$DIR" 2>/dev/null || $SUDO mkdir -p "$DIR"
if [ -w "$DIR" ]; then install -m 0755 "$TMP/$BIN" "$DIR/$BIN"
else log "installing into $DIR needs sudo"; $SUDO install -m 0755 "$TMP/$BIN" "$DIR/$BIN"; fi

case ":$PATH:" in *":$DIR:"*) ;; *) warn "$DIR is not in PATH; add it before running cpprobe" ;; esac
log "installed: $("$DIR/$BIN" version)"
printf '\nNext:\n  cpprobe scan --target <server-ip> --pin '\''<spki-pin>'\''\n  cpprobe tests\n\n'
