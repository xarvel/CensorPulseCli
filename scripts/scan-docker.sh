#!/bin/sh
# Run the CensorPulse client from Docker (no Go, no build tools on the host).
#
#   sh scripts/scan-docker.sh --target <server-ip> --pin '<pin>' [scan flags...]
#
# Builds the image from this checkout on first use, then runs `cpprobe scan`
# with the host network (real source ports and timings) and the current
# directory mounted as the output directory, so `--out report.json` lands
# next to you. Any argument is passed to `cpprobe scan` unchanged.
#
# The image is rebuilt automatically when the sources in this checkout
# changed since it was built (a checksum of the Go sources, go.mod/go.sum and
# the Dockerfile is stored as an image label). The container itself is
# throwaway (--rm): there is nothing to recreate, only the image.
#
# Environment:
#   CPPROBE_IMAGE      image to use (default censorpulse-probe:local)
#   CPPROBE_REBUILD=1  force a rebuild of the image
set -eu

IMAGE="${CPPROBE_IMAGE:-censorpulse-probe:local}"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed (see scripts/install.sh for a native build instead)"
[ $# -gt 0 ] || die "usage: $0 --target <server-ip> --pin '<pin>' [scan flags]"

# Checksum of everything that goes into the binary; compared with the label
# of the existing image so that a stale image is never used silently.
SRC_SUM=$(cd "$ROOT" && find . -type f \( -name '*.go' -o -name go.mod -o -name go.sum -o -name Dockerfile \) \
  -not -path './dist/*' -not -path './bin/*' | LC_ALL=C sort | xargs cksum | cksum | cut -d' ' -f1)
HAVE_SUM=$(docker image inspect -f '{{ index .Config.Labels "censorpulse.src" }}' "$IMAGE" 2>/dev/null || true)
if [ "${CPPROBE_REBUILD:-0}" = 1 ]; then
  log "rebuilding $IMAGE (CPPROBE_REBUILD=1)"
  REBUILD=1
elif [ -z "$HAVE_SUM" ]; then
  log "building $IMAGE from $ROOT"
  REBUILD=1
elif [ "$HAVE_SUM" != "$SRC_SUM" ]; then
  log "sources changed since $IMAGE was built; rebuilding"
  REBUILD=1
else
  REBUILD=0
fi
if [ "$REBUILD" = 1 ]; then
  docker build -q --label "censorpulse.src=$SRC_SUM" -t "$IMAGE" "$ROOT" >/dev/null
fi

# Host networking gives the scan the machine's own source ports and RTTs. It
# is native on Linux; Docker Desktop (macOS/Windows) only supports it as an
# opt-in feature, so fall back to a bridge network there with a warning.
NET="--network host"
case "$(uname -s)" in
  Darwin|MINGW*|MSYS*|CYGWIN*)
    if ! docker info 2>/dev/null | grep -qi "host networking"; then
      warn "host networking is not available on this Docker; using a bridge network (extra NAT hop, timings are less precise)"
      NET=""
    fi ;;
esac

# Run as the invoking user so the report file is owned by you. That uid has
# no HOME inside the container, so the default --geoip-dir (~/.cpprobe/geoip)
# does not exist there: offline GeoIP needs the tables under the mounted
# output directory and an explicit --geoip-dir /out/<dir>.
USER_FLAG=""
if [ "$(uname -s)" = Linux ]; then USER_FLAG="-u $(id -u):$(id -g)"; fi
case " $* " in
  *" --geoip-dir"*|*" --geoip-dir="*) ;;
  *) log "hint: offline GeoIP inside the container needs --geoip-dir /out/<dir> (only \$PWD is mounted, as /out)" ;;
esac

TTY=""
if [ -t 0 ] && [ -t 1 ]; then TTY="-it"; fi

exec docker run --rm $TTY $NET $USER_FLAG \
  -v "$PWD:/out" -w /out \
  -e QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true \
  "$IMAGE" scan "$@"
