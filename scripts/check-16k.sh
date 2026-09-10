#!/bin/sh
# check-16k.sh [dist/cpprobe.aar]
#
# Google Play requires 16 KB page-size support of apps that target Android
# 15+ (August 2025 onwards): every PT_LOAD segment of a native library must
# be aligned to 16384 or more. `make bind-android` passes the alignment to
# the linker; this verifies the result for every ABI in the AAR and exits 1
# when one is short, so bind.yml never publishes a 4 KB build.
#
# Needs readelf (binutils) or llvm-readelf (on PATH, or in the NDK under
# ANDROID_NDK_HOME), and unzip.
set -eu

aar=${1:-dist/cpprobe.aar}
[ -f "$aar" ] || { echo "check-16k: $aar not found (make bind-android)" >&2; exit 2; }
command -v unzip >/dev/null || { echo "check-16k: unzip not found" >&2; exit 2; }

if command -v readelf >/dev/null; then
  re=readelf
elif command -v llvm-readelf >/dev/null; then
  re=llvm-readelf
else
  # A symlink to llvm-readobj in the NDK: no -type f.
  re=$(find "${ANDROID_NDK_HOME:-/nonexistent}/toolchains/llvm/prebuilt" -name llvm-readelf 2>/dev/null | head -n 1)
  [ -n "$re" ] || { echo "check-16k: neither readelf nor llvm-readelf found (set ANDROID_NDK_HOME)" >&2; exit 2; }
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unzip -q "$aar" 'jni/*/*.so' -d "$tmp"

# readelf -lW prints one row per program header; the last column of a LOAD
# row is its alignment, in hex. The conversion stays in awk: strtonum is a
# gawk extension and $((0x...)) is not in every sh.
bad=0
for so in "$tmp"/jni/*/*.so; do
  abi=$(basename "$(dirname "$so")")
  short=$("$re" -lW "$so" | awk '
    function hex(s,  i, c, v) {
      v = 0; s = tolower(s); sub(/^0x/, "", s)
      for (i = 1; i <= length(s); i++) { c = index("0123456789abcdef", substr(s, i, 1)) - 1; v = v * 16 + c }
      return v
    }
    $1 == "LOAD" && hex($NF) < 16384 { print $NF }')
  if [ -n "$short" ]; then
    echo "check-16k: $abi/$(basename "$so"): PT_LOAD alignment $(echo "$short" | sort -u | tr '\n' ' ')(< 16 KB)" >&2
    bad=1
  else
    echo "check-16k: $abi/$(basename "$so"): ok"
  fi
done
[ "$bad" = 0 ] || { echo "check-16k: FAIL: rebuild with -extldflags=-Wl,-z,max-page-size=16384 (make bind-android does) or NDK r28+" >&2; exit 1; }
