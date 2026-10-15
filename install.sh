#!/usr/bin/env bash
# JamfDisabler quick installer for macOS and Linux.
#
#   ./install.sh                 install to /usr/local/bin (asks for sudo)
#   ./install.sh --user          install to ~/.local/bin, no sudo needed
#   ./install.sh --build         build a stand-alone binary from source instead
#                                of downloading one
#
# Nothing is installed as a background service or launch agent: this is just a
# copy of one executable. Uninstalling = deleting that single file.

set -euo pipefail

REPO="BestCheatsEver/JamfDisabler"
BIN_NAME="jamfdisabler"
PREFIX="/usr/local"
TARGET="$PREFIX/bin/$BIN_NAME"
MODE="download"
USER_INSTALL=0

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_INSTALL=1; TARGET="$HOME/.local/bin/$BIN_NAME"; shift ;;
    --prefix) PREFIX="$2"; TARGET="$PREFIX/bin/$BIN_NAME"; shift 2 ;;
    --build|--from-source) MODE="build"; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin) asset="JamfDisabler-macos-$( [ "$arch" = "arm64" ] && echo arm64 || echo x86_64 )" ;;
  Linux)  asset="JamfDisabler-linux-x86_64" ;;
  *) echo "This installer supports macOS and Linux. On Windows use install.ps1." >&2; exit 1 ;;
esac

if [ "$MODE" = "build" ]; then
  echo "==> building from source with PyInstaller"
  python3 -m pip install --user --upgrade pyinstaller >/dev/null 2>&1 || true
  python3 scripts/build.py --name JamfDisabler >/dev/null
  src="dist/JamfDisabler"
else
  echo "==> downloading the latest $asset from GitHub releases"
  url="https://github.com/$REPO/releases/latest/download/$asset"
  tmp="$(mktemp)"
  if ! curl -fL --retry 3 -o "$tmp" "$url"; then
    echo "Download failed. Falling back to a source build..."
    MODE="build"
    python3 -m pip install --user --upgrade pyinstaller >/dev/null 2>&1 || true
    python3 scripts/build.py --name JamfDisabler >/dev/null
    src="dist/JamfDisabler"
  else
    src="$tmp"
    chmod +x "$src"
  fi
fi

echo "==> installing to $TARGET"
if [ "$USER_INSTALL" = "1" ]; then
  mkdir -p "$(dirname "$TARGET")"
  install -m 0755 "$src" "$TARGET"
else
  sudo mkdir -p "$(dirname "$TARGET")"
  sudo install -m 0755 "$src" "$TARGET"
fi

echo
echo "==> installed: $($TARGET --version 2>/dev/null || echo "$TARGET")"
echo
echo "Run it:"
echo "    jamfdisabler on       # turn the block on (asks for your password)"
echo "    jamfdisabler status   # check it"
echo "    jamfdisabler off      # undo everything"
case ":$PATH:" in
  *":$(dirname "$TARGET"):"*) ;;
  *) echo; echo "NOTE: $(dirname "$TARGET") is not in your PATH. Add it, or run $TARGET directly." ;;
esac
