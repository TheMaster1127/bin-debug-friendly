#!/usr/bin/env bash
# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="system"
UNINSTALL=0

for arg in "$@"; do
    case "$arg" in
        --user)
            MODE="user"
            ;;
        --system)
            MODE="system"
            ;;
        --uninstall)
            UNINSTALL=1
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Installs bin-debug-friendly globally so these commands work from anywhere (and across reboots):
  bin-debug-friendly          (main debugger & mapper)
  bin-debug-friendly-heap     (lifecycle heap dumper)
  bin-debug-friendly-strings  (stack & register string extractor)

Options:
  --system      Install to /opt/bin-debug-friendly and /usr/local/bin (default; uses sudo if needed)
  --user        Install to ~/.local/share/bin-debug-friendly and ~/.local/bin (no sudo)
  --uninstall   Remove installed files and command wrappers
  -h, --help    Show this help
EOF
            exit 0
            ;;
        *)
            echo "[!] Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

if [[ "$MODE" == "system" ]]; then
    LIB_DIR="/opt/bin-debug-friendly"
    BIN_DIR="/usr/local/bin"
    SUDO=""
    if [[ "$EUID" -ne 0 ]]; then
        SUDO="sudo"
    fi
else
    LIB_DIR="${HOME}/.local/share/bin-debug-friendly"
    BIN_DIR="${HOME}/.local/bin"
    SUDO=""
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
    echo "[*] Removing bin-debug-friendly from $BIN_DIR and $LIB_DIR ..."
    $SUDO rm -f \
        "$BIN_DIR/bin-debug-friendly" \
        "$BIN_DIR/bin-debug-friendly-heap" \
        "$BIN_DIR/bin-debug-friendly-strings"
    $SUDO rm -rf "$LIB_DIR"
    echo "[+] Uninstalled cleanly."
    exit 0
fi

# Verify dependencies
for dep in python3 gdb bwrap; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "[!] Missing dependency: $dep" >&2
        echo "    Install python3, gdb, and bubblewrap first." >&2
        exit 1
    fi
done

echo "[*] Installing bin-debug-friendly ($MODE mode)..."
echo "    Library directory : $LIB_DIR"
echo "    Binaries directory: $BIN_DIR"

$SUDO mkdir -p "$LIB_DIR" "$BIN_DIR"
$SUDO rm -rf "$LIB_DIR/src" "$LIB_DIR/main.py" "$LIB_DIR/heap_dump.py" "$LIB_DIR/stack_strings.py"

$SUDO cp -r "$REPO_DIR/src" "$LIB_DIR/src"
$SUDO cp "$REPO_DIR/main.py" "$LIB_DIR/main.py"
$SUDO cp "$REPO_DIR/heap_dump.py" "$LIB_DIR/heap_dump.py"
$SUDO cp "$REPO_DIR/stack_strings.py" "$LIB_DIR/stack_strings.py"

$SUDO chmod 755 "$LIB_DIR/main.py" "$LIB_DIR/heap_dump.py" "$LIB_DIR/stack_strings.py"

# Create clean launcher binaries (no .py extension) so `bin-debug-friendly<Tab>` completes all 3!
$SUDO tee "$BIN_DIR/bin-debug-friendly" >/dev/null <<EOF
#!/usr/bin/env sh
exec python3 "$LIB_DIR/main.py" "\$@"
EOF

$SUDO tee "$BIN_DIR/bin-debug-friendly-heap" >/dev/null <<EOF
#!/usr/bin/env sh
exec python3 "$LIB_DIR/heap_dump.py" "\$@"
EOF

$SUDO tee "$BIN_DIR/bin-debug-friendly-strings" >/dev/null <<EOF
#!/usr/bin/env sh
exec python3 "$LIB_DIR/stack_strings.py" "\$@"
EOF

$SUDO chmod 755 \
    "$BIN_DIR/bin-debug-friendly" \
    "$BIN_DIR/bin-debug-friendly-heap" \
    "$BIN_DIR/bin-debug-friendly-strings"

echo ""
echo "[+] Installation complete!"
echo "    Try typing 'bin-debug-friendly' + Tab from any directory:"
echo "      bin-debug-friendly <binary> [-A \"...\"] [-m] [--record] [--map]"
echo "      bin-debug-friendly-heap <binary> [-A \"...\"] [--input ...]"
echo "      bin-debug-friendly-strings <record-or-mapped-folder> [-a] [-c]"

if [[ "$MODE" == "user" ]] && [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "[!] Note: $BIN_DIR is not in your current PATH."
    echo "    Add this to ~/.bashrc or ~/.zshrc:"
    echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
