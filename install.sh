#!/usr/bin/env bash
#
# Install autocrack system-wide so `sudo autocrack ...` works (instead of
# `sudo python3 autocrack.py ...`). Run from the repo root:
#
#     ./install.sh          # or: sudo ./install.sh
#
set -euo pipefail
cd "$(dirname "$0")"

# Use sudo only when we're not already root (Pi OS has sudo; a root shell
# may not).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

echo "[*] Installing dependencies (aircrack-ng, iw, python3-pip)..."
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y aircrack-ng iw python3-pip
    # hcxtools is optional (enables the hashcat .hc22000 export).
    $SUDO apt-get install -y hcxtools \
        || echo "[!] hcxtools unavailable — hashcat export will be skipped."
else
    echo "[!] apt-get not found — install aircrack-ng, iw and pip yourself."
fi

echo "[*] Installing the 'autocrack' command system-wide..."
# Modern Debian/Pi OS (Bookworm) blocks system pip installs (PEP 668); retry
# with --break-system-packages, which is fine for a dedicated audit box.
if ! $SUDO python3 -m pip install . 2>/dev/null; then
    echo "[*] Retrying with --break-system-packages (PEP 668)..."
    $SUDO python3 -m pip install --break-system-packages .
fi

if command -v autocrack >/dev/null 2>&1; then
    echo "[+] Installed: $(command -v autocrack)"
    echo "[+] Try:   sudo autocrack --interface wlan1 --scan-only"
else
    echo "[!] 'autocrack' is not on PATH. It may be in /usr/local/bin — check"
    echo "    that directory is on root's PATH, or run: sudo python3 autocrack.py ..."
    exit 1
fi
