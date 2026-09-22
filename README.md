# autocrack — automated aircrack-ng Wi-Fi audit (Linux)

`autocrack` chains the [aircrack-ng](https://www.aircrack-ng.org/) suite into
one automated run — monitor mode → scan → targeted handshake capture (with
deauth) → offline crack — so you don't drive each tool by hand.

> **Authorized use only.** Run this against a network you own or have explicit
> written permission to test. Deauthentication and handshake capture against
> networks you don't control are illegal in most places. The `--authorized`
> flag is a speed bump, not permission.

## Why this is Linux-only

Wi-Fi monitor mode + packet injection **do not work on macOS** for USB adapters
like the ALFA AWUS036ACHM (MediaTek MT7610U) — there is no such driver. On
**Linux** the in-kernel `mt76x0u` driver gives that card full monitor mode and
injection, so the aircrack-ng suite works against it out of the box. This tool
automates that Linux workflow.

### Hardware note for Apple Silicon Macs

Passing a USB Wi-Fi adapter through to a Linux VM on an Apple Silicon Mac
(M-series) is unreliable — Apple's Virtualization.framework doesn't do arbitrary
USB passthrough, and QEMU `usb-host` passthrough of Wi-Fi NICs is flaky on ARM.
Run this on a **separate Linux machine** instead: a Raspberry Pi 4/5 (Raspberry
Pi OS or Kali), or any x86 box booting Kali Linux, with the ALFA plugged
directly into it.

## Setup (Debian / Ubuntu / Kali / Raspberry Pi OS)

```bash
# 1. Install the aircrack-ng suite
sudo apt update && sudo apt install -y aircrack-ng

# 2. Plug in the ALFA (AWUS036ACHM / MT7610U) and confirm the driver bound it
ip link                       # look for a wlanN interface
sudo dmesg | grep -i mt76     # should show mt76x0u claiming the device

# 3. (Recommended) stop processes that fight for the radio
sudo airmon-ng check kill

# 4. A wordlist, e.g. rockyou
#    Kali: /usr/share/wordlists/rockyou.txt.gz  (gunzip it first)
```

The MT7610U is supported by mainline Linux, so no out-of-tree driver is
normally needed. If `ip link` shows no `wlanN`, update your kernel/firmware
(`sudo apt install firmware-misc-nonfree` on Debian) and re-plug.

## Raspberry Pi

A Pi (4/5, or a Zero 2 W) running Raspberry Pi OS or Kali is the recommended
host. No code changes are needed — but four things bite people:

1. **The ALFA is `wlan1`, not `wlan0`.** `wlan0` is the Pi's built-in Wi-Fi;
   the AWUS036ACHM comes up as `wlan1`. Pass `--interface wlan1`. Confirm with
   `iw dev` after plugging it in. (autocrack now fails preflight with a clear
   message if you name an interface that doesn't exist.)
2. **Don't SSH in over Wi-Fi.** autocrack runs `airmon-ng check kill` by
   default, which stops NetworkManager/wpa_supplicant and **drops a Wi-Fi SSH
   session**. Reach the Pi over **Ethernet** or a serial/HDMI console. If you
   must stay on Wi-Fi, add `--no-check-kill` (the built-in radio may then
   interfere with capture).
3. **Firmware.** The MT7610U needs `mediatek/mt7610u.bin`. It's in
   `firmware-misc-nonfree` / `linux-firmware` (present on current Pi OS). If
   `wlan1` never appears: `sudo apt install -y firmware-misc-nonfree && sudo reboot`.
   Verify the driver bound it: `sudo dmesg | grep -i mt76`.
4. **Power.** The AWUS036ACHM is high-power; under injection it can brown out a
   Pi. Use a **powered USB hub** or a strong PSU.

Typical Pi run (over Ethernet):

```bash
sudo apt install -y aircrack-ng iw
sudo python3 autocrack.py --interface wlan1 --essid <your-network> \
    --wordlist /path/to/rockyou.txt --authorized
```

## Usage

Run as root (monitor mode requires it).

```bash
# Target a specific AP you own (no scan step)
sudo python3 autocrack.py \
    --interface wlan0 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 \
    --wordlist /path/to/rockyou.txt \
    --authorized

# Or scan first and target by network name
sudo python3 autocrack.py \
    --interface wlan0 \
    --essid MyHomeNetwork \
    --wordlist /path/to/rockyou.txt \
    --authorized
```

Without a `--bssid` or `--essid`, `autocrack` scans and then **prints the
networks it saw and stops** — it will not attack every AP in range.

Must be run as **root** (monitor mode, injection and `airmon-ng` all require it).

### What it does, step by step

1. Verify it's running as root and that the aircrack-ng suite is installed.
2. `airmon-ng check kill` — stop NetworkManager/wpa_supplicant so they can't
   yank the radio off-channel (skip with `--no-check-kill`).
3. `airmon-ng start <iface>` — enable monitor mode (auto-detects the `…mon`
   vif) and verify with `iw` that the card is really in monitor mode, failing
   fast (rfkill / unsupported driver) instead of limping on.
4. `airodump-ng` — timed scan; parse the CSV to resolve your target's BSSID/channel
   (skipped when you pass `--bssid`/`--channel`). Stale files from prior runs are cleared first.
5. `airodump-ng --bssid <t> --channel <c> -w …` — targeted capture in the background.
6. `aireplay-ng --deauth` — short deauth bursts to make a client re-handshake,
   polling the capture until the WPA 4-way handshake appears.
7. `aircrack-ng -w <wordlist> -b <bssid> <cap>` — offline crack; prints the key.
8. `airmon-ng stop` — tear monitor mode back down.

## Key options

| Flag | Meaning |
|------|---------|
| `--interface` | Wi-Fi interface (e.g. `wlan0`) — **required** |
| `--wordlist` | Passphrase wordlist — **required** |
| `--authorized` | Confirm you're permitted to test the target — **required to run** |
| `--bssid` / `--channel` | Target AP directly, skipping the scan |
| `--essid` | Resolve BSSID/channel from a scan by network name |
| `--scan-time` | Seconds to scan for APs (default 15) |
| `--deauth-rounds` | Deauth/capture attempts before giving up (default 4) |
| `--workdir` | Where capture files are written (default `/tmp/autocrack`) |
| `--no-check-kill` | Don't run `airmon-ng check kill` (leave NetworkManager up) |

## Tests

The orchestration and all output parsing are unit-tested with fake command
runners (no radio needed), so the logic is verifiable anywhere:

```bash
python3 -m pytest test_autocrack.py -v
```

**Not covered by tests:** the live aircrack-ng integration itself. The tests
prove the parsing and control flow; capturing a real handshake and cracking it
must be validated on the Linux box with the ALFA attached.
