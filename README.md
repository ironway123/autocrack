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
# 1. One-shot install: dependencies + the `autocrack` command, system-wide
./install.sh
# Installs aircrack-ng, iw, hcxtools, then pip-installs autocrack (handling
# Bookworm's PEP 668 automatically). Afterwards `sudo autocrack ...` works.

# 2. Plug in the ALFA (AWUS036ACHM / MT7610U) and confirm the driver bound it
ip link                       # look for a wlanN interface (usually wlan1)
sudo dmesg | grep -i mt76     # should show mt76x0u claiming the device

# 3. A wordlist, e.g. rockyou
#    Kali: /usr/share/wordlists/rockyou.txt.gz  (gunzip it first)
```

Prefer to do it by hand? Install the deps (`sudo apt install -y aircrack-ng iw
hcxtools`) and then `sudo pip install --break-system-packages .` from the repo
root (the `--break-system-packages` flag is what gets past Bookworm's PEP 668
guard). Or skip installing entirely and run `sudo python3 autocrack.py ...`.

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

Run as root (monitor mode requires it). After `pip install .` you invoke it as
`autocrack`; without installing, run `sudo python3 autocrack.py …` instead.

```bash
# Recon only — scan and list nearby APs, then exit (no target/wordlist/auth)
sudo autocrack --interface wlan1 --scan-only

# Recon on ONE AP — list the clients (stations) associated to it
sudo autocrack --interface wlan1 --scan-only --bssid AA:BB:CC:DD:EE:FF --channel 6
sudo autocrack --interface wlan1 --scan-only --essid HomeLab   # resolves BSSID/channel first

# Target a specific AP you own (no scan step)
sudo autocrack \
    --interface wlan1 \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 \
    --wordlist /path/to/rockyou.txt \
    --authorized

# Or scan first and target by network name
sudo autocrack \
    --interface wlan1 \
    --essid MyHomeNetwork \
    --wordlist /path/to/rockyou.txt \
    --authorized
```

Use `--scan-only` for **reconnaissance**: it enables monitor mode, scans, and
prints a table of nearby APs (BSSID · channel · power · privacy · ESSID), then
exits — no target, wordlist, or `--authorized` needed (it only listens for
beacons). Pick a target from that list and re-run with `--bssid`/`--channel` or
`--essid` to capture and crack.

Add a target to `--scan-only` to instead **list the clients associated to one
AP** — give `--bssid` + `--channel`, or `--essid` (its BSSID/channel are
resolved by a quick scan first). It prints each associated station (client MAC ·
power · packets · associated BSSID · probes). Handy for confirming a client is
connected before capturing (deauthing an AP with no clients won't yield a
handshake). Still passive — monitor and listen only, no deauth.

In the attack path, without a `--bssid` or `--essid`, `autocrack` scans and then
**prints the networks it saw and stops** — it will not attack every AP in range.

Must be run as **root** (monitor mode, injection and `airmon-ng` all require it).

### Live display

In an interactive terminal, autocrack shows a refreshing view — an
airodump-style table of discovered APs during the scan, then a capture-progress
block (elapsed, deauth rounds, handshake state) — updated in place. Pass
`--quiet` (or pipe the output to a file) to fall back to plain one-line
milestones, which is what non-interactive/scripted runs get automatically.

### What it does, step by step

1. Verify it's running as root and that the aircrack-ng suite is installed.
2. `airmon-ng check kill` — stop NetworkManager/wpa_supplicant so they can't
   yank the radio off-channel (skip with `--no-check-kill`).
3. `airmon-ng start <iface>` — enable monitor mode, then read `iw dev` to find
   the interface actually in monitor mode (works whether the driver switches
   the card in place, e.g. mt76/ALFA keeps `wlan1`, or creates a `wlan1mon`
   vif). Fails fast (rfkill / unsupported driver) instead of limping on.
4. `airodump-ng` — timed scan; parse the CSV to resolve your target's BSSID/channel
   (skipped when you pass `--bssid`/`--channel`). Stale files from prior runs are cleared first.
5. **PMKID first (clientless).** `hcxdumptool` targets the AP and elicits EAPOL
   M1 with a PMKID — no client and no deauth needed, so it works on idle APs and
   past PMF/802.11w. If a PMKID appears (converted to `.hc22000` and detected),
   it's cracked directly and the deauth path is skipped. Turn this off with
   `--no-pmkid`, or bound it with `--pmkid-time` (default 20s). If no PMKID
   appears, fall through to the handshake path below.
6. `airodump-ng --bssid <t> --channel <c> -w …` — targeted capture in the background.
7. `aireplay-ng --deauth -c <client>` — short deauth bursts to make a client
   re-handshake, polling the capture until the WPA 4-way handshake appears.
8. Retain the capture: copy the pcap to `~/autocrack/captures/` as
   `<essid>_<bssid>_<timestamp>.cap` (never clobbers a previous run), and, if
   `hcxpcapngtool` (hcxtools) is installed, export the EAPOL to a hashcat
   `.hc22000` next to it.
9. Offline crack against your wordlist. **Prefers hashcat** on the `.hc22000`
   (`hashcat -m 22000 <hc22000> <wordlist>`) — it's much faster and its
   hcxtools-derived handshake is more robust than aircrack-ng's own pcap
   parsing, which can run an entire wordlist and *miss* a key hashcat finds from
   the same capture. Falls back to `aircrack-ng -w <wordlist> -b <bssid> <cap>`
   when hashcat or the `.hc22000` isn't available. Prints the key.
10. `airmon-ng stop` — tear monitor mode back down.

Even when the passphrase isn't in your wordlist, the saved `.cap`/`.hc22000`
let you crack it later with a bigger list or hashcat/GPU. For the export:
`sudo apt install -y hcxtools`. Change the location with `--captures-dir`.

## Cracking the exports with hashcat

autocrack's built-in crack is a single `aircrack-ng` pass over one wordlist on
the capture host (often a slow Pi CPU). When that doesn't find the key, take the
`.hc22000` export to a **GPU box** and run [hashcat](https://hashcat.net/hashcat/)
in mode **22000** (WPA-PBKDF2-PMKID+EAPOL) — it's far faster and lets you apply
rules and masks a plain wordlist can't. (`aircrack-ng` reads the `.cap`; hashcat
reads the `.hc22000`.)

First, check the hash loads and isn't already cracked:

```bash
hashcat -m 22000 capture.hc22000 --show     # prints any key already in the potfile
```

Then escalate, cheapest and most likely first:

```bash
# 1. A bigger/different wordlist (rockyou is small)
hashcat -m 22000 capture.hc22000 weakpass.txt

# 2. Wordlist + rules — mutates each word (caps, leetspeak, appended digits:
#    Password1!, summer2023, ...). This is usually the highest-value step.
hashcat -m 22000 capture.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 22000 capture.hc22000 rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# 3. Mask / brute force (-a 3) — WPA keys are >=8 chars and often structured.
#    Very effective against default-format router passwords.
hashcat -m 22000 capture.hc22000 -a 3 ?d?d?d?d?d?d?d?d        # 8 digits
hashcat -m 22000 capture.hc22000 -a 3 ?u?l?l?l?l?l?d?d        # Upper+lower+2 digits
#    ?d digit  ?l lower  ?u upper  ?s symbol  ?a all

# 4. Hybrid — word + appended mask (e.g. netgear1234)
hashcat -m 22000 capture.hc22000 -a 6 rockyou.txt ?d?d?d?d
```

Useful flags: `-w 3` (higher throughput), `-O` (optimized kernels, faster),
`--status --status-timer=10` (live progress/ETA). hashcat auto-checkpoints —
resume an interrupted run with `--restore`. Cracked keys are stored in the
potfile (`~/.local/share/hashcat/hashcat.potfile`); re-run with `--show` anytime.

If none of this works and the key is long and random (12+ mixed characters),
it's effectively uncrackable by wordlist/mask — that's the correct outcome for a
strong passphrase, not a tool failure.

**If even hashcat finds nothing quickly, sanity-check the handshake is complete**
— a capture with only EAPOL M1/M2 will never crack. Re-derive from the pcap and
confirm it reports a written hash:

```bash
hcxpcapngtool -o check.hc22000 capture.cap
```

If it's incomplete, take a fresh capture (all four EAPOL messages) rather than
burning GPU time on a dead handshake.

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
| `--deauth-count` | Deauth frames sent per round (default 5) |
| `--no-pmkid` | Skip the clientless PMKID attempt; go straight to deauth capture |
| `--pmkid-time` | Seconds to attempt PMKID before falling back (default 20) |
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
