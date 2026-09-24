# autocrack — Handoff

**Last updated:** 2026-09-24
**Repo:** `ironway123/autocrack` (private GitHub). Local dev copy: `/Users/local/autocrack` on a macOS machine.
**Status:** Functional. Parsing + orchestration are fully unit-tested (49 tests, all green). The offline crack path is verified against the real `aircrack-ng` binary; the live RF pipeline (monitor→scan→deauth→capture) is correct in logic and needs a real Linux + ALFA run to validate end-to-end — including the new targeted-deauth path.

This is a snapshot to resume from, not permanent docs — update or delete as work continues.

## What it is

An automated aircrack-ng workflow (**Linux only**) for **authorized** Wi-Fi audits: monitor mode → scan → targeted handshake capture (deauth) → offline crack. It's a thin, dependency-injected orchestrator around the aircrack-ng binaries (pure Python stdlib), so the control flow and all output parsing are unit-testable with fake runners on any OS.

Kept separate from the macOS `crackiswhack` project because monitor mode / injection don't exist on macOS for this adapter.

## Hardware / environment

- **Adapter:** ALFA **AWUS036ACHM = MediaTek MT7610U**. On Linux the in-kernel `mt76x0u` driver gives monitor mode + injection. On the Pi it enumerates as **`wlan1`** and `airmon-ng` builds **`wlan1mon`**.
- **Runs on Linux** — Raspberry Pi is the intended capture rig; crack on a GPU box (hashcat). Not macOS.
- **Dev/testing** happens on macOS (this machine) via `pytest` with fake command runners — no radio needed.

## Current features (all on `main`)

- Monitor mode via `airmon-ng`, with the monitor interface **detected from `iw dev`** (handles both in-place `wlan1` and a created `wlan1mon`).
- **`--scan-only`** recon: list nearby APs; add `--bssid`+`--channel` or `--essid` to list the **associated clients (stations)** of one AP.
- Targeted capture: backgrounded `airodump-ng` + `aireplay-ng` deauth, polling for the handshake. Tunable `--deauth-rounds` (default 4) and `--deauth-count` (default 5). Poll interval is 5s (hardcoded).
- **Targeted (per-client) deauth:** the capture airodump now writes `--output-format pcap,csv`; each round re-reads that live csv and sends a `-c <station>` deauth burst to **every client currently associated** with the AP (many clients ignore broadcast deauths). Falls back to a broadcast `-a <bssid>` burst when no associated clients are visible yet. Clients that appear mid-capture get targeted on the next round.
- **Retention:** successful captures copied to **`~/autocrack/captures/`** as `<essid>_<bssid>_<timestamp>.cap` (never clobbers); EAPOL exported to hashcat **`.hc22000`** via `hcxpcapngtool` (best-effort). Override with `--captures-dir`.
- Offline crack via `aircrack-ng`; prints `KEY FOUND` and the saved cap/hashcat paths (even when the key isn't in the wordlist, so you can crack later).
- **Live display** in a tty (refreshing AP/station table + capture progress); `--quiet` or a non-tty falls back to plain milestone lines.
- **Safety:** `--authorized` required for the attack path; `--scan-only` needs only root (passive); refuses to auto-attack every AP; requires root; preflights required tools and interface existence.
- **Packaging:** `pyproject.toml` console entry point (`autocrack`); `install.sh` installs system-wide and handles Bookworm's PEP 668 (`--break-system-packages`).

## Key decisions / rationale

- **Monitor interface from `iw dev`, not airmon-ng text** — fixed a real Pi bug where the old regex parsed `"10"` (from `phy10`) and aborted even though monitor mode was up.
- `install.sh` does a **non-editable** `pip install .`, so the installed `autocrack` is a snapshot — **re-run `install.sh` after a `git pull`** for the command to update. (See open items: switching to editable.)
- Under `sudo`, `~` may resolve to `/root`, so captures can land in `/root/autocrack/captures/`. Pin with `--captures-dir`.
- Cracking on the Pi is the heaviest load; capturing on the Pi and cracking on a GPU box is the intended split.

## Known issue under investigation

- **The Pi froze/crashed twice.** Concluded (user + assistant) to be a **hardware power/brownout** issue — the high-power ALFA on a marginal PSU, worst during deauth injection — **not autocrack**. Fixes: powered USB hub, stronger PSU (Pi4 5V/3A, Pi5 5V/5A), cooling. Confirm with `vcgencmd get_throttled` (non-zero = under-voltage) and `dmesg | grep -i under-voltage`. No code change made — user's call.

## Open items / offers (not yet done)

- **Editable install:** switch `install.sh` to `pip install -e .` so a plain `git pull` updates the `autocrack` command (repo must stay put). Recommended.
- **`--poll-interval`** flag (seconds between deauth rounds; currently 5s hardcoded).
- **`--no-crack`** capture-only mode to cut Pi load (crack elsewhere). User leaning against, pending the power fix.
- **Capture-reliability follow-ups** (identified 2026-09-24, targeted deauth done first): PMKID attack via `hcxdumptool` (gets a hash from the AP with **no clients** and bypasses PMF); detect **802.11w/PMF & WPA3** from the scan and warn that deauth won't work; longer/adaptive attack window (more rounds, a short settle before round 0); validate handshakes with `hcxpcapngtool`/`cowpatty` (M1–M4) instead of trusting aircrack's loose handshake count.
- README section "Cracking the exports with hashcat" (commands drafted in chat: `hashcat -m 22000 <file>.hc22000 <wordlist>`, rules, masks, `--show`).

## How to run

```bash
# Install (Pi): dependencies + the `autocrack` command, system-wide
./install.sh

# Recon: nearby APs
sudo autocrack --interface wlan1 --scan-only
# Recon: clients of one AP
sudo autocrack --interface wlan1 --scan-only --essid <net>
# Attack: capture + crack
sudo autocrack --interface wlan1 --essid <net> --wordlist /path/rockyou.txt --authorized

# Without installing:  sudo python3 autocrack.py ...
# Tests (in a venv):   python3 -m pytest
```

## How to resume after clearing context

Point a fresh session at the repo (`github.com/ironway123/autocrack`, or `/Users/local/autocrack`). Read `README.md`, this `HANDOFF.md`, and `git log --oneline`. The test suite (`test_autocrack.py`) is the behavioral spec.
