from __future__ import annotations

import datetime
import pathlib
import subprocess

import pytest

import autocrack
from autocrack import (
    AccessPoint,
    AutocrackError,
    AuthorizationError,
    InterfaceNotFoundError,
    LiveWriter,
    MonitorModeError,
    NotRootError,
    ToolNotFoundError,
    WifiAuditor,
    build_parser,
    parse_airodump_csv,
    parse_crack_key,
    Station,
    parse_airodump_stations,
    parse_monitor_from_iw_dev,
    parse_monitor_interface,
    render_ap_list,
    render_capture_status,
    render_scan_table,
    render_station_list,
    scan_has_handshake,
)


def _tools_present_runner(cmd, **kwargs):
    """A runner where `which` finds every tool (for tests past preflight)."""
    if cmd[0] == "which":
        return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


class FakeClock:
    """Monotonic-ish clock that advances a fixed step on each call."""

    def __init__(self, step=5):
        self.t = 0
        self.step = step

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


class _FakeProcess:
    """Stand-in for a backgrounded airodump-ng Popen handle."""

    def __init__(self, *args, **kwargs):
        self.terminated = False

    def poll(self):
        return None if not self.terminated else 0

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0

# A real `airodump-ng --output-format csv` dump (CRLF line endings, leading
# spaces on every field) with two APs and one associated station.
SAMPLE_AIRODUMP_CSV = (
    "\r\n"
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "AA:BB:CC:DD:EE:FF, 2024-01-01 10:00:00, 2024-01-01 10:05:00,  6,  130, WPA2, "
    "CCMP, PSK, -42,      120,        0,   0.  0.  0.  0,   8, HomeLab , \r\n"
    "11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 11,  195, OPN , "
    ", , -70,   40, 0,   0.  0.  0.  0,   9, CoffeeAP , \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes\r\n"
    "99:88:77:66:55:44, 2024-01-01 10:00:00, 2024-01-01 10:05:00, -55, 30, "
    "AA:BB:CC:DD:EE:FF, \r\n"
)


# --- parse_airodump_csv ---------------------------------------------------


def test_parse_airodump_csv_returns_access_points_with_trimmed_fields():
    aps = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)

    assert aps == [
        AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel="6", privacy="WPA2", power="-42", essid="HomeLab"),
        AccessPoint(bssid="11:22:33:44:55:66", channel="11", privacy="OPN", power="-70", essid="CoffeeAP"),
    ]


def test_parse_airodump_csv_ignores_station_section():
    aps = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)

    # The station row's MAC must not be mistaken for an access point.
    assert all(ap.bssid != "99:88:77:66:55:44" for ap in aps)


def test_parse_airodump_csv_handles_empty_dump():
    assert parse_airodump_csv("\r\n") == []


# --- parse_monitor_interface ----------------------------------------------


def test_parse_monitor_interface_extracts_created_vif():
    airmon_output = (
        "PHY\tInterface\tDriver\t\tChipset\n"
        "phy0\twlan0\t\tmt76x0u\t\tMediaTek MT7610U\n\n"
        "\t\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
        "\t\t(mac80211 station mode vif disabled for [phy0]wlan0)\n"
    )

    assert parse_monitor_interface(airmon_output, requested="wlan0") == "wlan0mon"


def test_parse_monitor_interface_falls_back_to_requested_when_in_place():
    # Some drivers switch the same interface into monitor mode in place.
    assert parse_monitor_interface("nothing useful here", requested="wlan0") == "wlan0"


# --- scan_has_handshake ---------------------------------------------------


def test_scan_has_handshake_true_when_aircrack_reports_one_for_bssid():
    output = (
        "   #  BSSID              ESSID          Encryption\n"
        "   1  AA:BB:CC:DD:EE:FF  HomeLab        WPA (1 handshake)\n"
    )

    assert scan_has_handshake(output, "AA:BB:CC:DD:EE:FF") is True


def test_scan_has_handshake_false_when_no_handshake_for_bssid():
    output = (
        "   #  BSSID              ESSID          Encryption\n"
        "   1  AA:BB:CC:DD:EE:FF  HomeLab        WPA (0 handshake)\n"
    )

    assert scan_has_handshake(output, "AA:BB:CC:DD:EE:FF") is False


def test_scan_has_handshake_is_case_insensitive_about_bssid():
    output = "   1  aa:bb:cc:dd:ee:ff  HomeLab  WPA (1 handshake)\n"

    assert scan_has_handshake(output, "AA:BB:CC:DD:EE:FF") is True


# --- parse_crack_key ------------------------------------------------------


def test_parse_crack_key_extracts_found_passphrase():
    output = "\n\n                 KEY FOUND! [ correct horse battery ]\n\n"

    assert parse_crack_key(output) == "correct horse battery"


def test_parse_crack_key_returns_none_when_not_found():
    output = "Passphrase not in dictionary\nQuitting aircrack-ng...\n"

    assert parse_crack_key(output) is None


# --- authorization guard --------------------------------------------------


def test_auditor_run_requires_explicit_authorization():
    auditor = WifiAuditor(interface="wlan0", workdir="/tmp/x", authorized=False)

    with pytest.raises(AuthorizationError):
        auditor.run(bssid="AA:BB:CC:DD:EE:FF", channel="6", wordlist="/tmp/w.txt")


def test_preflight_raises_when_interface_does_not_exist(tmp_path):
    # No wlanN under the (empty) sysfs dir -> clear error, not a cryptic
    # airmon-ng failure (the classic wlan0-vs-wlan1 Pi mistake).
    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        runner=_tools_present_runner,
        net_sysfs=str(tmp_path / "netdev"),
    )
    (tmp_path / "netdev").mkdir()

    with pytest.raises(InterfaceNotFoundError, match="wlan1"):
        auditor.preflight()


def test_preflight_accepts_existing_interface(tmp_path):
    netdev = tmp_path / "netdev"
    (netdev / "wlan1").mkdir(parents=True)
    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        runner=_tools_present_runner,
        net_sysfs=str(netdev),
    )

    auditor.preflight()  # should not raise


def test_run_requires_root(tmp_path):
    auditor = WifiAuditor(
        interface="wlan0",
        workdir=str(tmp_path),
        authorized=True,
        runner=_tools_present_runner,
        euid_getter=lambda: 1000,  # not root
    )

    with pytest.raises(NotRootError, match="root"):
        auditor.run(bssid="AA:BB:CC:DD:EE:FF", channel="6", wordlist="/tmp/w.txt")


# `iw dev` output samples --------------------------------------------------

# mt76 / ALFA on a Pi: airmon-ng switches the SAME interface to monitor mode.
IW_DEV_IN_PLACE = "phy#10\n\tInterface wlan1\n\t\tifindex 5\n\t\ttype monitor\n"
# Other drivers create a separate <iface>mon vif and leave the original managed.
IW_DEV_MON_VIF = (
    "phy#0\n\tInterface wlan0mon\n\t\ttype monitor\n"
    "\tInterface wlan0\n\t\ttype managed\n"
)
IW_DEV_ALL_MANAGED = "phy#0\n\tInterface wlan0\n\t\ttype managed\n"


def _monitor_runner(iw_dev_output, interface="wlan1", airmon_rc=0):
    def runner(cmd, **kwargs):
        if cmd[:2] == ["airmon-ng", "start"]:
            return subprocess.CompletedProcess(cmd, airmon_rc, stdout="", stderr="err")
        if cmd[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=iw_dev_output, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return runner


# --- parse_monitor_from_iw_dev --------------------------------------------


def test_parse_monitor_from_iw_dev_finds_in_place_monitor_interface():
    assert parse_monitor_from_iw_dev(IW_DEV_IN_PLACE, prefer="wlan1") == "wlan1"


def test_parse_monitor_from_iw_dev_finds_created_vif():
    assert parse_monitor_from_iw_dev(IW_DEV_MON_VIF, prefer="wlan0") == "wlan0mon"


def test_parse_monitor_from_iw_dev_returns_none_when_nothing_in_monitor_mode():
    assert parse_monitor_from_iw_dev(IW_DEV_ALL_MANAGED, prefer="wlan0") is None


# --- enable_monitor (detects the monitor interface from `iw dev`) ----------


def test_enable_monitor_detects_in_place_monitor_interface():
    # Regression: mt76/ALFA keeps the name `wlan1`; must not mis-parse to "10".
    auditor = WifiAuditor(
        interface="wlan1", workdir="/tmp/x", authorized=True,
        runner=_monitor_runner(IW_DEV_IN_PLACE, interface="wlan1"), check_kill=False,
    )
    assert auditor.enable_monitor() == "wlan1"


def test_enable_monitor_detects_created_mon_vif():
    auditor = WifiAuditor(
        interface="wlan0", workdir="/tmp/x", authorized=True,
        runner=_monitor_runner(IW_DEV_MON_VIF, interface="wlan0"), check_kill=False,
    )
    assert auditor.enable_monitor() == "wlan0mon"


def test_enable_monitor_kills_interfering_processes_by_default():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=IW_DEV_IN_PLACE, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    WifiAuditor(interface="wlan1", workdir="/tmp/x", authorized=True, runner=runner).enable_monitor()

    assert ["airmon-ng", "check", "kill"] in calls


def test_enable_monitor_can_skip_check_kill():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=IW_DEV_IN_PLACE, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    auditor = WifiAuditor(
        interface="wlan1", workdir="/tmp/x", authorized=True, runner=runner, check_kill=False
    )
    auditor.enable_monitor()

    assert ["airmon-ng", "check", "kill"] not in calls


def test_enable_monitor_raises_when_airmon_ng_reports_failure():
    auditor = WifiAuditor(
        interface="wlan1", workdir="/tmp/x", authorized=True,
        runner=_monitor_runner(IW_DEV_ALL_MANAGED, airmon_rc=1), check_kill=False,
    )
    with pytest.raises(MonitorModeError):
        auditor.enable_monitor()


def test_enable_monitor_raises_when_no_interface_entered_monitor_mode():
    # airmon-ng exits 0 but iw dev shows nothing in monitor mode.
    auditor = WifiAuditor(
        interface="wlan0", workdir="/tmp/x", authorized=True,
        runner=_monitor_runner(IW_DEV_ALL_MANAGED, interface="wlan0"), check_kill=False,
    )
    with pytest.raises(MonitorModeError, match="monitor mode"):
        auditor.enable_monitor()


# --- stale capture files --------------------------------------------------


def test_scan_ignores_stale_csv_from_a_previous_run(tmp_path):
    # A leftover dump from an earlier run must not be reported as this scan's
    # result once the new scan finds nothing.
    (tmp_path / "scan-01.csv").write_text(SAMPLE_AIRODUMP_CSV)

    def popen(cmd, **kwargs):  # airodump starts but writes nothing new
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        popen=popen,
        sleep=lambda _s: None,
        clock=FakeClock(step=20),
    )

    assert auditor.scan(seconds=15) == []


def test_scan_streams_live_updates_and_returns_final_aps(tmp_path):
    def popen(cmd, **kwargs):
        prefix = cmd[cmd.index("--write") + 1]
        # airodump-ng writes/refreshes its CSV while it runs.
        pathlib.Path(f"{prefix}-01.csv").write_text(SAMPLE_AIRODUMP_CSV)
        return _FakeProcess()

    frames = []
    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        popen=popen,
        sleep=lambda _s: None,
        clock=FakeClock(step=5),
    )

    aps = auditor.scan(seconds=15, on_update=lambda a, e, t: frames.append((len(a), e, t)))

    assert [ap.essid for ap in aps] == ["HomeLab", "CoffeeAP"]
    assert frames, "expected at least one live scan frame"
    assert frames[-1][2] == 15  # total seconds reported to the display


def test_capture_handshake_reports_live_progress(tmp_path):
    checks = iter(["WPA (0 handshake)", "AA:BB:CC:DD:EE:FF WPA (1 handshake)"])

    def runner(cmd, **kwargs):
        if cmd[0] == "aircrack-ng":
            return subprocess.CompletedProcess(cmd, 0, stdout=next(checks), stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        return _FakeProcess()

    frames = []
    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        runner=runner,
        popen=popen,
        sleep=lambda _s: None,
    )

    cap, captured = auditor.capture_handshake(
        "AA:BB:CC:DD:EE:FF", "6", deauth_rounds=3, essid="HomeLab",
        on_update=lambda b, e, elapsed, done, total, got: frames.append((done, total, got)),
    )

    assert captured is True
    assert frames  # progress was reported
    assert frames[-1][2] is True  # final frame shows the handshake captured


# --- scan-only / AP discovery ---------------------------------------------


def test_discover_enables_monitor_scans_and_returns_aps(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "which":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")
        if cmd[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=IW_DEV_IN_PLACE, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        prefix = cmd[cmd.index("--write") + 1]
        pathlib.Path(f"{prefix}-01.csv").write_text(SAMPLE_AIRODUMP_CSV)
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=False,  # recon/discovery does not require the attack gate
        runner=runner,
        popen=popen,
        sleep=lambda _s: None,
        clock=FakeClock(step=5),
        euid_getter=lambda: 0,
        net_sysfs=str(tmp_path / "no-sysfs"),  # absent -> interface check skipped
    )

    aps = auditor.discover(scan_seconds=15)

    assert [ap.essid for ap in aps] == ["HomeLab", "CoffeeAP"]
    assert ["airmon-ng", "start", "wlan1"] in calls
    assert any(c[:2] == ["airmon-ng", "stop"] for c in calls)  # cleaned up


def test_parser_scan_only_makes_wordlist_optional():
    args = build_parser().parse_args(["--interface", "wlan1", "--scan-only"])
    assert args.scan_only is True
    assert args.wordlist is None


def test_render_ap_list_includes_every_ap():
    aps = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
    out = render_ap_list(aps)
    assert "AA:BB:CC:DD:EE:FF" in out and "HomeLab" in out
    assert "11:22:33:44:55:66" in out and "CoffeeAP" in out


# --- associated-client (station) monitoring -------------------------------


def test_parse_airodump_stations_lists_associated_clients():
    stations = parse_airodump_stations(SAMPLE_AIRODUMP_CSV)
    assert stations == [
        Station(
            mac="99:88:77:66:55:44", power="-55", packets="30",
            bssid="AA:BB:CC:DD:EE:FF", probes="",
        )
    ]


def test_parse_airodump_stations_filters_by_bssid():
    assert parse_airodump_stations(SAMPLE_AIRODUMP_CSV, bssid="11:22:33:44:55:66") == []
    assert len(parse_airodump_stations(SAMPLE_AIRODUMP_CSV, bssid="aa:bb:cc:dd:ee:ff")) == 1


def test_render_station_list_includes_client_and_its_ap():
    stations = parse_airodump_stations(SAMPLE_AIRODUMP_CSV)
    out = render_station_list(stations)
    assert "99:88:77:66:55:44" in out and "AA:BB:CC:DD:EE:FF" in out


def test_discover_clients_returns_stations_for_a_target(tmp_path):
    def runner(cmd, **kwargs):
        if cmd[0] == "which":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")
        if cmd[:2] == ["iw", "dev"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=IW_DEV_IN_PLACE, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        prefix = cmd[cmd.index("--write") + 1]
        pathlib.Path(f"{prefix}-01.csv").write_text(SAMPLE_AIRODUMP_CSV)
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=runner, popen=popen, sleep=lambda _s: None, clock=FakeClock(step=5),
        euid_getter=lambda: 0, net_sysfs=str(tmp_path / "nope"),
    )

    bssid, channel, stations = auditor.discover_clients(
        scan_seconds=15, bssid="AA:BB:CC:DD:EE:FF", channel="6"
    )

    assert bssid == "AA:BB:CC:DD:EE:FF" and channel == "6"
    assert [s.mac for s in stations] == ["99:88:77:66:55:44"]


def test_discover_clients_requires_channel_with_bssid(tmp_path):
    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=_tools_present_runner, euid_getter=lambda: 0,
        net_sysfs=str(tmp_path / "nope"),
    )
    with pytest.raises(AutocrackError, match="channel"):
        auditor.discover_clients(bssid="AA:BB:CC:DD:EE:FF")


# --- capture retention & hashcat export -----------------------------------


def test_archive_capture_saves_pcap_and_exports_hashcat(tmp_path):
    cap = tmp_path / "handshake-01.cap"
    cap.write_bytes(b"pcap-bytes-with-eapol")
    captures = tmp_path / "captures"

    def runner(cmd, **kwargs):
        if cmd[0] == "hcxpcapngtool":
            out = cmd[cmd.index("-o") + 1]
            pathlib.Path(out).write_text("WPA*02*deadbeef...")  # emulate conversion
            return subprocess.CompletedProcess(cmd, 0, stdout="1 handshake(s) written", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True, runner=runner,
        captures_dir=str(captures),
        now=lambda: datetime.datetime(2026, 9, 23, 14, 30, 0),
    )

    saved, hc = auditor._archive_capture(cap, "AA:BB:CC:DD:EE:FF", "HomeLab")

    assert saved and pathlib.Path(saved).exists() and saved.endswith(".cap")
    assert "HomeLab" in saved and "AA-BB-CC-DD-EE-FF" in saved  # BSSID + ESSID in name
    assert "20260923-143000" in saved                            # timestamped
    assert pathlib.Path(saved).read_bytes() == b"pcap-bytes-with-eapol"
    assert hc and pathlib.Path(hc).exists() and hc.endswith(".hc22000")


def test_archive_capture_skips_hashcat_when_tool_missing(tmp_path):
    cap = tmp_path / "handshake-01.cap"
    cap.write_bytes(b"pcap")

    def runner(cmd, **kwargs):
        if cmd[0] == "hcxpcapngtool":
            raise FileNotFoundError("hcxpcapngtool not installed")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True, runner=runner,
        captures_dir=str(tmp_path / "captures"),
    )

    saved, hc = auditor._archive_capture(cap, "AA:BB:CC:DD:EE:FF", "HomeLab")

    assert saved and pathlib.Path(saved).exists()  # pcap still retained
    assert hc is None                              # export gracefully skipped


def test_capture_handshake_uses_configured_deauth_count(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "aircrack-ng":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="AA:BB:CC:DD:EE:FF WPA (1 handshake)", stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=runner, popen=popen, sleep=lambda _s: None,
    )

    auditor.capture_handshake("AA:BB:CC:DD:EE:FF", "6", deauth_rounds=1, deauth_count=12)

    aireplay = next(c for c in calls if c and c[0] == "aireplay-ng")
    assert aireplay[aireplay.index("--deauth") + 1] == "12"


def _capture_runner(calls):
    """A fake runner that records commands and reports a captured handshake."""

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "aircrack-ng":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="AA:BB:CC:DD:EE:FF WPA (1 handshake)", stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return runner


def test_capture_handshake_targets_associated_clients(tmp_path):
    calls = []

    def popen(cmd, **kwargs):
        # The live airodump table lists an associated client for our AP.
        (tmp_path / "handshake-01.csv").write_text(SAMPLE_AIRODUMP_CSV)
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=_capture_runner(calls), popen=popen, sleep=lambda _s: None,
    )

    auditor.capture_handshake("AA:BB:CC:DD:EE:FF", "6", deauth_rounds=1)

    aireplay = next(c for c in calls if c and c[0] == "aireplay-ng")
    assert aireplay[aireplay.index("-a") + 1] == "AA:BB:CC:DD:EE:FF"
    # Deauth is aimed at the specific associated station, not broadcast.
    assert aireplay[aireplay.index("-c") + 1] == "99:88:77:66:55:44"


def test_capture_handshake_broadcasts_when_no_clients(tmp_path):
    calls = []

    def popen(cmd, **kwargs):
        return _FakeProcess()  # no CSV written -> no associated stations

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=_capture_runner(calls), popen=popen, sleep=lambda _s: None,
    )

    auditor.capture_handshake("AA:BB:CC:DD:EE:FF", "6", deauth_rounds=1)

    aireplay = next(c for c in calls if c and c[0] == "aireplay-ng")
    assert aireplay[aireplay.index("-a") + 1] == "AA:BB:CC:DD:EE:FF"
    assert "-c" not in aireplay  # falls back to a broadcast deauth


def test_capture_handshake_airodump_writes_pcap_and_csv(tmp_path):
    popened = []

    def popen(cmd, **kwargs):
        popened.append(cmd)
        return _FakeProcess()

    auditor = WifiAuditor(
        interface="wlan1", workdir=str(tmp_path), authorized=True,
        runner=_capture_runner([]), popen=popen, sleep=lambda _s: None,
    )

    auditor.capture_handshake("AA:BB:CC:DD:EE:FF", "6", deauth_rounds=1)

    airodump = next(c for c in popened if c and c[0] == "airodump-ng")
    fmt = airodump[airodump.index("--output-format") + 1]
    # A single background airodump must produce both the pcap (for the
    # handshake) and the csv (for the live station list we target).
    assert "pcap" in fmt and "csv" in fmt


# --- live display rendering -----------------------------------------------


def test_render_scan_table_lists_aps_and_progress():
    aps = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
    out = render_scan_table(aps, elapsed=7, total=15)

    assert "7" in out and "15" in out
    assert "AA:BB:CC:DD:EE:FF" in out and "HomeLab" in out
    assert "CoffeeAP" in out


def test_render_capture_status_shows_waiting_then_captured():
    waiting = render_capture_status("AA:BB:CC:DD:EE:FF", "HomeLab", 12, 2, 4, captured=False)
    assert "AA:BB:CC:DD:EE:FF" in waiting and "2" in waiting and "4" in waiting

    got = render_capture_status("AA:BB:CC:DD:EE:FF", "HomeLab", 20, 3, 4, captured=True)
    assert "captured" in got.lower() or "✓" in got


def test_live_writer_redraws_in_place():
    import io

    buf = io.StringIO()
    writer = LiveWriter(stream=buf, enabled=True)
    writer.update("frame one\nline two")
    writer.update("frame two")
    out = buf.getvalue()

    assert "frame one" in out and "frame two" in out
    assert "\033[" in out  # used an ANSI cursor-control sequence to redraw


def test_live_writer_is_silent_when_disabled():
    import io

    buf = io.StringIO()
    writer = LiveWriter(stream=buf, enabled=False)
    writer.update("nothing should appear")

    assert buf.getvalue() == ""


# --- preflight tool check -------------------------------------------------


def test_preflight_raises_when_a_required_tool_is_missing():
    def runner(cmd, **kwargs):
        # `which` returns non-zero for the missing tool.
        found = cmd[1] != "aireplay-ng"
        return subprocess.CompletedProcess(cmd, 0 if found else 1, stdout="", stderr="")

    auditor = WifiAuditor(interface="wlan0", workdir="/tmp/x", authorized=True, runner=runner)

    with pytest.raises(ToolNotFoundError, match="aireplay-ng"):
        auditor.preflight()


def test_preflight_passes_when_all_tools_present():
    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")

    auditor = WifiAuditor(interface="wlan0", workdir="/tmp/x", authorized=True, runner=runner)

    auditor.preflight()  # should not raise


# --- CLI parser -----------------------------------------------------------


def test_parser_requires_interface_and_wordlist():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_accepts_full_invocation():
    parser = build_parser()
    args = parser.parse_args(
        ["--interface", "wlan0", "--wordlist", "/tmp/rockyou.txt", "--authorized"]
    )
    assert args.interface == "wlan0"
    assert args.wordlist == "/tmp/rockyou.txt"
    assert args.authorized is True


# --- end-to-end orchestration with a fake runner --------------------------


def test_run_captures_handshake_then_cracks_key(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("hunter2\ncorrecthorse\n")

    calls = []
    # scan_has_handshake polls: first check has none, second has the handshake.
    handshake_checks = iter(["WPA (0 handshake)", "AA:BB:CC:DD:EE:FF HomeLab WPA (1 handshake)"])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        prog = cmd[0]
        if prog == "which":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")
        if prog == "airmon-ng" and cmd[1] == "start":
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:2] == ["iw", "dev"]:
            out = "phy#0\n\tInterface wlan1mon\n\t\ttype monitor\n"
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
        if prog == "airodump-ng" and "--output-format" in cmd:  # timed scan
            # Write the CSV where the tool expects it (prefix + "-01.csv").
            prefix = cmd[cmd.index("--write") + 1]
            (tmp_path / f"{prefix.split('/')[-1]}-01.csv").write_text(SAMPLE_AIRODUMP_CSV)
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))
        if prog == "aireplay-ng":
            return subprocess.CompletedProcess(cmd, 0, stdout="Sending DeAuth", stderr="")
        if prog == "aircrack-ng" and "-w" in cmd:  # final crack
            return subprocess.CompletedProcess(
                cmd, 0, stdout="KEY FOUND! [ correcthorse ]", stderr=""
            )
        if prog == "aircrack-ng":  # handshake presence check
            return subprocess.CompletedProcess(cmd, 0, stdout=next(handshake_checks), stderr="")
        if prog == "hcxpcapngtool":
            out = cmd[cmd.index("-o") + 1]
            pathlib.Path(out).write_text("WPA*02*...")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if prog == "airmon-ng" and cmd[1] == "stop":
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        prefix = cmd[cmd.index("--write") + 1]
        # The targeted (pcap) airodump writes the handshake capture to disk.
        if "handshake" in prefix:
            pathlib.Path(f"{prefix}-01.cap").write_bytes(b"pcap-eapol")
        return _FakeProcess()

    captures = tmp_path / "captures"
    auditor = WifiAuditor(
        interface="wlan1",
        workdir=str(tmp_path),
        authorized=True,
        runner=runner,
        popen=popen,
        sleep=lambda _s: None,
        euid_getter=lambda: 0,  # pretend root
        captures_dir=str(captures),
    )

    result = auditor.run(
        bssid="AA:BB:CC:DD:EE:FF", channel="6", essid="HomeLab",
        wordlist=str(wordlist), deauth_rounds=2,
    )

    assert result.handshake_captured is True
    assert result.key == "correcthorse"
    # Monitor mode was enabled and then torn down.
    assert ["airmon-ng", "start", "wlan1"] in calls
    assert any(c[:2] == ["airmon-ng", "stop"] for c in calls)
    # The capture was retained to the captures dir and exported for hashcat.
    assert result.capture_path and pathlib.Path(result.capture_path).exists()
    assert pathlib.Path(result.capture_path).parent == captures
    assert result.hashcat_path and pathlib.Path(result.hashcat_path).exists()
