from __future__ import annotations

import subprocess

import pytest

import autocrack
from autocrack import (
    AccessPoint,
    AuthorizationError,
    NotRootError,
    ToolNotFoundError,
    WifiAuditor,
    build_parser,
    parse_airodump_csv,
    parse_crack_key,
    parse_monitor_interface,
    scan_has_handshake,
)


def _tools_present_runner(cmd, **kwargs):
    """A runner where `which` finds every tool (for tests past preflight)."""
    if cmd[0] == "which":
        return subprocess.CompletedProcess(cmd, 0, stdout=f"/usr/sbin/{cmd[1]}", stderr="")
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

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


# --- interfering processes (check kill) -----------------------------------


def test_enable_monitor_kills_interfering_processes_by_default():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["airmon-ng", "start"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="on [phy0]wlan0mon)\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    WifiAuditor(interface="wlan0", workdir="/tmp/x", authorized=True, runner=runner).enable_monitor()

    assert ["airmon-ng", "check", "kill"] in calls


def test_enable_monitor_can_skip_check_kill():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["airmon-ng", "start"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="on [phy0]wlan0mon)\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    auditor = WifiAuditor(
        interface="wlan0", workdir="/tmp/x", authorized=True, runner=runner, check_kill=False
    )
    auditor.enable_monitor()

    assert ["airmon-ng", "check", "kill"] not in calls


# --- stale capture files --------------------------------------------------


def test_scan_ignores_stale_csv_from_a_previous_run(tmp_path):
    # A leftover dump from an earlier run must not be reported as this scan's
    # result once the new scan finds nothing.
    (tmp_path / "scan-01.csv").write_text(SAMPLE_AIRODUMP_CSV)

    def runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)  # airodump ran, wrote nothing new

    auditor = WifiAuditor(
        interface="wlan0", workdir=str(tmp_path), authorized=True, runner=runner
    )

    assert auditor.scan(seconds=1) == []


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


class _FakeProcess:
    """Stand-in for a backgrounded airodump-ng Popen handle."""

    def __init__(self, cap_path):
        self._cap_path = cap_path
        self.terminated = False

    def poll(self):
        return None if not self.terminated else 0

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0


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
            out = "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
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
        if prog == "airmon-ng" and cmd[1] == "stop":
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def popen(cmd, **kwargs):
        prefix = cmd[cmd.index("--write") + 1]
        return _FakeProcess(f"{prefix}-01.cap")

    auditor = WifiAuditor(
        interface="wlan0",
        workdir=str(tmp_path),
        authorized=True,
        runner=runner,
        popen=popen,
        sleep=lambda _s: None,
        euid_getter=lambda: 0,  # pretend root
    )

    result = auditor.run(
        bssid="AA:BB:CC:DD:EE:FF", channel="6", wordlist=str(wordlist), deauth_rounds=2
    )

    assert result.handshake_captured is True
    assert result.key == "correcthorse"
    # Monitor mode was enabled and then torn down.
    assert ["airmon-ng", "start", "wlan0"] in calls
    assert any(c[:2] == ["airmon-ng", "stop"] for c in calls)
