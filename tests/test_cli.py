from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import stat

import pytest

from porchwatch import alerts, cli, network, safety
from porchwatch.safety import SafeError, fingerprint
from porchwatch.state import FIELDS, Store
from conftest import DEVICE, GATEWAY, RANDOM, fixture_snapshot


def snapshot_tree(root):
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_size,
                                     p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode))
            for p in root.rglob("*") if p.is_file()}


def newcomer(lan, mac=DEVICE):
    lan["snapshot"] = fixture_snapshot([{"mac": mac, "ip": "192.168.50.20", "dev": "eth0"}])


def test_init_imports_known_no_storm(lan, state_path, capsys):
    newcomer(lan)
    assert cli.main(["init", "--format", "json"]) == 0
    init = json.loads(capsys.readouterr().out)
    assert len(init["devices"]) == 2
    assert cli.main(["scan", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["alerts"]["messages"] == []
    for record in json.loads((state_path / "devices.json").read_text()):
        assert set(record) == FIELDS
        assert record["first_seen"].endswith(":00:00Z")
    identity = json.loads((state_path / "home.json").read_text())
    assert identity["gateway_fp"].startswith("fp:")
    assert GATEWAY not in (state_path / "home.json").read_text()


def test_init_imports_both_verified_home_interfaces(lan, capsys):
    routes = [
        {"dst": "default", "gateway": "192.168.50.1", "dev": "eth0", "metric": 100},
        {"dst": "192.168.50.0/24", "dev": "eth0", "scope": "link"},
        {"dst": "default", "gateway": "192.168.50.1", "dev": "wlan0", "metric": 600},
        {"dst": "192.168.50.0/24", "dev": "wlan0", "scope": "link"},
    ]
    neighbors = [
        {"mac": GATEWAY, "ip": "192.168.50.1", "dev": "eth0"},
        {"mac": GATEWAY, "ip": "192.168.50.1", "dev": "wlan0"},
        {"mac": DEVICE, "ip": "192.168.50.20", "dev": "eth0"},
        {"mac": RANDOM, "ip": "192.168.50.21", "dev": "wlan0"},
    ]
    lan["snapshot"] = network.select_home(routes, neighbors)
    assert cli.main(["init", "--format", "json"]) == 0
    assert {r["mac"] for r in json.loads(capsys.readouterr().out)["devices"]} == {GATEWAY, DEVICE, RANDOM}
    assert cli.main(["scan", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["alerts"]["messages"] == []


def test_newcomer_once_then_rescan_no_repeat(lan, capsys):
    assert cli.main(["init"]) == 0
    capsys.readouterr()
    newcomer(lan)
    assert cli.main(["scan", "--format", "json"]) == 1
    first = json.loads(capsys.readouterr().out)
    assert first["newcomers"] == [DEVICE]
    assert len(first["alerts"]["messages"]) == 1
    assert cli.main(["scan", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["alerts"]["messages"] == []
    assert cli.main(["report", "--send", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["alerts"]["messages"] == []


def test_failed_channel_retries_without_repeating_success(lan, config_file, monkeypatch, capsys):
    config_file('alert_channels = ["slack", "ntfy"]\nalert_slack_webhook_env = "PW_TEST_WEBHOOK"\nalert_ntfy_topic = "demo"\n')
    assert cli.main(["init"]) == 0
    newcomer(lan)
    calls = []
    failing = {"slack"}
    def send(channel, cfg, message):
        calls.append((channel, message))
        if channel in failing:
            raise RuntimeError("sensitive provider URL")
    monkeypatch.setattr(alerts, "send_one", send)
    assert cli.main(["scan"]) == 2
    assert [c for c, _ in calls] == ["slack", "ntfy"]
    failing.clear()
    assert cli.main(["scan"]) == 0
    assert [c for c, _ in calls] == ["slack", "ntfy", "slack"]
    assert cli.main(["scan"]) == 0
    assert len(calls) == 3
    assert "sensitive provider URL" not in capsys.readouterr().err
    for _, message in calls:
        assert DEVICE not in message and "192.168." not in message and "demo" not in message
        assert message.endswith("run `porchwatch report` locally for details")


@pytest.mark.parametrize("command", [["label", DEVICE, "Television"], ["known", DEVICE]])
def test_label_and_known_silence_pending(command, lan, config_file, monkeypatch):
    config_file('alert_channels = ["slack"]\nalert_slack_webhook_env = "PW_TEST_WEBHOOK"\n')
    assert cli.main(["init"]) == 0
    newcomer(lan)
    monkeypatch.setattr(alerts, "send_one", lambda *a: (_ for _ in ()).throw(RuntimeError("failed")))
    assert cli.main(["scan"]) == 2
    assert cli.main(command) == 0
    monkeypatch.setattr(alerts, "send_one", lambda *a: pytest.fail("labeled or known must not alert"))
    assert cli.main(["scan"]) == 0
    assert cli.main(["report", "--send"]) == 0


def test_randomized_severity_and_vendor(lan, monkeypatch, capsys):
    monkeypatch.setattr(cli, "vendors", lambda: {"021122": "Incorrect random vendor"})
    assert cli.main(["init"]) == 0
    newcomer(lan, RANDOM)
    capsys.readouterr()
    assert cli.main(["scan", "--format", "json"]) == 1
    result = json.loads(capsys.readouterr().out)
    row = next(r for r in result["devices"] if r["mac"] == RANDOM)
    assert row["randomized"] is True and row["vendor"] == ""
    assert "warn=0; info=1" in result["alerts"]["messages"][0]


@pytest.mark.parametrize("command", ["scan", "report", "list", "label", "known", "forget", "print-timer"])
def test_away_no_writes_alerts_or_output(command, lan, state_path, tmp_path, monkeypatch, capsys):
    assert cli.main(["init"]) == 0
    before = snapshot_tree(state_path)
    lan["snapshot"] = replace(lan["snapshot"], gateway_mac=DEVICE)
    monkeypatch.setattr(alerts, "send_one", lambda *a: pytest.fail("away must not alert"))
    output = tmp_path / "away.html"
    args = [command, "--output", str(output), "--format", "html"]
    if command in {"label", "known", "forget"}: args += [GATEWAY]
    if command == "label": args += ["new label"]
    if command == "report": args += ["--send"]
    capsys.readouterr()
    assert cli.main(args) == 0
    assert "not home" in capsys.readouterr().out
    assert snapshot_tree(state_path) == before
    assert not output.exists()


def test_unknown_home_no_state_key_or_output_creation(lan, state_path, monkeypatch, tmp_path):
    monkeypatch.setattr(network, "collect", lambda: (_ for _ in ()).throw(SafeError("unknown")))
    assert cli.main(["scan", "--output", str(tmp_path / "report")]) == 0
    assert not state_path.exists()
    assert cli.main(["init"]) == 2
    assert not state_path.exists()


def test_missing_key_does_not_regenerate(lan, state_path):
    assert cli.main(["init"]) == 0
    (state_path / "fp.key").unlink()
    before = snapshot_tree(state_path)
    assert cli.main(["scan"]) == 0
    assert snapshot_tree(state_path) == before


def test_changed_subnet_not_home(lan, state_path):
    assert cli.main(["init"]) == 0
    before = snapshot_tree(state_path)
    lan["snapshot"] = replace(lan["snapshot"], subnet="192.168.51.0/24")
    assert cli.main(["scan"]) == 0
    assert snapshot_tree(state_path) == before


def test_away_detected_before_active_no_nmap(lan, monkeypatch):
    assert cli.main(["init"]) == 0
    lan["snapshot"] = replace(lan["snapshot"], gateway_mac=DEVICE)
    monkeypatch.setattr(network, "active", lambda *a: pytest.fail("must not run active"))
    assert cli.main(["scan", "--active"]) == 0


def test_network_change_during_active_no_device_write(lan, monkeypatch, state_path):
    assert cli.main(["init"]) == 0
    before = snapshot_tree(state_path)
    def active(snapshot):
        lan["snapshot"] = replace(snapshot, gateway_mac=DEVICE)
        return "mock active"
    monkeypatch.setattr(network, "active", active)
    assert cli.main(["scan", "--active"]) == 0
    assert snapshot_tree(state_path) == before


def test_init_network_change_creates_nothing(lan, monkeypatch, state_path):
    samples = iter([lan["snapshot"], replace(lan["snapshot"], gateway_mac=DEVICE)])
    monkeypatch.setattr(network, "collect", lambda: next(samples))
    assert cli.main(["init"]) == 2
    assert not state_path.exists()


def test_init_multi_route_churn_creates_nothing(lan, monkeypatch, state_path):
    primary = lan["snapshot"]
    dual = network.select_home(
        [*primary.routes,
         {"dst": "default", "gateway": primary.gateway, "dev": "wlan0", "metric": 600},
         {"dst": primary.subnet, "dev": "wlan0", "scope": "link"}],
        [*primary.neighbors, {"mac": GATEWAY, "ip": primary.gateway, "dev": "wlan0"}])
    monkeypatch.setattr(network, "collect", lambda: next(samples))
    samples = iter([dual, primary])
    assert cli.main(["init"]) == 2
    assert not state_path.exists()


def test_modes_from_creation(lan, monkeypatch, state_path, tmp_path):
    opened = []
    original_open = os.open
    def record(path, flags, mode=0o777, **kw):
        if flags & os.O_CREAT:
            opened.append((path, mode))
        return original_open(path, flags, mode, **kw)
    monkeypatch.setattr(os, "open", record)
    assert cli.main(["init"]) == 0
    newcomer(lan)
    assert cli.main(["scan", "--output", str(tmp_path / "report.json")]) == 1
    assert opened and all(mode == 0o600 for _, mode in opened)
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in state_path.iterdir())
    assert stat.S_IMODE((tmp_path / "report.json").stat().st_mode) == 0o600


def test_no_network_passive_and_read_only_sources(lan, config_file, tmp_path, monkeypatch):
    source = tmp_path / "fixture.txt"
    source.write_text("fixture source, not a target to modify")
    cfg = config_file('alert_channels = ["stdout"]\n')
    def details(p):
        s = p.stat()
        return hashlib.sha256(p.read_bytes()).hexdigest(), s.st_size, s.st_mtime_ns, s.st_mode
    before = {p: details(p) for p in (source, cfg)}
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **kw: pytest.fail("network attempted"))
    monkeypatch.setattr(network.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected child process"))
    for args in (["init"], ["scan"], ["list"], ["report", "--send"], ["known", GATEWAY],
                 ["label", GATEWAY, "Router"], ["print-timer"], ["forget", GATEWAY]):
        assert cli.main(args) == 0
    assert {p: details(p) for p in (source, cfg)} == before


@pytest.mark.parametrize("fmt", ["text", "json", "md", "html"])
def test_all_commands_canary_safe(fmt, lan, config_file, monkeypatch, state_path, tmp_path, capsys):
    # Split provider markers keep defensive fixtures safe for the real push guard.
    token = "gh" + "p_" + "A7b3K9z1" * 5
    webhook = "https://hooks." + "slack.com/services/" + "TTEST/BTEST/secret-canary"
    monkeypatch.setenv("PW_TEST_WEBHOOK", webhook)
    config_file('alert_channels = ["stdout", "slack"]\nalert_slack_webhook_env = "PW_TEST_WEBHOOK"\n')
    sent = []
    monkeypatch.setattr(alerts, "send_one", lambda channel, cfg, text: sent.append(text))
    monkeypatch.setattr(cli, "vendors", lambda: {"001122": token})
    operations = [["init"], ["scan"], ["label", GATEWAY, "<script>alert(1)</script> " + token + " " + webhook],
                  ["known", GATEWAY], ["list"], ["report", "--send"], ["print-timer"], ["forget", GATEWAY]]
    for i, args in enumerate(operations):
        if args[0] == "scan":
            newcomer(lan)
        assert cli.main([*args, "--format", fmt, "--output", str(tmp_path / f"result{i}.{fmt}")]) == int(args[0] == "scan")
    captured = capsys.readouterr()
    text = captured.out + captured.err + "".join(sent)
    for root in (state_path, tmp_path):
        for file in root.rglob("*"):
            if file.is_file() and file.name != "fp.key" and file.suffix != ".toml":
                text += file.read_text(errors="ignore")
    assert token not in text and webhook not in text
    assert sent
    assert all(DEVICE not in payload and GATEWAY not in payload and "192.168." not in payload for payload in sent)
    if fmt == "html":
        report = (tmp_path / "result4.html").read_text()
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
        assert "<script>" not in report


def test_canary_invalid_arguments_static_errors(lan, capsys):
    token = "gh" + "p_" + "Qw12" * 12
    for args in ([token], ["scan", "--format", token], ["known", token], ["report", "--since", token]):
        assert cli.main(args) in {0, 2}
    assert token not in str(capsys.readouterr())


def test_forget_removes_record_and_allows_new_notice(lan, capsys):
    assert cli.main(["init"]) == 0
    newcomer(lan)
    assert cli.main(["scan"]) == 1
    assert cli.main(["forget", DEVICE]) == 0
    capsys.readouterr()
    assert cli.main(["scan", "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["newcomers"] == [DEVICE]


def test_unlabeled_and_since_filter(lan, capsys):
    assert cli.main(["init"]) == 0
    newcomer(lan)
    assert cli.main(["scan"]) == 1
    assert cli.main(["label", GATEWAY, "Router"]) == 0
    capsys.readouterr()
    assert cli.main(["list", "--unlabeled", "--since", "7d", "--format", "json"]) == 0
    assert [r["mac"] for r in json.loads(capsys.readouterr().out)["devices"]] == [DEVICE]


def test_output_never_overwrites_scanned_or_state_files(lan, tmp_path, state_path):
    assert cli.main(["init"]) == 0
    output = tmp_path / "keep.txt"
    output.write_text("keep me")
    assert cli.main(["list", "--output", str(output)]) == 2
    assert output.read_text() == "keep me"
    assert cli.main(["list", "--output", str(state_path / "other.json")]) == 2
    assert not (state_path / "other.json").exists()


def test_timers_print_no_init_or_commands(monkeypatch, state_path, capsys):
    monkeypatch.setattr(network, "collect", lambda: pytest.fail("timer does not collect"))
    assert cli.main(["print-timer", "--interval", "15m"]) == 0
    text = capsys.readouterr().out
    assert "OnUnitActiveSec=15m" in text and "ExecStart=%h/.local/bin/porchwatch scan" in text
    assert "--active" not in text and not state_path.exists()


def test_state_symlink_cannot_redirect_writes(lan, state_path, tmp_path):
    state_path.parent.mkdir(parents=True)
    target = tmp_path / "protected"
    target.mkdir()
    state_path.symlink_to(target, target_is_directory=True)
    assert cli.main(["init"]) == 2
    assert list(target.iterdir()) == []


def test_report_parent_symlink_rejected(lan, tmp_path):
    assert cli.main(["init"]) == 0
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    assert cli.main(["list", "--output", str(link / "report")]) == 2
    assert list(target.iterdir()) == []


def test_config_invalid_inline_webhook_is_not_echoed(lan, config_file, capsys):
    value = "https://example.invalid/secret-value"
    config_file('alert_slack_webhook = "' + value + '"\n')
    assert cli.main(["init"]) == 2
    assert value not in str(capsys.readouterr())


def test_init_will_not_overwrite_existing_state(lan, state_path):
    assert cli.main(["init"]) == 0
    before = snapshot_tree(state_path)
    assert cli.main(["init"]) == 2
    assert snapshot_tree(state_path) == before
