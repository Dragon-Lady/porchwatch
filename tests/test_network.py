from dataclasses import replace
import json
import subprocess

import pytest

from porchwatch import network
from porchwatch.safety import SafeError
from conftest import DEVICE, GATEWAY, RANDOM, fixture_snapshot


@pytest.mark.parametrize("state", ["REACHABLE", "STALE", "DELAY", "PERMANENT"])
@pytest.mark.parametrize("address", ["192.168.50.20", "fe80::a", "2001:db8::1"])
def test_neighbor_supported_states_and_ipv6(state, address):
    rows = [{"dst": address, "lladdr": DEVICE, "dev": "eth0", "state": [state]}] * 2
    assert network.parse_neighbors(rows) == [{"ip": address, "mac": DEVICE, "dev": "eth0"}]


@pytest.mark.parametrize("state", ["FAILED", "INCOMPLETE", "PROBE", "NOARP", "NONE", "bad"])
def test_neighbor_ignored_states(state):
    assert network.parse_neighbors([{"dst": "192.168.50.2", "lladdr": DEVICE, "dev": "eth0", "state": [state]}]) == []


@pytest.mark.parametrize("mac", ["ff:ff:ff:ff:ff:ff", "01:11:22:33:44:55", "00:00:00:00:00:00", "bad", None])
def test_invalid_mac(mac):
    with pytest.raises(SafeError):
        network.mac_address(mac)


def test_randomized_and_globally_administered():
    assert network.randomized(RANDOM)
    assert not network.randomized(DEVICE)


def test_dedupe_and_only_default_interface():
    s = fixture_snapshot([
        {"mac": DEVICE, "ip": "fe80::a", "dev": "eth0"},
        {"mac": DEVICE, "ip": "192.168.50.20", "dev": "eth0"},
        {"mac": RANDOM, "ip": "10.0.0.3", "dev": "other0"},
    ])
    assert network.devices(s) == {GATEWAY: "192.168.50.1", DEVICE: "192.168.50.20"}


def test_parse_proc_ipv4_fallback():
    arp = "IP address HW type Flags HW address Mask Device\n192.168.50.1 0x1 0x2 00:11:22:33:44:55 * eth0\n192.168.50.2 0x1 0x0 00:00:00:00:00:00 * eth0\n"
    route = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0132A8C0 0003 0 0 100 00000000 0 0 0\neth0 0032A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n"
    snap = network.select_home(network.parse_proc_routes(route), network.parse_arp(arp), source="proc")
    assert snap.gateway == "192.168.50.1"
    assert snap.subnet == "192.168.50.0/24"
    with pytest.raises(SafeError, match="policy"):
        network.validate_active(snap)


def test_collect_only_read_commands(monkeypatch):
    commands = []
    snapshot = fixture_snapshot()
    monkeypatch.setattr(network.shutil, "which", lambda name: "/test/ip" if name == "ip" else None)
    def run(argv, timeout=5):
        commands.append(argv)
        if "route" in argv:
            return json.dumps(snapshot.routes)
        if "rule" in argv:
            return json.dumps(snapshot.rules)
        return json.dumps([{"dst": snapshot.gateway, "lladdr": GATEWAY, "dev": "eth0", "state": ["STALE"]}])
    monkeypatch.setattr(network, "run", run)
    assert network.collect().gateway_mac == GATEWAY
    assert commands == [["/test/ip", "-j", "-4", "route", "show", "table", "all"],
                        ["/test/ip", "-j", "neigh", "show"],
                        ["/test/ip", "-j", "-4", "rule", "show"]]


@pytest.mark.parametrize("change", ["no-default", "multiple-defaults", "missing-gateway", "missing-interface", "multipath", "no-connected", "wrong-interface", "unknown-mac", "conflicting-mac", "nhid", "linkdown"])
def test_home_evidence_fails_closed(change):
    base = fixture_snapshot()
    routes = [dict(r) for r in base.routes]
    neighbors = list(base.neighbors)
    if change == "no-default": routes.pop(0)
    if change == "multiple-defaults": routes.append(dict(routes[0], dev="other0"))
    if change == "missing-gateway": routes[0].pop("gateway")
    if change == "missing-interface": routes[0].pop("dev")
    if change == "multipath": routes[0]["multipath"] = [{"dev": "eth0"}]
    if change == "no-connected": routes.pop(1)
    if change == "wrong-interface": routes[1]["dev"] = "other0"
    if change == "unknown-mac": neighbors.clear()
    if change == "conflicting-mac": neighbors.append(dict(neighbors[0], mac=DEVICE))
    if change == "nhid": routes[0]["nhid"] = 9
    if change == "linkdown": routes[1]["flags"] = ["linkdown"]
    with pytest.raises(SafeError):
        network.select_home(routes, neighbors)


@pytest.mark.parametrize("subnet", ["8.8.8.0/24", "192.168.0.0/16", "10.0.0.0/21", "100.64.0.0/24", "127.0.0.0/24", "169.254.0.0/24", "198.18.0.0/24"])
def test_active_refuses_non_rfc1918_and_broad(subnet):
    with pytest.raises(SafeError):
        network.validate_active(replace(fixture_snapshot(), subnet=subnet))


@pytest.mark.parametrize("subnet", ["192.168.48.0/22", "172.16.1.0/24", "10.0.0.0/30"])
def test_active_accepts_private_small_connected(subnet):
    import ipaddress
    s = fixture_snapshot()
    gateway = str(next(ipaddress.ip_network(subnet).hosts()))
    routes = ({"dst": "default", "dev": "eth0", "gateway": gateway},
              {"dst": subnet, "scope": "link", "dev": "eth0"})
    assert network.validate_active(replace(s, subnet=subnet, gateway=gateway, routes=routes)) == subnet


@pytest.mark.parametrize("change", ["wrong-interface", "overlap", "vpn", "policy", "no-rules", "multipath", "duplicate", "other-table"])
def test_active_refuses_route_ambiguity(change):
    s = fixture_snapshot()
    routes, rules = [dict(r) for r in s.routes], [dict(r) for r in s.rules]
    if change == "wrong-interface": routes[1]["dev"] = "other0"
    if change == "overlap": routes.append({"dst": "192.168.50.0/25", "dev": "eth0", "scope": "link"})
    if change == "vpn": routes.append({"dst": "192.168.0.0/16", "dev": "tun0", "scope": "link"})
    if change == "policy": rules.append({"priority": 100, "src": "all", "table": 52})
    if change == "no-rules": rules = None
    if change == "multipath": routes[1]["multipath"] = [{"dev": "eth0"}]
    if change == "duplicate": routes.append(dict(routes[1]))
    if change == "other-table": routes[1]["table"] = 52
    with pytest.raises(SafeError):
        network.validate_active(replace(s, routes=tuple(routes), rules=None if rules is None else tuple(rules)))


def test_exact_active_argv_mock_only(monkeypatch):
    commands = []
    monkeypatch.setattr(network.shutil, "which", lambda name: "/test/nmap")
    monkeypatch.setattr(network, "run", lambda argv, timeout: commands.append((argv, timeout)))
    assert network.active(fixture_snapshot()) == "active discovery completed"
    assert commands == [(["/test/nmap", "-sn", "-n", "192.168.50.0/24"], 60)]


@pytest.mark.parametrize("route", [
    {"dst": "192.168.50.2/32", "table": "local", "dev": "other0", "type": "local"},
    {"dst": "192.168.50.0/24", "table": "local", "dev": "eth0", "type": "local"},
    {"dst": "192.168.50.2/32", "table": "local", "dev": "eth0", "type": "blackhole"},
])
def test_active_rejects_ambiguous_local_routes(route):
    snap = fixture_snapshot()
    with pytest.raises(SafeError):
        network.validate_active(replace(snap, routes=(*snap.routes, route)))


def test_active_allows_ordinary_local_and_broadcast_routes():
    snap = fixture_snapshot()
    routes = (*snap.routes,
              {"dst": "192.168.50.2/32", "table": "local", "dev": "eth0", "type": "local"},
              {"dst": "192.168.50.255/32", "table": "local", "dev": "eth0", "type": "broadcast"})
    assert network.validate_active(replace(snap, routes=routes)) == "192.168.50.0/24"


def test_missing_nmap_passive_fallback(monkeypatch):
    monkeypatch.setattr(network.shutil, "which", lambda name: None)
    monkeypatch.setattr(network, "run", lambda *a, **kw: pytest.fail("must not execute"))
    assert network.active(fixture_snapshot()) == "nmap not installed; passive fallback"


def test_subprocess_wrapper_safe_error(monkeypatch):
    def fail(*a, **kw):
        raise subprocess.CalledProcessError(1, "sensitive output")
    monkeypatch.setattr(network.subprocess, "run", fail)
    with pytest.raises(SafeError, match="local network-table command failed"):
        network.run(["ip"])
