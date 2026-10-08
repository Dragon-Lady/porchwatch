"""Read the kernel's existing tables. No resolution, probing or hostname lookup."""
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from .safety import SafeError, bounded_read

ACCEPTED = {"REACHABLE", "STALE", "DELAY", "PERMANENT"}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def mac_address(value):
    if not isinstance(value, str) or not MAC.fullmatch(value):
        raise SafeError("invalid MAC address")
    value = value.lower()
    if value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        raise SafeError("invalid unicast MAC address")
    return value


def randomized(mac):
    return bool(int(mac[:2], 16) & 2)


def ip_address(value):
    # Never accept scoped strings or arbitrary command arguments.
    if not isinstance(value, str) or "%" in value:
        raise ValueError("invalid address")
    return ipaddress.ip_address(value)


def parse_neighbors(rows):
    if not isinstance(rows, list):
        raise SafeError("invalid neighbor table")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        state = row.get("state", [])
        if isinstance(state, str):
            state = state.split(",")
        if not isinstance(state, list) or not state or any(s not in ACCEPTED for s in state):
            continue
        try:
            mac = mac_address(row.get("lladdr"))
            addr = ip_address(row.get("dst"))
        except (SafeError, ValueError):
            continue
        dev = row.get("dev", "")
        if not isinstance(dev, str) or not IFACE.fullmatch(dev) or addr.is_multicast or addr.is_unspecified:
            continue
        item = {"mac": mac, "ip": str(addr), "dev": dev}
        if item not in result:
            result.append(item)
    return result


def parse_arp(text):
    rows = []
    for line in text.splitlines()[1:]:
        bits = line.split()
        if len(bits) != 6:
            continue
        addr, _, flags, mac, _, dev = bits
        try:
            # ATF_COM means complete; incomplete/all-zero entries are skipped.
            if int(flags, 16) & 2:
                rows.append({"dst": addr, "lladdr": mac, "dev": dev, "state": ["STALE"]})
        except ValueError:
            continue
    return parse_neighbors(rows)


def parse_proc_routes(text):
    rows = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8:
            continue
        dev, dst, gateway, flags = cols[:4]
        try:
            if not int(flags, 16) & 1:  # RTF_UP
                continue
            convert = lambda s: str(ipaddress.IPv4Address(int(s, 16).to_bytes(4, "little")))
            address, gw, mask = convert(dst), convert(gateway), convert(cols[7])
            network = ipaddress.IPv4Network((address, mask), strict=True)
            row = {"dst": "default" if network.prefixlen == 0 else str(network), "dev": dev, "table": "main"}
            if gw != "0.0.0.0":
                row["gateway"] = gw
            else:
                row["scope"] = "link"
            rows.append(row)
        except (ValueError, OverflowError):
            continue
    return rows


def run(argv, timeout=5):
    try:
        completed = subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=timeout,
                                   text=True, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        raise SafeError("local network-table command failed") from None
    if len(completed.stdout) > 5 * 1024 * 1024:
        raise SafeError("network-table output limit exceeded")
    return completed.stdout


@dataclass(frozen=True)
class Snapshot:
    interface: str
    gateway: str
    gateway_mac: str
    subnet: str
    neighbors: tuple
    routes: tuple
    rules: tuple | None
    source: str = "ip"
    interfaces: tuple = ()


def select_home(routes, neighbors, rules=None, source="ip"):
    if not isinstance(routes, list) or any(not isinstance(r, dict) for r in routes):
        raise SafeError("invalid routing table")
    main = [r for r in routes if r.get("table", "main") in {"main", 254}]
    defaults = [r for r in main if r.get("dst") in {"default", "0.0.0.0/0"}]
    if not defaults or (len(defaults) > 1 and source != "ip"):
        raise SafeError("default route is missing or ambiguous")
    candidates = []
    for default in defaults:
        dev = default.get("dev", "")
        if (not isinstance(dev, str) or not IFACE.fullmatch(dev) or default.get("multipath")
                or default.get("nexthops") or default.get("nhid") or default.get("flags")
                or default.get("type", "unicast") != "unicast"):
            raise SafeError("default route is not a single interface route")
        try:
            gateway = ip_address(default.get("gateway"))
        except ValueError:
            raise SafeError("default gateway is unknown") from None
        if gateway.version != 4 or gateway.is_unspecified or gateway.is_multicast:
            raise SafeError("an IPv4 default gateway is required")
        networks = set()
        for route in main:
            if (route.get("dev") != dev or route.get("gateway") or route.get("multipath")
                    or route.get("nexthops") or route.get("nhid") or route.get("flags")
                    or route.get("scope") != "link" or route.get("type", "unicast") != "unicast"):
                continue
            try:
                network = ipaddress.IPv4Network(route.get("dst", ""), strict=True)
            except ValueError:
                continue
            if gateway in network:
                networks.add(str(network))
        if len(networks) != 1:
            raise SafeError("connected gateway subnet is missing or ambiguous")
        gateway_macs = {n["mac"] for n in neighbors if n["dev"] == dev and n["ip"] == str(gateway)}
        if len(gateway_macs) != 1:
            raise SafeError("gateway MAC is not in the existing neighbor cache")
        metric = default.get("metric", 0)
        if not isinstance(metric, int) or isinstance(metric, bool) or metric < 0:
            raise SafeError("default route metric is invalid")
        candidates.append((metric, dev, str(gateway), networks.pop(), gateway_macs.pop()))
    if len({candidate[1] for candidate in candidates}) != len(candidates):
        raise SafeError("default interfaces are ambiguous")
    if len({candidate[2:] for candidate in candidates}) != 1:
        raise SafeError("default routes do not identify the same home")
    primary = min(candidates)
    if sum(candidate[0] == primary[0] for candidate in candidates) != 1:
        raise SafeError("default route metrics are ambiguous")
    _, dev, gateway, subnet, gateway_mac = primary
    interfaces = tuple(candidate[1] for candidate in sorted(candidates))
    return Snapshot(dev, gateway, gateway_mac, subnet, tuple(neighbors), tuple(routes),
                    None if rules is None else tuple(rules), source, interfaces)


def collect():
    ip = shutil.which("ip")
    if ip:
        try:
            routes = json.loads(run([ip, "-j", "-4", "route", "show", "table", "all"]))
            neighbors = parse_neighbors(json.loads(run([ip, "-j", "neigh", "show"])))
        except (ValueError, TypeError):
            raise SafeError("invalid network-table JSON") from None
        try:
            rules = json.loads(run([ip, "-j", "-4", "rule", "show"]))
            if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
                rules = None
        except (SafeError, ValueError, TypeError):
            rules = None
        return select_home(routes, neighbors, rules)
    try:
        # procfs files advertise a size of zero; bounded_read still reads to EOF.
        # /proc/net and /proc/self are symlinks. Resolve only this process's
        # numeric proc path; keep the reader's no-follow rule intact.
        proc = Path("/proc") / str(os.getpid()) / "net"
        routes = parse_proc_routes(bounded_read(proc / "route")[0].decode())
        neighbors = parse_arp(bounded_read(proc / "arp")[0].decode())
    except (OSError, ValueError):
        raise SafeError("passive network tables unavailable") from None
    return select_home(routes, neighbors, source="proc")


def devices(snapshot):
    # Keep one deterministic address per MAC, preferring IPv4; no address history.
    selected = [n for n in snapshot.neighbors if n["dev"] in (snapshot.interfaces or (snapshot.interface,))]
    result = {}
    for row in sorted(selected, key=lambda n: (ip_address(n["ip"]).version, int(ip_address(n["ip"])))):
        result.setdefault(row["mac"], row["ip"])
    return result


def validate_active(snapshot):
    if len(snapshot.interfaces) > 1:
        raise SafeError("active discovery requires a single default interface")
    network = ipaddress.IPv4Network(snapshot.subnet)
    if network.prefixlen < 22 or not any(network.subnet_of(private) for private in PRIVATE):
        raise SafeError("active discovery requires a directly connected RFC1918 subnet at /22 or smaller")
    # procfs cannot establish policy-route safety. Require all-table ip evidence.
    if snapshot.source != "ip" or snapshot.rules is None:
        raise SafeError("active discovery requires complete ip routing-policy evidence")
    standard_rules = {(0, "local"), (32766, "main"), (32767, "default")}
    actual = set()
    for rule in snapshot.rules:
        table = {255: "local", 254: "main", 253: "default"}.get(rule.get("table"), rule.get("table"))
        if (set(rule) - {"priority", "src", "table", "protocol"}
                or rule.get("src", "all") not in {"all", "0.0.0.0/0"}):
            raise SafeError("active discovery refused for nonstandard policy routing")
        actual.add((rule.get("priority"), table))
    if actual != standard_rules or len(snapshot.rules) != 3:
        raise SafeError("active discovery refused for ambiguous policy routing")
    # Every overlapping route outside the local table must be the single direct
    # route. This rejects VPN split routes, other interfaces and more-specific
    # routes which could redirect a part of the requested subnet.
    connected = 0
    for route in snapshot.routes:
        table = route.get("table", "main")
        if route.get("dst") in {"default", "0.0.0.0/0"}:
            continue
        try:
            candidate = ipaddress.IPv4Network(route.get("dst", ""), strict=True)
        except ValueError:
            continue
        if not candidate.overlaps(network):
            continue
        if table in {"local", 255}:
            if (candidate.prefixlen != 32 or route.get("type") not in {"local", "broadcast"}
                    or route.get("dev") != snapshot.interface or route.get("gateway")
                    or route.get("multipath") or route.get("nexthops") or route.get("nhid") or route.get("flags")):
                raise SafeError("active discovery refused for an ambiguous local-table route")
            continue
        if (table not in {"main", 254} or candidate != network or route.get("dev") != snapshot.interface
                or route.get("scope") != "link" or route.get("gateway") or route.get("multipath")
                or route.get("nexthops") or route.get("nhid") or route.get("flags")
                or route.get("type", "unicast") != "unicast"):
            raise SafeError("active discovery refused for an overlapping or indirect route")
        connected += 1
    if connected != 1:
        raise SafeError("active discovery requires a unique connected route")
    return str(network)


def active(snapshot):
    subnet = validate_active(snapshot)
    nmap = shutil.which("nmap")
    if not nmap:
        return "nmap not installed; passive fallback"
    # Never consume nmap's hostnames or vendor output. Re-read kernel neighbors.
    run([nmap, "-sn", "-n", subnet], timeout=60)
    return "active discovery completed"
