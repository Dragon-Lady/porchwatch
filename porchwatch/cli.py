"""Local-first command line. Runtime errors never echo source data or arguments."""
import argparse
from datetime import datetime, timedelta, timezone
import html
import json
import os
from pathlib import Path
import re
import sys

from . import alerts, network
from .config import load_config, locations
from .safety import Redactor, SafeError, absolute, bounded_read, fingerprint, write_private
from .state import Store


class NotHome(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's standard errors echo untrusted values, including secret labels.
        raise SafeError("invalid command or option; run porchwatch --help")


def parser():
    p = Parser(prog="porchwatch", description="Watch the existing home-LAN neighbor cache; no telemetry.")
    p.add_argument("--config", type=Path, help="private TOML config path")
    p.add_argument("--version", action="version", version="porchwatch 0.1.0")
    sub = p.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name in ("init", "scan", "list", "label", "known", "forget", "report", "print-timer"):
        command = sub.add_parser(name)
        command.add_argument("--format", choices=("text", "json", "md", "html"), default="text")
        command.add_argument("--output", type=Path, help="create a new 0600 report file; never overwrite")
        if name == "scan":
            command.add_argument("--active", action="store_true", help="opt-in local host discovery, subject to strict routing checks")
        if name == "list":
            command.add_argument("--unlabeled", action="store_true")
        if name in {"list", "report"}:
            command.add_argument("--since", help="last-seen window, e.g. 7d or 24h (UTC, hour precision)")
        if name == "report":
            command.add_argument("--send", action="store_true", help="send only unacknowledged, undelivered newcomer alerts")
        if name in {"label", "known", "forget"}:
            command.add_argument("mac")
        if name == "label":
            command.add_argument("label")
        if name == "print-timer":
            command.add_argument("--interval", default="10m")
    return p


def duration(value):
    match = re.fullmatch(r"([1-9][0-9]{0,5})([smhd])", value or "")
    if not match:
        raise SafeError("invalid duration; use a positive number followed by s, m, h or d")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    if seconds > 366 * 86400:
        raise SafeError("duration must be at most 366 days")
    return seconds


def now_hour():
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def redactor(key, cfg):
    result = Redactor(key)
    result.discover(cfg)
    for field, name in cfg.items():
        if field.endswith("_env") and isinstance(name, str):
            result.add(os.environ.get(name, ""))
    return result


def vendors():
    result = {}
    for source in (Path("/usr/share/ieee-data/oui.txt"), Path("/usr/share/nmap/nmap-mac-prefixes")):
        try:
            data = bounded_read(source)[0].decode("utf-8", errors="replace")
        except (OSError, SafeError):
            continue
        for line in data.splitlines():
            match = re.match(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
            if match:
                result["".join(match.group(i) for i in (1, 2, 3)).lower()] = match[4][:2048]
                continue
            match = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
            if match:
                result[match[1].lower()] = match[2][:2048]
        if result:
            break
    return result


def row(mac, ip, hour, oui, clean):
    random = network.randomized(mac)
    vendor = "" if random else oui.get(mac.replace(":", "")[:6], "")
    clean.discover(vendor)
    return {"mac": mac, "last_ip": ip, "first_seen": hour, "last_seen": hour,
            "label": "", "vendor": clean.clean(vendor), "randomized": random}


def guard(store):
    # A failed read is unknown home, never an invitation to probe the gateway.
    try:
        snapshot = network.collect()
        matches = store.matches(snapshot)
    except (SafeError, OSError, ValueError, TypeError):
        raise NotHome from None
    if not matches:
        raise NotHome
    return snapshot


def sanitize_records(records, clean):
    for record in records:
        for field in ("label", "vendor"):
            clean.discover(record[field])
    return clean.clean(records)


def filtered(records, args):
    result = records
    if getattr(args, "unlabeled", False):
        result = [r for r in result if not r["label"]]
    if getattr(args, "since", None):
        minimum = datetime.now(timezone.utc) - timedelta(seconds=duration(args.since))
        # Stored dates are validated by strptime, not lexicographic assumptions.
        result = [r for r in result if datetime.strptime(r["last_seen"], "%Y-%m-%dT%H:00:00Z").replace(tzinfo=timezone.utc) >= minimum]
    return result


def timer(interval):
    duration(interval)
    return ("# porchwatch.service\n[Unit]\nDescription=Porch Watch passive home-LAN check\n\n"
            "[Service]\nType=oneshot\nExecStart=%h/.local/bin/porchwatch scan\n"
            "SuccessExitStatus=1\nUMask=0077\n\n"
            "# porchwatch.timer\n[Unit]\nDescription=Check the home-LAN neighbor cache\n\n"
            f"[Timer]\nOnBootSec=2m\nOnUnitActiveSec={interval}\nPersistent=false\n\n"
            "[Install]\nWantedBy=timers.target\n")


def render(result, fmt):
    encoded = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True)
    if fmt == "json":
        return encoded + "\n"
    if fmt == "html":
        return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Porch Watch</title>"
                "<h1>Porch Watch</h1><pre>" + html.escape(encoded) + "</pre></html>\n")
    if fmt == "md":
        # Escaped JSON inside HTML prevents user labels from breaking a code fence.
        return "# Porch Watch\n\n<pre>" + html.escape(encoded) + "</pre>\n"
    if "units" in result:
        return result["units"]
    lines = ["Porch Watch: " + result["status"]]
    if result.get("message"):
        lines.append(result["message"])
    for record in result.get("devices", []):
        detail = "randomized; phones may rotate private MACs" if record["randomized"] else (record["vendor"] or "vendor unknown")
        lines.append(f"{record['mac']}  {record['last_ip']}  {record['label'] or '(unlabeled)'}  {detail}  last seen {record['last_seen']}")
    for message in result.get("alerts", {}).get("messages", []):
        lines.append(message)
    if result.get("alerts", {}).get("failed"):
        lines.append("Alert delivery failed; run scan or report --send to retry.")
    return "\n".join(lines) + "\n"


def execute(args, cfg, store):
    if getattr(args, "since", None):
        duration(args.since)
    if args.command == "print-timer":
        if args.output:
            # Printing never needs network tables; writing still requires home.
            guard(store)
        return {"status": "timer printed; nothing installed", "units": timer(args.interval)}, 0
    if args.command == "init":
        if any((store.path / name).exists() for name in ("home.json", "devices.json", "fp.key", "alerts.json")):
            raise SafeError("state already exists; init will not replace it")
        try:
            snapshot = network.collect()
            confirmed = network.collect()
        except (SafeError, OSError, ValueError, TypeError):
            raise SafeError("cannot initialize: home gateway is unknown in the existing cache") from None
        if (snapshot.gateway_mac, snapshot.subnet, snapshot.interface) != (confirmed.gateway_mac, confirmed.subnet, confirmed.interface):
            raise SafeError("cannot initialize: network identity changed")
        store.initialize_key()
        with store.lock():
            clean = redactor(store.key, cfg)
            hour, oui = now_hour(), vendors()
            records = [row(mac, ip, hour, oui, clean) for mac, ip in sorted(network.devices(confirmed).items())]
            store.save("devices.json", records)
            store.save("alerts.json", {"known": [fingerprint(store.key, r["mac"]) for r in records], "receipts": {}})
            # Identity written last: an interrupted init never enables scanning.
            store.save("home.json", {"gateway_fp": fingerprint(store.key, confirmed.gateway_mac), "subnet": confirmed.subnet})
        return {"status": "initialized", "message": "Current devices imported as known; no alerts sent.", "devices": records}, 0
    # Never initialize state, generate a key, write a lock or report, or alert
    # until a current existing-neighbor identity matches the saved home identity.
    snapshot = guard(store)
    with store.lock():
        snapshot = guard(store)
        clean = redactor(store.key, cfg)
        records = sanitize_records(store.records(), clean)
        tracking = store.tracking()
        if args.command in {"list", "report"}:
            result = {"status": "report", "devices": filtered(records, args),
                      "message": "Times are UTC to the hour. Randomized MACs may be rotated by phones."}
            if args.command == "report" and args.send:
                result["alerts"] = alerts.deliver(cfg, store, result["devices"], tracking, lambda: guard(store))
            return result, 2 if result.get("alerts", {}).get("failed") else 0
        if args.command in {"label", "known", "forget"}:
            mac = network.mac_address(args.mac)
            target = next((r for r in records if r["mac"] == mac), None)
            if target is None:
                raise SafeError("device not found")
            identity = fingerprint(store.key, mac)
            if args.command == "forget":
                records = [r for r in records if r["mac"] != mac]
                tracking["known"] = [item for item in tracking["known"] if item != identity]
                tracking["receipts"].pop(identity, None)
            else:
                if args.command == "label":
                    if len(args.label) > 2048:
                        raise SafeError("label is too long")
                    clean.discover(args.label)
                    target["label"] = clean.clean(args.label)
                if identity not in tracking["known"]:
                    tracking["known"].append(identity)
            guard(store)
            store.save("devices.json", records)
            store.save("alerts.json", tracking)
            return {"status": args.command + " complete", "devices": records}, 0
        note = "Passive cache read; no packets sent."
        if args.active:
            # Recollect immediately before validation/execution and again after.
            snapshot = guard(store)
            note = network.active(snapshot)
            snapshot = guard(store)
        records_by_mac = {r["mac"]: r for r in records}
        fresh = []
        hour, oui = now_hour(), vendors()
        for mac, ip in sorted(network.devices(snapshot).items()):
            if mac not in records_by_mac:
                fresh.append(mac)
                records_by_mac[mac] = row(mac, ip, hour, oui, clean)
            records_by_mac[mac]["last_ip"] = ip
            records_by_mac[mac]["last_seen"] = hour
        records = sorted(records_by_mac.values(), key=lambda r: r["mac"])
        guard(store)
        store.save("devices.json", records)
        delivered = alerts.deliver(cfg, store, records, tracking, lambda: guard(store))
        return {"status": "newcomers" if fresh else "no newcomers", "newcomers": fresh,
                "devices": records, "message": note, "alerts": delivered}, 2 if delivered["failed"] else int(bool(fresh))


def main(argv=None):
    args = None
    try:
        args = parser().parse_args(argv)
        config_path, state_path = locations()
        cfg = load_config(args.config or config_path)
        store = Store(state_path)
        result, code = execute(args, cfg, store)
        output = render(result, args.format)
        if args.output:
            guard(store)
            destination = absolute(args.output)
            # Reports cannot be placed within or replace tool state.
            if destination.is_relative_to(store.path):
                raise SafeError("report destination must be outside tool state")
            write_private(destination, output)
        print(output, end="")
        return code
    except NotHome:
        print(render({"status": "not home"}, args.format if args else "text"), end="")
        return 0
    except SafeError as exc:
        print("Porch Watch: " + str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        print("Porch Watch: unreadable or invalid input; no sensitive details displayed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
