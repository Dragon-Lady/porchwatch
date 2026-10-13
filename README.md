# Porch Watch

Porch Watch notices new MAC addresses in the existing home-LAN neighbor cache.
Initialize it once at home to mark current devices as known, then review newcomer
notices and add your own labels. A randomized MAC gets an informational notice:
phones often rotate private MACs, so a new address need not mean a new device.

Built and maintained by Dragon Lady — [GitHub](https://github.com/Dragon-Lady).

## Posture

- Linux first, Python 3.10 or newer. Apache-2.0.
- Passive by default: reads kernel neighbor/routing tables without sending
  discovery packets. No telemetry, DNS lookups, hostnames, mDNS, DHCP scraping,
  router login, blocking, port scans, OS fingerprinting, or service discovery.
- Only its own state and explicitly requested local reports are written.
  Configuration and local vendor tables are read-only. There is no root use.
- Alert delivery is opt-in through `alert_channels`. Active host discovery is
  separately opt-in with `scan --active`. Neither is enabled by a printed timer.
- Local state/report metadata includes MACs, last IPs, user labels, vendor,
  randomized flag, and first/last observation rounded down to the UTC hour.
  These reports are private. No packet contents or address history are kept.
- Off-box alerts contain only newcomer counts, rule ID, and severity. They never
  contain MACs, IPs, labels, vendors, paths, hostnames, or machine identifiers.
- Recognized provider-token shapes in labels/vendor text and configured alert
  credentials are replaced by keyed fingerprints. Never enter passwords or
  arbitrary secrets as device labels: this is not a general secret detector.
- The home gateway uses an HMAC-SHA256 fingerprint (`fp:` plus 16 hex digits)
  with a private random 32-byte key. No plain hash is used.
- State directory: 0700. Every state/report file: 0600 at creation. Unsafe
  existing modes are refused; source permissions are never changed. Reports
  are create-only and cannot overwrite an existing file or tool state.

## Install

Install the published package, or install from a source checkout:

```sh
python3 -m pip install porchwatch==0.1.2
```

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/porchwatch --help
```

Runtime uses the standard library and `tomli` only on Python 3.10. Building uses
setuptools; tests use pytest. No packages are installed during a scan. On Linux,
iproute2 supplies the passive `ip` commands; nmap is optional and is never
installed or elevated by Porch Watch.

## Commands

Run `init` only while connected to the home network you intend to monitor. It
trusts that network as home; it cannot determine that a network belongs to you.

```sh
porchwatch init
porchwatch scan
porchwatch scan --format html --output porchwatch-report.html
porchwatch list --unlabeled --since 7d
porchwatch label 00:11:22:33:44:66 "Living room TV"
porchwatch known 00:11:22:33:44:66
porchwatch report --since 7d
porchwatch report --send
porchwatch forget 00:11:22:33:44:66
porchwatch print-timer --interval 15m
```

All commands accept `--format text|json|md|html` and `--output FILE`. Output is
also printed to stdout. Labels are escaped in HTML/Markdown output; text output
removes control characters. `--since` filters by last observation, with UTC-hour
precision; it is not a scan-history view. `report --send` retries only pending
notices in that report's selected window.

`init` imports every current device as unlabeled-known and sends no alerts. It
will never overwrite existing initialization. Each subsequently discovered MAC
is alerted once per configured channel. Successful channel receipts persist;
failed channels retry on `scan` or `report --send`. Labeling or marking a device
known suppresses pending notices. Forgetting removes its record and delivery
receipts, allowing a fresh notice if it is observed again. Changing/rotating a
channel's destination does not replay already delivered notices for that channel.

For a first home baseline, keep remote alert channels disabled, run `init` while
present on the intended network, and review `list` before configuring delivery
or a timer. The operator decides which devices are normal; the tool cannot make
that judgment.

Exit status: `0` no newly observed MACs (or not home), `1` newcomer(s), `2`
usage/runtime/alert-delivery error. An alert failure does not drop the newcomer:
the next run retries it. A fresh scan with only already-notified devices exits 0.

## Home-network guard

Before writing state, a key, a report, or delivery receipts, and before sending
alerts, Porch Watch requires an existing neighbor-cache MAC for the IPv4 default
gateway. A connected gateway subnet must be present. Multiple default interfaces
are accepted for passive checks only when each independently has the same gateway
address, gateway MAC, and connected subnet, with one unique lowest route metric.
Their neighbor caches are combined. This exception requires `iproute2`; the proc
fallback and all other multiple-route cases are refused.
The gateway fingerprint and subnet must match the initialized home identity.
Missing, ambiguous, or mismatched identity yields `not home`, exit 0, no alert,
and no writes. `init` with insufficient evidence exits 2 and creates nothing.
It never probes a missing gateway to make the guard pass.

The guard also covers `label`, `known`, `forget`, and report file output. Lists
and local reports conservatively return `not home` when identity is unknown.
Printing a timer to stdout needs no network or initialization. An interrupted
initialization or missing key is not silently repaired; preserve the state for
inspection and recovery. Deliberately re-initializing on a different network
requires you to archive the old private state yourself.

Home identity is advisory: cached entries can be stale, MACs can be spoofed, and
a router replacement looks like a different home. Checks are snapshots, repeated
before active discovery, state writes, and alert delivery; no user-space tool can
atomically bind routing changes and an external delivery transaction. A crash
after remote acceptance but before saving a receipt can produce a retry. There
is no claim of exactly-once delivery across crashes or provider timeouts.

## Passive and active coverage

Passive mode runs only these read operations (actual executable path resolved
locally):

```text
ip -j -4 route show table all
ip -j neigh show
ip -j -4 rule show
```

Neighbor states REACHABLE, STALE, DELAY, and PERMANENT are accepted. FAILED,
INCOMPLETE, and other states are ignored. IPv4 and IPv6 cache entries on the
selected interface are deduplicated by MAC; one deterministic last IP is stored,
preferring IPv4. IPv6-only home-gateway initialization is not supported in v0.1.
Without `ip`, `/proc/net/route` and `/proc/net/arp` provide an IPv4-only passive
fallback; proc files are accessed through this process's numeric proc directory
to avoid following `/proc/net` symlinks. No root or nmap is needed for passive use.
Cache visibility is limited: a silent device may never appear, and a disappearing
device is not considered removed. This is not an exhaustive network inventory.

For an explicit local host-discovery run:

```sh
porchwatch scan --active
```

The only permitted discovery command is `nmap -sn -n <subnet>`. Active discovery
requires a single default interface. There is no user-supplied target,
additional flag, port scan, DNS, or privilege elevation.
Only an exact, directly connected RFC1918 IPv4 subnet on the default-route
interface, at /22 or smaller, passes. All-table route evidence and standard
IPv4 policy rules are required. Public, CGNAT, link-local, overly broad,
overlapping, other-interface, multipath, or policy-routing ambiguity fails closed.
The proc fallback cannot authorize active mode. If the subnet is safe but nmap
is missing, the command reports `nmap not installed; passive fallback`.

After discovery, Porch Watch rechecks home identity and reads the kernel cache;
it does not ingest nmap's output or hostnames. Unprivileged nmap host discovery
may use TCP connection probes and may find fewer devices than privileged ARP
discovery. `-sn` disables the port-scan phase; it does not mean no TCP packets.
See the [ip neighbor manual](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html)
and [nmap host-discovery reference](https://nmap.org/book/man-host-discovery.html).

Vendor lookup uses only `/usr/share/ieee-data/oui.txt` or
`/usr/share/nmap/nmap-mac-prefixes` if present and under the 5 MB read limit.
Locally administered MACs do not receive an OUI vendor guess. Missing vendor
data is harmless; it is never downloaded.

## Configuration and state

Configuration defaults to `~/.config/porchwatch/config.toml`; state defaults to
`~/.local/state/porchwatch/`. `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are respected.
An alternate config is selected before the command:

```sh
porchwatch --config ~/.config/porchwatch/config.toml scan
```

Configuration must be owned by the current user, 0600, and a regular file.
Porch Watch does not create or edit it. [examples/config.toml](examples/config.toml)
documents the accepted keys. An absent config, empty `alert_channels`, or
`["stdout"]` keeps alert handling local. There are no per-MAC remote payloads.

Slack webhooks, ntfy tokens, and SMTP passwords come from environment variable
**names**, never inline config credentials. HTTP endpoints require HTTPS except
on literal loopback/localhost; redirects are rejected. SMTP requires TLS except
on loopback. Delivery has a 5-second timeout per channel. Error messages do not
echo provider errors, URLs, labels, or credential values.

Private state consists of:

| File | Contents |
| --- | --- |
| `devices.json` | Only MAC, first_seen, last_seen, label, vendor, randomized, last_ip per device |
| `home.json` | Gateway MAC HMAC and initialized subnet |
| `fp.key` | Random 32-byte HMAC key |
| `alerts.json` | HMAC identities of known devices and permanent channel delivery receipts |
| `lock` | Empty advisory lock, preventing overlapping local state updates |

The extra receipt state is necessary to keep the specified device schema intact
while supporting known devices, once-per-channel notices, and failure retries.
No report/history file is automatically accumulated.

## Scheduling and verification

`print-timer` prints a systemd **user** service and timer; it installs or enables
nothing. The printed service expects a `~/.local/bin/porchwatch` executable:
adjust its path to your chosen environment before a separate manual installation.
It treats finding exit code 1 as success and runs passive scans only. Configure
remote channels and their environment separately before scheduling if desired.

```sh
python -m pytest
```

Tests use a fake HOME/XDG tree, fixture routes/neighbors, mocked commands and
alert endpoints. They do not initialize a real network, execute nmap, install
timers, send alerts, or touch the real home. Installing the package does not
enable monitoring.
