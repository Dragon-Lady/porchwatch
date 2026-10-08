"""Private state access; construction and reads have no write side effects."""
from contextlib import contextmanager
import fcntl
import json
import os
import re
import secrets
import stat

from .network import ip_address, mac_address, randomized
from .safety import (MAX_BYTES, SafeError, absolute, bounded_read, directory_fd,
                     fingerprint, private_dir, write_private)

FIELDS = {"mac", "first_seen", "last_seen", "label", "vendor", "randomized", "last_ip"}
FP = re.compile(r"^fp:[0-9a-f]{16}$")
HOUR = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:00:00Z$")


class Store:
    def __init__(self, path):
        self.path = absolute(path)
        self.key = None

    def read(self, name, raw=False):
        data, info, directory = bounded_read(self.path / name)
        if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise SafeError("state directory must be owned by this user and mode 0700")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise SafeError("state file must be owned by this user and mode 0600")
        return data if raw else json.loads(data)

    def identity(self):
        self.key = self.read("fp.key", raw=True)
        if len(self.key) != 32:
            raise SafeError("invalid fingerprint key")
        home = self.read("home.json")
        if (not isinstance(home, dict) or set(home) != {"gateway_fp", "subnet"}
                or not isinstance(home["gateway_fp"], str) or not FP.fullmatch(home["gateway_fp"])
                or not isinstance(home["subnet"], str)):
            raise SafeError("invalid home identity")
        return home

    def matches(self, snapshot):
        home = self.identity()
        return (home["gateway_fp"] == fingerprint(self.key, snapshot.gateway_mac)
                and home["subnet"] == snapshot.subnet)

    def save(self, name, value):
        data = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        if len(data.encode()) > MAX_BYTES:
            raise SafeError("state size limit exceeded")
        write_private(self.path / name, data, replace=True)

    def initialize_key(self):
        # Caller MUST validate a present gateway before reaching this method.
        private_dir(self.path)
        self.key = secrets.token_bytes(32)
        write_private(self.path / "fp.key", self.key)

    def records(self):
        records = self.read("devices.json")
        if not isinstance(records, list):
            raise SafeError("invalid device state")
        seen = set()
        for row in records:
            if not isinstance(row, dict) or set(row) != FIELDS:
                raise SafeError("invalid device schema")
            try:
                mac = mac_address(row["mac"])
                ip_address(row["last_ip"])
            except (SafeError, ValueError, TypeError):
                raise SafeError("invalid device state") from None
            if (mac != row["mac"] or mac in seen or type(row["randomized"]) is not bool
                    or row["randomized"] != randomized(mac)
                    or any(not isinstance(row[k], str) or not HOUR.fullmatch(row[k]) for k in ("first_seen", "last_seen"))
                    or any(not isinstance(row[k], str) or len(row[k]) > 2048 for k in ("label", "vendor"))):
                raise SafeError("invalid device state")
            seen.add(mac)
        return records

    def tracking(self):
        tracking = self.read("alerts.json")
        if not isinstance(tracking, dict) or set(tracking) != {"known", "receipts"}:
            raise SafeError("invalid alert state")
        known, receipts = tracking["known"], tracking["receipts"]
        if (not isinstance(known, list) or any(not isinstance(x, str) or not FP.fullmatch(x) for x in known)
                or not isinstance(receipts, dict)
                or any(not isinstance(k, str) or not FP.fullmatch(k) or not isinstance(v, list)
                       or any(not isinstance(x, str) or not FP.fullmatch(x) for x in v)
                       for k, v in receipts.items())):
            raise SafeError("invalid alert state")
        return tracking

    @contextmanager
    def lock(self):
        # File lock is opened only AFTER a successful home guard.
        parent = directory_fd(self.path)
        try:
            fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise SafeError("unsafe state lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafeError("another Porch Watch command is running") from None
            yield
        finally:
            os.close(fd)
