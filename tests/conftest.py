from copy import deepcopy
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from porchwatch import cli, network


GATEWAY = "00:11:22:33:44:55"
DEVICE = "00:11:22:33:44:66"
RANDOM = "02:11:22:33:44:77"


def fixture_snapshot(extra=(), routes=None, rules=None):
    routes = routes if routes is not None else [
        {"dst": "default", "gateway": "192.168.50.1", "dev": "eth0"},
        {"dst": "192.168.50.0/24", "dev": "eth0", "scope": "link", "protocol": "kernel"},
    ]
    rules = rules if rules is not None else [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 32766, "src": "all", "table": "main"},
        {"priority": 32767, "src": "all", "table": "default"},
    ]
    return network.select_home(routes, [{"mac": GATEWAY, "ip": "192.168.50.1", "dev": "eth0"}, *extra], rules)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    monkeypatch.setattr(cli, "vendors", lambda: {})
    return home


@pytest.fixture
def lan(monkeypatch):
    value = {"snapshot": fixture_snapshot()}
    monkeypatch.setattr(network, "collect", lambda: deepcopy(value["snapshot"]))
    return value


@pytest.fixture
def state_path(isolated_home):
    return isolated_home / "state/porchwatch"


@pytest.fixture
def config_file(isolated_home):
    def create(text):
        path = isolated_home / "config/porchwatch/config.toml"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
        return path
    return create
