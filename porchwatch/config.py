"""Configuration is never created or changed by Porch Watch."""
import os
from pathlib import Path
import stat
try:
    import tomllib
except ImportError:
    import tomli as tomllib

from .safety import SafeError, absolute, bounded_read


def locations():
    home = absolute(Path.home())
    config = absolute(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    state = absolute(os.environ.get("XDG_STATE_HOME", home / ".local/state"))
    return config / "porchwatch/config.toml", state / "porchwatch"


def load_config(path):
    try:
        data, info, _ = bounded_read(path)
    except FileNotFoundError:
        return {}
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise SafeError("configuration must be owned by this user and mode 0600")
    cfg = tomllib.loads(data.decode())
    supported = {"alert_channels", "alert_slack_webhook_env", "alert_ntfy_token_env", "alert_ntfy_topic",
                 "alert_smtp_password_env", "alert_smtp_host", "alert_smtp_port", "alert_smtp_security",
                 "alert_smtp_from", "alert_email", "alert_smtp_username"}
    if set(cfg) - supported:
        raise SafeError("unsupported configuration key; use environment variable names for alert credentials")
    channels = cfg.get("alert_channels") or ["stdout"]
    if (not isinstance(channels, list) or any(c not in {"stdout", "slack", "ntfy", "email"} for c in channels)
            or len(channels) != len(set(channels))):
        raise SafeError("invalid alert_channels")
    for key, value in cfg.items():
        if key not in {"alert_channels", "alert_smtp_port"} and not isinstance(value, str):
            raise SafeError("alert configuration values must be strings")
    if "alert_smtp_port" in cfg and (type(cfg["alert_smtp_port"]) is not int or not 1 <= cfg["alert_smtp_port"] <= 65535):
        raise SafeError("invalid SMTP port")
    return cfg
