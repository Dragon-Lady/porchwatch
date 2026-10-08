"""Aggregate alerts, matching Net Ward channel names; never send inventory."""
from email.message import EmailMessage
import json
import os
import smtplib
import ssl
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .safety import SafeError, fingerprint


def destination_id(channel, cfg, key):
    # Only the channel is used: rotating an endpoint must not replay old devices.
    return fingerprint(key, "channel:" + channel)


def deliver(cfg, store, records, tracking, home_check):
    """Successful channels get permanent receipts; failures remain retryable."""
    channels = cfg.get("alert_channels") or ["stdout"]
    result = {"delivered": [], "failed": [], "deduped": [], "messages": []}
    for channel in channels:
        channel_id = destination_id(channel, cfg, store.key)
        pending = []
        for row in records:
            identity = fingerprint(store.key, row["mac"])
            if (not row["label"] and identity not in tracking["known"]
                    and channel_id not in tracking["receipts"].get(identity, [])):
                pending.append((identity, row["randomized"]))
        if not pending:
            result["deduped"].append(channel)
            continue
        # A route/cache change cancels sending and receipt writes.
        home_check()
        private = sum(randomized for _, randomized in pending)
        message = (f"Porch Watch: PW-NEW-DEVICE={len(pending)}; warn={len(pending) - private}; "
                   f"info={private} (randomized). run `porchwatch report` locally for details")
        try:
            send_one(channel, cfg, message)
        except Exception:
            # Provider errors can embed credentials, endpoints or recipient details.
            result["failed"].append(channel)
        else:
            result["delivered"].append(channel)
            if channel == "stdout":
                result["messages"].append(message)
            for identity, _ in pending:
                tracking["receipts"].setdefault(identity, []).append(channel_id)
            home_check()
            store.save("alerts.json", tracking)
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def endpoint(value):
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SafeError("invalid alert endpoint")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise SafeError("alert endpoint must use HTTPS except on loopback")
    return value


def env_secret(cfg, field):
    name = cfg.get(field)
    if not isinstance(name, str) or not os.environ.get(name):
        raise SafeError("alert credential environment variable is missing")
    return os.environ[name]


def post(url, body, headers):
    request = Request(endpoint(url), data=body, headers=headers, method="POST")
    with build_opener(NoRedirect).open(request, timeout=5) as response:
        response.read(1024)


def send_one(channel, cfg, message):
    if channel == "stdout":
        return  # Returned as structured output by CLI, never mixed into JSON.
    if channel == "slack":
        url = env_secret(cfg, "alert_slack_webhook_env")
        post(url, json.dumps({"text": message}).encode(), {"Content-Type": "application/json"})
    elif channel == "ntfy":
        topic = cfg.get("alert_ntfy_topic", "")
        if not topic:
            raise SafeError("ntfy topic missing")
        url = topic if "://" in topic else "https://ntfy.sh/" + quote(topic, safe="")
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if cfg.get("alert_ntfy_token_env"):
            headers["Authorization"] = "Bearer " + env_secret(cfg, "alert_ntfy_token_env")
        post(url, message.encode(), headers)
    elif channel == "email":
        host = cfg.get("alert_smtp_host", "")
        security = cfg.get("alert_smtp_security", "starttls")
        if security not in {"ssl", "starttls", "none"} or not host:
            raise SafeError("invalid SMTP configuration")
        if security == "none" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise SafeError("SMTP encryption is required off loopback")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = cfg["alert_smtp_from"], cfg["alert_email"], "Porch Watch aggregate alert"
        msg.set_content(message)
        client = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
        kwargs = {"context": ssl.create_default_context()} if security == "ssl" else {}
        with client(host, int(cfg.get("alert_smtp_port", 465 if security == "ssl" else 587)), timeout=5, **kwargs) as smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if cfg.get("alert_smtp_username"):
                smtp.login(cfg["alert_smtp_username"], env_secret(cfg, "alert_smtp_password_env"))
            smtp.send_message(msg)
    else:
        raise SafeError("unsupported alert channel")
