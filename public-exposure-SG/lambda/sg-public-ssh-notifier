import json
import os
import urllib.request

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

def post_to_discord(content: str) -> None:
    if not DISCORD_WEBHOOK_URL:
        raise RuntimeError("Missing env var: DISCORD_WEBHOOK_URL")

    payload = {"content": content}
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=3) as resp:
        resp.read()


def lambda_handler(event, context):
    """
    Expected event: EventBridge custom event emitted by Detection Lambda.
    Example fields:
      - source: "custom.security.sg"
      - detail-type: "PublicSSHDetected"
      - detail: {account, region, security_group, port, cidr, time, ...}
    """
    detail = event.get("detail", {}) or {}

    account = detail.get("account", event.get("account", "unknown"))
    region = detail.get("region", event.get("region", "unknown"))
    sg_id = detail.get("security_group", "unknown")
    port = detail.get("port", "unknown")
    cidr = detail.get("cidr", "unknown")
    t = detail.get("time", event.get("time", "unknown"))

    msg = (
        "🚨 **Public SSH Exposure Detected** 🚨\n"
        f"- Account: `{account}`\n"
        f"- Region: `{region}`\n"
        f"- SecurityGroup: `{sg_id}`\n"
        f"- Port: `{port}`\n"
        f"- CIDR: `{cidr}`\n"
        f"- Time: `{t}`\n"
    )

    post_to_discord(msg)

    return {"ok": True}
