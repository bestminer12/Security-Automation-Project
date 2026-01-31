import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

DISCORD_WEBHOOK_URL_ENV = "DISCORD_WEBHOOK_URL"

def post_to_discord_embed(title: str, description: str, severity: str, fields: list, footer: str = "AWS Security Automation"):
    url = os.environ[DISCORD_WEBHOOK_URL_ENV]

    # Discord embed color (decimal)
    # red / orange / green
    sev = (severity or "MEDIUM").upper()
    if sev == "HIGH":
        color = 15158332  # red
        icon = "🚨"
    elif sev == "LOW":
        color = 3066993   # green
        icon = "✅"
    else:
        color = 15105570  # orange
        icon = "⚠️"

    payload = {
        "username": "security-alert-bot",
        # "avatar_url": "https://i.imgur.com/xxxx.png",  # 필요하면 아이콘 URL
        "embeds": [
            {
                "title": f"{icon} {title}",
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": footer}
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aws-lambda-discord-notifier"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("discord_status", resp.status)
            return resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print("discord_http_error", e.code, body)
        raise


def _guess_severity(event_name: str, resource: str, detail: dict) -> str:
    text = f"{event_name} {resource} {json.dumps(detail, ensure_ascii=False)[:500]}".lower()

    # 취약 SG, 22/tcp, 0.0.0.0/0 같은 키워드면 HIGH
    high_keywords = ["authorize", "ingress", "securitygroup", "0.0.0.0/0", "22", "ssh", "open port", "modifysecuritygroup"]
    medium_keywords = ["assumerole", "updatefunction", "putrule", "addevent", "create", "attach"]

    if any(k in text for k in high_keywords):
        return "HIGH"
    if any(k in text for k in medium_keywords):
        return "MEDIUM"
    return "LOW"


def lambda_handler(event, context):
    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    event_name = detail.get("eventName", "N/A")
    event_source = detail.get("eventSource", detail.get("event_source", "N/A"))
    aws_region = detail.get("awsRegion", os.environ.get("AWS_REGION", "N/A"))

    # CloudTrail 이벤트면 userIdentity / sourceIPAddress 등이 자주 있음
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn") or user_identity.get("userName") or "N/A"
    src_ip = detail.get("sourceIPAddress", "N/A")

    # 리소스 힌트(네 프로젝트는 SG 관련이라 리소스명도 넣어봄)
    resource_hint = (
        detail.get("requestParameters", {}).get("groupId")
        or detail.get("requestParameters", {}).get("groupName")
        or detail.get("resources", [{}])[0].get("ARN")
        if isinstance(detail.get("resources"), list) else "N/A"
    )
    if not resource_hint:
        resource_hint = "N/A"

    severity = _guess_severity(event_name, str(resource_hint), detail)

    title = "SECURITY EVENT DETECTED"
    description = "An AWS management event was detected and forwarded by the automation pipeline."

    fields = [
        {"name": "Severity", "value": f"**{severity}**", "inline": True},
        {"name": "Event", "value": f"`{event_name}`", "inline": True},
        {"name": "Region", "value": f"`{aws_region}`", "inline": True},
        {"name": "Actor", "value": actor if actor != "" else "N/A", "inline": False},
        {"name": "Source IP", "value": f"`{src_ip}`", "inline": True},
        {"name": "Event Source", "value": f"`{event_source}`", "inline": True},
        {"name": "Resource", "value": f"`{resource_hint}`", "inline": False},
    ]

    # 필요하면 detail 일부를 짧게 첨부(너무 길면 Discord가 거절함)
    detail_preview = json.dumps(detail, ensure_ascii=False)
    if len(detail_preview) > 900:
        detail_preview = detail_preview[:900] + "…"
    fields.append({"name": "Detail (preview)", "value": f"```json\n{detail_preview}\n```", "inline": False})

    post_to_discord_embed(
        title=title,
        description=description,
        severity=severity,
        fields=fields,
        footer="AWS EventBridge → Lambda → Discord | Security Automation"
    )

    return {"statusCode": 200, "body": "ok"}
