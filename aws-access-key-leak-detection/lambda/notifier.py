import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

def _get(d, path, default=None):
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def _first(*vals, default="N/A"):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return default

def post_to_discord_embed(event: dict):
    url = os.environ["DISCORD_WEBHOOK_URL"].strip().strip('"').strip("'")

    detail = event.get("detail", {}) if isinstance(event, dict) else {}

    # CloudTrail fields (most reliable)
    region = _first(
        _get(detail, ("awsRegion",)),
        _get(event, ("region",)),
    )

    account = _first(
        _get(detail, ("userIdentity", "accountId")),
        _get(event, ("account",)),
    )

    event_name = _first(_get(detail, ("eventName",)), default="CreateAccessKey")
    event_source = _first(_get(detail, ("eventSource",)), default="iam.amazonaws.com")

    user_identity = detail.get("userIdentity", {}) if isinstance(detail.get("userIdentity"), dict) else {}

    actor_arn = _first(
        user_identity.get("arn"),
        user_identity.get("principalId"),  # fallback
    )

    actor_type = _first(user_identity.get("type"))
    principal_id = _first(user_identity.get("principalId"))

    # Prefer requestParameters.userName (the user whose key is being created)
    req_params = detail.get("requestParameters", {}) if isinstance(detail.get("requestParameters"), dict) else {}
    target_user = _first(
        req_params.get("userName"),
        user_identity.get("userName"),
    )

    source_ip = _first(_get(detail, ("sourceIPAddress",)))
    user_agent = _first(_get(detail, ("userAgent",)))

    # Created key id
    created_access_key_id = _first(
        _get(detail, ("responseElements", "accessKey", "accessKeyId")),
        _get(detail, ("responseElements", "accessKeyId")),  # rare shape
    )

    # Event time
    event_time = _first(
        _get(detail, ("eventTime",)),
        datetime.now(timezone.utc).isoformat(),
        default=datetime.now(timezone.utc).isoformat()
    )

    # If anything is still N/A, show a short hint in preview
    detail_preview = {
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": _first(_get(detail, ("awsRegion",)), default="N/A"),
        "sourceIPAddress": _first(_get(detail, ("sourceIPAddress",)), default="N/A"),
        "userName": _first(user_identity.get("userName"), default="N/A"),
        "requestParameters": req_params if req_params else {},
    }

    payload = {
        "content": "",
        "embeds": [
            {
                "title": "🚨 SECURITY EVENT DETECTED",
                "description": "A high-risk IAM action was detected and forwarded by the automation pipeline.",
                "color": 0xED4245,  # red
                "fields": [
                    {"name": "Severity", "value": "HIGH", "inline": True},
                    {"name": "Event", "value": f"`{event_name}`", "inline": True},
                    {"name": "Region", "value": f"`{region}`", "inline": True},

                    {"name": "Account", "value": f"`{account}`", "inline": True},
                    {"name": "Actor", "value": f"`{actor_type}`\n{actor_arn}", "inline": False},
                    {"name": "PrincipalId", "value": f"`{principal_id}`", "inline": False},

                    {"name": "Target User", "value": f"`{target_user}`", "inline": True},
                    {"name": "Created AccessKeyId", "value": f"`{created_access_key_id}`", "inline": True},
                    {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},

                    {
                        "name": "Detail (preview)",
                        "value": "```json\n" + json.dumps(detail_preview, ensure_ascii=False)[:900] + "\n```",
                        "inline": False,
                    },
                ],
                "footer": {"text": "AWS EventBridge → Lambda → Discord | Security Automation"},
                "timestamp": event_time,
            }
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aws-lambda-discord-notifier",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("discord_status", resp.status)
            return resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print("discord_http_error", e.code, body[:1000])
        raise

def lambda_handler(event, context):
    # Log a bit of the incoming event for troubleshooting
    print("event_keys", list(event.keys()) if isinstance(event, dict) else type(event))
    print("detail_keys", list(event.get("detail", {}).keys()) if isinstance(event, dict) else "N/A")

    post_to_discord_embed(event)
    return {"statusCode": 200, "body": "ok"}
