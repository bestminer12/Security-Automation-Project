import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

def _get(d, path, default="N/A"):
    """Safely get nested dict values. path example: ('detail','userIdentity','arn')"""
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur if cur is not None else default

def post_to_discord_embed(event: dict):
    url = os.environ["DISCORD_WEBHOOK_URL"].strip().strip('"').strip("'")

    # Extract key fields from CloudTrail event delivered via EventBridge
    account = _get(event, ("account",), "N/A")
    region = _get(event, ("region",), "N/A")

    event_name = _get(event, ("detail", "eventName"), "CreateAccessKey")
    event_source = _get(event, ("detail", "eventSource"), "iam.amazonaws.com")

    actor_arn = _get(event, ("detail", "userIdentity", "arn"), "N/A")
    actor_type = _get(event, ("detail", "userIdentity", "type"), "N/A")
    principal = _get(event, ("detail", "userIdentity", "principalId"), "N/A")

    source_ip = _get(event, ("detail", "sourceIPAddress"), "N/A")
    user_agent = _get(event, ("detail", "userAgent"), "N/A")

    # For CreateAccessKey, CloudTrail typically includes the created accessKeyId in responseElements
    created_access_key_id = _get(event, ("detail", "responseElements", "accessKey", "accessKeyId"), "N/A")

    # Target user name can appear depending on who created the key (requestParameters.userName)
    target_user = _get(event, ("detail", "requestParameters", "userName"), "N/A")

    event_time = _get(event, ("detail", "eventTime"), None)
    if not event_time:
        event_time = datetime.now(timezone.utc).isoformat()

    # A short preview to aid triage (keep it small so Discord doesn't get too noisy)
    detail_preview = {
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": _get(event, ("detail", "awsRegion"), region),
        "sourceIPAddress": source_ip,
        "userAgent": user_agent if isinstance(user_agent, str) else "N/A",
        "requestParameters": _get(event, ("detail", "requestParameters"), {}),
    }

    # Discord embed payload
    payload = {
        "content": "",  # keep empty; embed is the main card
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
                    {"name": "PrincipalId", "value": f"`{principal}`", "inline": False},

                    {"name": "Target User", "value": f"`{target_user}`", "inline": True},
                    {"name": "Created AccessKeyId", "value": f"`{created_access_key_id}`", "inline": True},
                    {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},

                    {
                        "name": "Detail (preview)",
                        "value": "```json\n" + json.dumps(detail_preview, ensure_ascii=False)[:900] + "\n```",
                        "inline": False,
                    },
                ],
                "footer": {
                    "text": "AWS EventBridge → Lambda → Discord | Security Automation"
                },
                "timestamp": event_time,
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
        print("discord_http_error", e.code, body[:1000])
        raise

def lambda_handler(event, context):
    # Useful for debugging actual incoming events
    print("event", json.dumps(event)[:1500])

    post_to_discord_embed(event)
    return {"statusCode": 200, "body": "ok"}
