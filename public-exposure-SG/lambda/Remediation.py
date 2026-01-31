import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


# =========================
# Discord (Embed)
# =========================
def post_to_discord_embed(title: str, description: str, color: int, fields: list, footer: str):
    url = os.environ["DISCORD_WEBHOOK_URL"]

    payload = {
        "username": "security-remediator-bot",
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": footer},
            }
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aws-lambda-security-remediator",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("discord_status", resp.status)
            return resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print("discord_http_error", e.code, body)
        raise


# =========================
# Remediation Logic
# =========================
ec2 = boto3.client("ec2")

# 안전장치(권장): 기본은 DRY_RUN=true로 두고 테스트 후 false로 전환
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"

# 안전장치(선택): 특정 SG는 절대 건드리지 않게 allowlist
# 예: "sg-0123abcd,sg-0beefcafe"
ALLOWLIST_SG_IDS = set(
    sg.strip() for sg in os.environ.get("ALLOWLIST_SG_IDS", "").split(",") if sg.strip()
)

# 조치 대상 조건(너 프로젝트 기준)
TARGET_CIDR = os.environ.get("TARGET_CIDR", "0.0.0.0/0")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "22"))
TARGET_PROTOCOL = os.environ.get("TARGET_PROTOCOL", "tcp")


def _extract_event_fields(event: dict):
    """
    너가 만든 탐지 이벤트(Detail preview에 보이던 구조)를 우선 지원:
    {
      "account": "...",
      "region": "ap-northeast-2",
      "security_group": "sg-xxxx",
      "port": 22,
      "cidr": "0.0.0.0/0",
      "time": "..."
    }

    만약 EventBridge/CloudTrail 원본(detail.eventName 등)으로 올 경우를 대비해
    최소한의 fallback만 제공.
    """
    detail = event.get("detail", {}) if isinstance(event, dict) else {}

    sg_id = detail.get("security_group") or detail.get("groupId") or detail.get("securityGroupId")
    port = detail.get("port")
    cidr = detail.get("cidr")
    region = detail.get("region") or detail.get("awsRegion") or os.environ.get("AWS_REGION")
    account = detail.get("account") or detail.get("recipientAccountId")

    # 숫자형 보정
    try:
        port = int(port) if port is not None else None
    except Exception:
        port = None

    return {
        "detail": detail,
        "sg_id": sg_id,
        "port": port,
        "cidr": cidr,
        "region": region,
        "account": account,
    }


def _should_remediate(sg_id: str, port: int, cidr: str) -> (bool, str):
    if not sg_id:
        return False, "missing security_group id"
    if ALLOWLIST_SG_IDS and sg_id in ALLOWLIST_SG_IDS:
        return False, f"sg allowlisted: {sg_id}"
    if port != TARGET_PORT:
        return False, f"port mismatch: {port} != {TARGET_PORT}"
    if cidr != TARGET_CIDR:
        return False, f"cidr mismatch: {cidr} != {TARGET_CIDR}"
    return True, "match"


def _revoke_ingress_rule(sg_id: str, port: int, cidr: str):
    """
    특정 SG에서 (protocol=tcp, from/to port, cidr) 인바운드 룰 제거
    """
    ip_permissions = [
        {
            "IpProtocol": TARGET_PROTOCOL,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}],
        }
    ]

    if DRY_RUN:
        # Dry-run 모드에서는 실제 API 호출 없이 시뮬레이션
        return {"dry_run": True, "changed": False, "message": "dry-run enabled (no changes applied)"}

    try:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=ip_permissions,
        )
        return {"dry_run": False, "changed": True, "message": "ingress rule revoked"}
    except ClientError as e:
        # 이미 룰이 없을 때도 에러가 날 수 있어(멱등성)
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", str(e))

        # 흔한 케이스: 이미 규칙이 없는 경우
        if code in ("InvalidPermission.NotFound",):
            return {"dry_run": False, "changed": False, "message": f"rule not found (already removed): {code}"}

        raise


def lambda_handler(event, context):
    info = _extract_event_fields(event)
    detail = info["detail"]
    sg_id = info["sg_id"]
    port = info["port"]
    cidr = info["cidr"]
    region = info["region"] or "N/A"
    account = info["account"] or "N/A"

    ok, reason = _should_remediate(sg_id, port, cidr)

    # Discord 알림 기본 필드
    base_fields = [
        {"name": "Account", "value": f"`{account}`", "inline": True},
        {"name": "Region", "value": f"`{region}`", "inline": True},
        {"name": "Security Group", "value": f"`{sg_id or 'N/A'}`", "inline": False},
        {"name": "Target Rule", "value": f"`{TARGET_PROTOCOL} {TARGET_PORT} {TARGET_CIDR}`", "inline": False},
        {"name": "Observed", "value": f"`{TARGET_PROTOCOL} {port} {cidr}`", "inline": False},
        {"name": "Mode", "value": "**DRY-RUN**" if DRY_RUN else "**ENFORCE**", "inline": True},
    ]

    # detail preview (너무 길면 컷)
    detail_preview = json.dumps(detail, ensure_ascii=False)
    if len(detail_preview) > 900:
        detail_preview = detail_preview[:900] + "…"
    base_fields.append({"name": "Detail (preview)", "value": f"```json\n{detail_preview}\n```", "inline": False})

    if not ok:
        # 스킵 알림(정보성)
        post_to_discord_embed(
            title="ℹ️ REMEDIATION SKIPPED",
            description=f"Remediation conditions not met: **{reason}**",
            color=9807270,  # blue-ish
            fields=base_fields,
            footer="EventBridge → Lambda (Remediator) → Discord | Security Automation",
        )
        return {"statusCode": 200, "body": f"skipped: {reason}"}

    # 실제 조치 수행
    try:
        result = _revoke_ingress_rule(sg_id, port, cidr)

        if result.get("dry_run"):
            title = "🧪 REMEDIATION SIMULATED (DRY-RUN)"
            desc = "Matched high-risk rule, but no changes were applied (dry-run)."
            color = 15105570  # orange
        else:
            if result.get("changed"):
                title = "✅ REMEDIATION APPLIED"
                desc = "Insecure ingress rule was successfully revoked."
                color = 3066993  # green
            else:
                title = "✅ REMEDIATION NOT NEEDED"
                desc = "Rule was already removed (idempotent result)."
                color = 3066993  # green

        base_fields.insert(0, {"name": "Result", "value": result.get("message", "ok"), "inline": False})

        post_to_discord_embed(
            title=title,
            description=desc,
            color=color,
            fields=base_fields,
            footer="EventBridge → Lambda (Remediator) → Discord | Security Automation",
        )

        return {"statusCode": 200, "body": "ok"}

    except Exception as e:
        # 실패 알림
        err = f"{type(e).__name__}: {str(e)}"
        base_fields.insert(0, {"name": "Error", "value": f"`{err}`", "inline": False})

        post_to_discord_embed(
            title="🚨 REMEDIATION FAILED",
            description="Attempted remediation but encountered an error.",
            color=15158332,  # red
            fields=base_fields,
            footer="EventBridge → Lambda (Remediator) → Discord | Security Automation",
        )
        raise
