
import json
import os
import urllib.request
from typing import Any, Dict, Optional, Tuple
from botocore.exceptions import ClientError
from urllib.error import HTTPError


import boto3

s3 = boto3.client("s3")
s3control = boto3.client("s3control")  # sometimes useful depending on event shape


DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
LAB_BUCKET_TAG_KEY = os.environ.get("LAB_BUCKET_TAG_KEY", "Project")
LAB_BUCKET_TAG_VALUE = os.environ.get("LAB_BUCKET_TAG_VALUE", "S3ExposureLab")


def _post_discord(payload: dict) -> None:
    if not DISCORD_WEBHOOK_URL:
        print("DISCORD_WEBHOOK_URL is not set")
        print("payload:", payload)
        return

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("Discord status:", resp.status)
            return

    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        print("Discord HTTPError:", e.code, e.reason)
        print("Discord body:", body)
        if e.headers:
            print("Retry-After:", e.headers.get("Retry-After"))
        raise

def _safe_get(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _extract_bucket_name(event: Dict[str, Any]) -> Optional[str]:
    """
    CloudTrail event shapes vary.
    For PutPublicAccessBlock, bucket name can show up in:
      detail.requestParameters.bucketName
      detail.requestParameters.bucket
      detail.requestParameters.publicAccessBlockConfiguration.bucketName (rare)
    We'll try multiple.
    """
    detail = event.get("detail", {})
    rp = detail.get("requestParameters", {}) or {}

    for key in ("bucketName", "bucket"):
        v = rp.get(key)
        if isinstance(v, str) and v:
            return v

    # Fallback: some shapes nest config
    pab = rp.get("publicAccessBlockConfiguration") or rp.get("PublicAccessBlockConfiguration")
    if isinstance(pab, dict):
        v = pab.get("bucketName") or pab.get("bucket")
        if isinstance(v, str) and v:
            return v

    return None


def _get_bucket_tags(bucket: str) -> Dict[str, str]:
    try:
        resp = s3.get_bucket_tagging(Bucket=bucket)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        # 태그가 없을 때 보통 이 코드로 옴
        if code in ("NoSuchTagSet", "NoSuchTagSetError", "NoSuchTagSetException"):
            return {}
        # 버킷이 없거나 권한 문제 등은 로그 남기고 빈 값 처리(또는 raise)
        print(f"get_bucket_tagging ClientError for {bucket}: {code} {e}")
        return {}

    except Exception as e:
        print(f"get_bucket_tagging failed for {bucket}: {e}")
        return {}


def _is_lab_bucket(bucket: str) -> bool:
    tags = _get_bucket_tags(bucket)
    if not tags:
        # If you want strict filtering, return False here.
        # For now, allow if tags missing (but print).
        print(f"[WARN] No tags found for bucket={bucket}.")
        return False  # strict mode recommended
    return tags.get(LAB_BUCKET_TAG_KEY) == LAB_BUCKET_TAG_VALUE


def _get_public_access_block(bucket: str) -> Optional[Dict[str, bool]]:
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        # Normalize expected keys
        return {
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls", False)),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls", False)),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy", False)),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets", False)),
        }
    except Exception as e:
        print(f"get_public_access_block failed for {bucket}: {e}")
        return None


def _severity_for_pab(cfg: Optional[Dict[str, bool]]) -> Tuple[str, str]:
    """
    For this Lambda, we treat "BPA not fully ON" as WARNING (guardrail weakened).
    We do NOT label CRITICAL here—CRITICAL comes from policy+state correlation in detector_policy.
    """
    if not cfg:
        return "WARNING", "Public Access Block status unavailable; possible guardrail misconfig."

    # If any of the four are False, guardrail is weakened
    weakened = any(v is False for v in cfg.values())
    if weakened:
        return "WARNING", "Public Access Block is not fully enabled (guardrail weakened)."
    return "INFO", "Public Access Block appears fully enabled."


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    print("Received event:", json.dumps(event))

    bucket = _extract_bucket_name(event)
    if not bucket:
        # Still notify for visibility, but mark as unknown bucket
        msg = {
            "content": "⚠️ [WARNING] S3 PublicAccessBlock change detected, but bucket name could not be parsed.",
        }
        _post_discord(msg)
        return {"ok": True, "bucket": None}

    # Strictly handle only lab bucket (recommended)
    if not _is_lab_bucket(bucket):
        print(f"Skip non-lab bucket: {bucket}")
        return {"ok": True, "skipped": True, "bucket": bucket}

    # Who/where
    detail = event.get("detail", {})
    actor = _safe_get(detail, "userIdentity", "arn") or _safe_get(detail, "userIdentity", "principalId") or "unknown"
    src_ip = detail.get("sourceIPAddress", "unknown")
    user_agent = detail.get("userAgent", "unknown")

    # Snapshot current BPA state (best practice: don't rely only on event payload)
    pab = _get_public_access_block(bucket)
    severity, reason = _severity_for_pab(pab)

    # Discord message (simple + readable)
    lines = [
        f"🪣 Bucket: `{bucket}`",
        f"🧑 Actor: `{actor}`",
        f"🌐 SourceIP: `{src_ip}`",
        f"🖥 UserAgent: `{user_agent}`",
        f"📌 Reason: {reason}",
    ]
    if pab:
        lines.append(
            "🔎 PAB Snapshot: "
            + ", ".join([f"{k}={str(v)}" for k, v in pab.items()])
        )

    payload = {
        "content": f"⚠️ [{severity}] S3 PublicAccessBlock change detected\n" + "\n".join(lines)
    }
    _post_discord(payload)

    return {"ok": True, "bucket": bucket, "severity": severity}
