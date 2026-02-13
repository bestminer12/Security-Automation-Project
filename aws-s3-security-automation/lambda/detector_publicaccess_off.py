import json
import os
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# AWS clients
s3 = boto3.client("s3")
sns = boto3.client("sns")

# Env vars
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
LAB_BUCKET_TAG_KEY = os.environ.get("LAB_BUCKET_TAG_KEY", "Project")
LAB_BUCKET_TAG_VALUE = os.environ.get("LAB_BUCKET_TAG_VALUE", "S3ExposureLab")


def _safe_get(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _extract_bucket_name(event: Dict[str, Any]) -> Optional[str]:
    """
    CloudTrail event shapes can vary.
    For PutPublicAccessBlock, bucket name commonly appears in:
      detail.requestParameters.bucketName
      detail.requestParameters.bucket
    We'll try multiple keys.
    """
    detail = event.get("detail", {}) or {}
    rp = detail.get("requestParameters", {}) or {}

    for key in ("bucketName", "bucket"):
        v = rp.get(key)
        if isinstance(v, str) and v:
            return v

    # fallback: sometimes nested
    pab = rp.get("publicAccessBlockConfiguration") or rp.get("PublicAccessBlockConfiguration")
    if isinstance(pab, dict):
        v = pab.get("bucketName") or pab.get("bucket")
        if isinstance(v, str) and v:
            return v

    return None


def _get_bucket_tags(bucket: str) -> Dict[str, str]:
    """
    Return bucket tags as a dict. If no tags, return {}.
    """
    try:
        resp = s3.get_bucket_tagging(Bucket=bucket)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        # If no tags exist, AWS often returns NoSuchTagSet
        if code in ("NoSuchTagSet", "NoSuchTagSetError", "NoSuchTagSetException"):
            return {}
        print(f"get_bucket_tagging ClientError for {bucket}: {code} {e}")
        return {}

    except Exception as e:
        print(f"get_bucket_tagging failed for {bucket}: {e}")
        return {}


def _is_lab_bucket(bucket: str) -> bool:
    """
    Strict allowlist:
    process only buckets tagged Project=S3ExposureLab (configurable via env).
    """
    tags = _get_bucket_tags(bucket)
    if not tags:
        print(f"Skip bucket without tags (strict mode): {bucket}")
        return False

    is_lab = tags.get(LAB_BUCKET_TAG_KEY) == LAB_BUCKET_TAG_VALUE
    if not is_lab:
        print(f"Skip non-lab bucket: {bucket}, tags={tags}")
    return is_lab


def _get_public_access_block(bucket: str) -> Optional[Dict[str, bool]]:
    """
    Fetch current Public Access Block configuration for the bucket.
    """
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
        cfg = resp.get("PublicAccessBlockConfiguration", {}) or {}
        return {
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls", False)),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls", False)),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy", False)),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets", False)),
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        # If PublicAccessBlock is not configured, AWS may return NoSuchPublicAccessBlockConfiguration
        if code in ("NoSuchPublicAccessBlockConfiguration",):
            return {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        print(f"get_public_access_block ClientError for {bucket}: {code} {e}")
        return None
    except Exception as e:
        print(f"get_public_access_block failed for {bucket}: {e}")
        return None


def _severity_for_pab(cfg: Optional[Dict[str, bool]]) -> Tuple[str, str]:
    """
    For this detector, we only send WARNING when guardrail is weakened.
    (CRITICAL is handled by detector_policy, which correlates policy + BPA state)
    """
    if not cfg:
        return "WARNING", "Public Access Block status unavailable; possible guardrail misconfig."

    weakened = any(v is False for v in cfg.values())
    if weakened:
        return "WARNING", "Public Access Block is not fully enabled (guardrail weakened)."
    return "INFO", "Public Access Block appears fully enabled."


def _send_email_alert(subject: str, message: str) -> None:
    """
    Publish alert to SNS topic (email subscription sends the email).
    """
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN is not set; skipping SNS publish.")
        print("Subject:", subject)
        print("Message:", message)
        return

    # SNS Subject has a limit; keep it short
    subject = subject[:100]

    resp = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )
    print("SNS publish ok:", resp.get("MessageId"))


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    print("Received event:", json.dumps(event))

    bucket = _extract_bucket_name(event)
    if not bucket:
        _send_email_alert(
            subject="[WARNING] S3 PublicAccessBlock change detected (bucket parse failed)",
            message="A PutPublicAccessBlock event was detected via CloudTrail, but bucket name could not be parsed.\n"
                    f"Raw event:\n{json.dumps(event)[:3000]}",
        )
        return {"ok": True, "bucket": None}

    # Process only lab bucket (strict mode)
    if not _is_lab_bucket(bucket):
        return {"ok": True, "skipped": True, "bucket": bucket}

    # Who/where from CloudTrail detail
    detail = event.get("detail", {}) or {}
    actor = _safe_get(detail, "userIdentity", "arn") or _safe_get(detail, "userIdentity", "principalId") or "unknown"
    src_ip = detail.get("sourceIPAddress", "unknown")
    user_agent = detail.get("userAgent", "unknown")

    # Snapshot current PAB state (do not rely only on request payload)
    pab = _get_public_access_block(bucket)
    severity, reason = _severity_for_pab(pab)

    lines = [
        f"Bucket: {bucket}",
        f"Severity: {severity}",
        f"Reason: {reason}",
        f"Actor: {actor}",
        f"SourceIP: {src_ip}",
        f"UserAgent: {user_agent}",
    ]
    if pab:
        lines.append("PAB Snapshot: " + ", ".join([f"{k}={v}" for k, v in pab.items()]))

    subject = f"[{severity}] S3 PublicAccessBlock change: {bucket}"
    message = "\n".join(lines)

    _send_email_alert(subject, message)

    return {"ok": True, "bucket": bucket, "severity": severity}
