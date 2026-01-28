
import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TARGET_EVENT_NAME = "AuthorizeSecurityGroupIngress"
TARGET_CIDR = "0.0.0.0/0"
TARGET_FROM_PORT = 22


def lambda_handler(event: Dict[str, Any], context):
    """
    Detects when SSH (22) is opened to the world (0.0.0.0/0)
    via AuthorizeSecurityGroupIngress CloudTrail event.
    """

    # Log raw event for debugging
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    # 1) eventName check
    if event_name != TARGET_EVENT_NAME:
        return _resp("ignored", f"Not target eventName: {event_name}")

    request_params = detail.get("requestParameters", {}) or {}
    group_id = request_params.get("groupId")  # may exist
    ip_permissions = (
        (request_params.get("ipPermissions") or {}).get("items") or []
    )

    findings: List[Dict[str, Any]] = []

    # 2) Parse permissions
    for perm in ip_permissions:
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")

        # Some events may use -1 for all ports/protocols; we only care exact fromPort == 22
        if from_port != TARGET_FROM_PORT:
            continue

        ip_ranges = ((perm.get("ipRanges") or {}).get("items") or [])
        for r in ip_ranges:
            cidr = r.get("cidrIp")
            # 3) CIDR check
            if cidr == TARGET_CIDR:
                findings.append({
                    "severity": "HIGH",
                    "eventName": event_name,
                    "securityGroupId": group_id,
                    "fromPort": from_port,
                    "toPort": to_port,
                    "cidrIp": cidr,
                    "message": "Detected SSH(22) opened to 0.0.0.0/0 via AuthorizeSecurityGroupIngress"
                })

    if not findings:
        return _resp("ok", "No matching exposure found")

    # Alert
    logger.warning("ALERT: %s", json.dumps(findings))
    return {
        "status": "alert",
        "findings": findings
    }


def _resp(status: str, message: str) -> Dict[str, Any]:
    return {"status": status, "message": message}
