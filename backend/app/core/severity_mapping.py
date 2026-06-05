from __future__ import annotations

import datetime
from collections import Counter, defaultdict
from typing import Any

DEFAULT_CATEGORY_SEVERITY = {
    "Account Policies": "High",
    "Audit Policies": "High",
    "User Rights Assignment": "Critical",
    "Security Options": "High",
    "Windows Firewall": "High",
    "Windows Defender": "Medium",
    "Remote Access": "High",
    "Services & Features": "Medium",
    "Credential Protection": "Critical",
    "TLS/Cipher Suites": "High",
}

DEFAULT_KEYWORD_OVERRIDES = {
    "critical": [
        "debug programs",
        "credential",
        "lsa",
        "lsass",
        "wdigest",
        "kerberos",
        "delegation",
        "remote desktop",
    ],
    "high": [
        "password",
        "lockout",
        "audit",
        "logon",
        "user rights",
        "privilege",
        "uac",
        "ntlm",
        "lan manager",
        "smb",
        "signing",
        "firewall",
        "rdp",
        "tls",
        "ssl",
        "cipher",
    ],
    "medium": [
        "defender",
        "smartscreen",
        "attack surface",
        "service",
        "scheduled task",
        "autoplay",
        "autorun",
        "printer",
        "bluetooth",
    ],
    "low": [],
    "info": [],
}

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
_SEVERITY_BY_KEY = {s.lower(): s for s in SEVERITIES}
_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def default_mapping_payload() -> dict[str, Any]:
    return {
        "category_mapping": dict(DEFAULT_CATEGORY_SEVERITY),
        "keyword_overrides": {k: list(v) for k, v in DEFAULT_KEYWORD_OVERRIDES.items()},
    }


def normalize_mapping_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    base = default_mapping_payload()
    payload = payload or {}

    category_mapping = dict(base["category_mapping"])
    for category, severity in (payload.get("category_mapping") or {}).items():
        normalized = _SEVERITY_BY_KEY.get(str(severity).strip().lower())
        if normalized:
            category_mapping[str(category)] = normalized

    keyword_overrides = {k: list(v) for k, v in base["keyword_overrides"].items()}
    for severity, keywords in (payload.get("keyword_overrides") or {}).items():
        key = str(severity).strip().lower()
        if key not in keyword_overrides:
            continue
        keyword_overrides[key] = [
            str(keyword).strip()
            for keyword in (keywords or [])
            if str(keyword).strip()
        ]

    return {
        "category_mapping": category_mapping,
        "keyword_overrides": keyword_overrides,
    }


def classify_severity(
    category: str,
    policy_path: str = "",
    check_name: str = "",
    registry_path: str = "",
    mapping: dict[str, Any] | None = None,
) -> str:
    config = normalize_mapping_payload(mapping)
    haystack = f"{category} {policy_path} {check_name} {registry_path}".lower()
    selected = config["category_mapping"].get(category, "Low")

    for severity in ["critical", "high", "medium", "low", "info"]:
        for keyword in config["keyword_overrides"].get(severity, []):
            if keyword.lower() in haystack:
                candidate = _SEVERITY_BY_KEY[severity]
                if _RANK[candidate] < _RANK[selected]:
                    selected = candidate

    return selected


def severity_counts(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(check.get("severity") or "Low").title() for check in checks)
    return {severity: int(counts.get(severity, 0)) for severity in SEVERITIES}


def category_counts(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category: dict[str, Counter] = defaultdict(Counter)
    for check in checks:
        category = str(check.get("category") or "General")
        severity = str(check.get("severity") or "Low").title()
        by_category[category][severity] += 1
        by_category[category]["total"] += 1
    return [
        {
            "category": category,
            "total": int(counts["total"]),
            "severity_counts": {severity: int(counts.get(severity, 0)) for severity in SEVERITIES},
        }
        for category, counts in sorted(by_category.items())
    ]


def preview_from_definition(definition: dict[str, Any]) -> dict[str, Any]:
    checks = list(definition.get("checks") or [])
    sev_counts = severity_counts(checks)
    warnings = []
    if sev_counts.get("Low", 0) == 0:
        warnings.append("No Low severity checks detected")
    if sev_counts.get("Info", 0) == 0:
        warnings.append("No Info severity checks detected")
    return {
        "check_count": len(checks),
        "severity_counts": sev_counts,
        "category_counts": category_counts(checks),
        "sample_checks": checks[:10],
        "warnings": warnings,
    }


def get_mapping_from_db(db) -> dict[str, Any]:
    from app.models.severity_mapping import SeverityMapping

    row = db.query(SeverityMapping).order_by(SeverityMapping.id.desc()).first()
    if not row:
        return default_mapping_payload()
    return normalize_mapping_payload({
        "category_mapping": row.category_mapping or {},
        "keyword_overrides": row.keyword_overrides or {},
    })


def save_mapping_to_db(db, payload: dict[str, Any], user_id: int | None = None) -> dict[str, Any]:
    from app.models.severity_mapping import SeverityMapping

    normalized = normalize_mapping_payload(payload)
    row = db.query(SeverityMapping).order_by(SeverityMapping.id.desc()).first()
    if not row:
        row = SeverityMapping()
        db.add(row)
    row.category_mapping = normalized["category_mapping"]
    row.keyword_overrides = normalized["keyword_overrides"]
    row.updated_by = user_id
    row.updated_at = datetime.datetime.now()
    db.commit()
    return normalized
