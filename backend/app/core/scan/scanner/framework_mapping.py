from __future__ import annotations

from copy import deepcopy
from typing import Any


SCORE_MODEL = "cis_style_compliance_v1"

SEVERITY_KEYS = ("critical", "high", "medium", "low")

CATEGORY_FRAMEWORKS: dict[str, dict[str, list[str]]] = {
    "Account Policies": {"nist": ["AC", "IA"], "cis": ["5", "6"]},
    "Audit Policies": {"nist": ["AU"], "cis": ["8"]},
    "User Rights Assignment": {"nist": ["AC", "CM"], "cis": ["5", "6"]},
    "Security Options": {"nist": ["AC", "IA", "SC", "CM"], "cis": ["4", "5", "12"]},
    "Windows Firewall": {"nist": ["SC"], "cis": ["12"]},
    "Windows Defender": {"nist": ["SI"], "cis": ["10"]},
    "Remote Access": {"nist": ["AC", "SC"], "cis": ["12"]},
    "Services & Features": {"nist": ["CM"], "cis": ["4"]},
    "Credential Protection": {"nist": ["IA", "AC"], "cis": ["5", "6"]},
    "TLS/Cipher Suites": {"nist": ["SC"], "cis": ["3", "12"]},
}

KEYWORD_FRAMEWORKS: list[tuple[list[str], dict[str, list[str]]]] = [
    (["password", "lockout", "credential", "kerberos", "wdigest", "lsa", "lsass"], {"nist": ["IA", "AC"], "cis": ["5", "6"]}),
    (["audit", "logon", "logoff", "object access", "process creation"], {"nist": ["AU"], "cis": ["8"]}),
    (["firewall", "rdp", "remote desktop", "remote assistance"], {"nist": ["AC", "SC"], "cis": ["12"]}),
    (["defender", "antivirus", "smartscreen", "attack surface", "asr"], {"nist": ["SI"], "cis": ["10"]}),
    (["tls", "ssl", "cipher", "schannel"], {"nist": ["SC"], "cis": ["3", "12"]}),
    (["service", "scheduled task", "autoplay", "autorun"], {"nist": ["CM"], "cis": ["4"]}),
]


def _merge_codes(base: dict[str, list[str]], extra: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {"nist": list(base.get("nist") or []), "cis": list(base.get("cis") or [])}
    for family in ("nist", "cis"):
        for code in extra.get(family) or []:
            if code not in merged[family]:
                merged[family].append(code)
    return merged


def map_frameworks(
    category: str = "",
    policy_path: str = "",
    check_name: str = "",
    registry_path: str = "",
    sheet_type: str = "",
) -> dict[str, list[str]]:
    frameworks = deepcopy(CATEGORY_FRAMEWORKS.get(category, {"nist": ["CM"], "cis": ["4"]}))
    haystack = f"{category} {policy_path} {check_name} {registry_path} {sheet_type}".lower()
    for keywords, extra in KEYWORD_FRAMEWORKS:
        if any(keyword in haystack for keyword in keywords):
            frameworks = _merge_codes(frameworks, extra)
    return frameworks


def frameworks_for_result(result: dict[str, Any]) -> dict[str, list[str]]:
    existing = result.get("frameworks")
    if isinstance(existing, dict):
        nist = [str(code) for code in existing.get("nist") or [] if str(code).strip()]
        cis = [str(code) for code in existing.get("cis") or [] if str(code).strip()]
        if nist or cis:
            return {"nist": nist, "cis": cis}
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    return map_frameworks(
        category=str(result.get("category") or ""),
        policy_path=str(result.get("policy_path") or ""),
        check_name=str(result.get("check_name") or ""),
        registry_path=str(result.get("registry_path") or ""),
        sheet_type=str(source.get("sheet_type") or ""),
    )


def empty_framework_breakdown() -> dict[str, dict[str, dict[str, Any]]]:
    return {"nist": {}, "cis": {}}


def _record_framework(
    breakdown: dict[str, dict[str, dict[str, Any]]],
    frameworks: dict[str, list[str]],
    status_key: str,
    severity: str,
) -> None:
    for family in ("nist", "cis"):
        for code in frameworks.get(family) or []:
            row = breakdown[family].setdefault(
                code,
                {
                    "passed_assessed_count": 0,
                    "failed_assessed_count": 0,
                    "total_assessed_count": 0,
                    "severity_failed": {key: 0 for key in SEVERITY_KEYS},
                },
            )
            row["total_assessed_count"] += 1
            if status_key == "pass":
                row["passed_assessed_count"] += 1
            elif status_key == "fail":
                row["failed_assessed_count"] += 1
                row["severity_failed"][severity] = row["severity_failed"].get(severity, 0) + 1


def calculate_cis_style_score(results: dict[str, Any] | None) -> tuple[int, dict | None]:
    if not isinstance(results, dict):
        return 0, None

    passed = 0
    failed = 0
    excluded_manual = 0
    excluded_na = 0
    severity_failed = {key: 0 for key in SEVERITY_KEYS}
    framework_breakdown = empty_framework_breakdown()

    for key, result in results.items():
        if str(key).startswith("_") or not isinstance(result, dict):
            continue

        raw_status = str(result.get("status", "")).strip().lower()
        if not raw_status:
            continue
        if raw_status.startswith("manual") or "manual" in raw_status:
            excluded_manual += 1
            continue
        if raw_status in {"n/a", "na", "skipped", "__skip__"} or "not applicable" in raw_status:
            excluded_na += 1
            continue

        severity = str(result.get("severity") or "low").strip().lower()
        if severity not in SEVERITY_KEYS:
            severity = "low"

        if raw_status.startswith("pass"):
            passed += 1
            _record_framework(framework_breakdown, frameworks_for_result(result), "pass", severity)
        elif raw_status.startswith("fail"):
            failed += 1
            severity_failed[severity] += 1
            _record_framework(framework_breakdown, frameworks_for_result(result), "fail", severity)

    total = passed + failed
    if total <= 0:
        return 0, None

    return int((passed / total) * 100), {
        "model": SCORE_MODEL,
        "passed_assessed_count": passed,
        "failed_assessed_count": failed,
        "total_assessed_count": total,
        "excluded_manual_count": excluded_manual,
        "excluded_na_count": excluded_na,
        "severity_failed": severity_failed,
        "framework_breakdown": framework_breakdown,
    }


def normalize_score_breakdown(breakdown: dict[str, Any] | None) -> dict | None:
    if not isinstance(breakdown, dict):
        return None
    if breakdown.get("model") != SCORE_MODEL:
        return None
    try:
        return {
            **breakdown,
            "passed_assessed_count": int(breakdown.get("passed_assessed_count", 0) or 0),
            "failed_assessed_count": int(breakdown.get("failed_assessed_count", 0) or 0),
            "total_assessed_count": int(breakdown.get("total_assessed_count", 0) or 0),
            "excluded_manual_count": int(breakdown.get("excluded_manual_count", 0) or 0),
            "excluded_na_count": int(breakdown.get("excluded_na_count", 0) or 0),
            "severity_failed": {
                key: int((breakdown.get("severity_failed") or {}).get(key, 0) or 0)
                for key in SEVERITY_KEYS
            },
            "framework_breakdown": breakdown.get("framework_breakdown") or empty_framework_breakdown(),
        }
    except Exception:
        return None
