"""
baseline_metadata.py  (v2 — simplified)

เปลี่ยนหลักๆ:
  - enrich_scan_details() ไม่ต้อง lookup JSON อีกแล้ว
    เพราะ security_scanner.py v3 ส่ง metadata ครบมาใน result dict
  - เหลือแค่ adapter: แปลง result dict → findings list format เดิม
    เพื่อให้ frontend, PDF, AI summary ยังรับได้เหมือนเดิม (backward compat)
  - summarize_findings() ไม่เปลี่ยน
"""

from __future__ import annotations

from typing import Any


VALID_SERVER_ROLES = {"Member Server", "Domain Controller"}


def resolve_scan_role(
    details: dict[str, Any] | None,
    configured_role: str = "",
    target_name: str = "",
) -> str:
    """Resolve the effective role, preferring metadata reported by the agent."""
    rows = details if isinstance(details, dict) else {}
    detected = str(rows.get("_detected_role") or "").strip()
    if detected in VALID_SERVER_ROLES:
        return detected

    # Older agents omit _detected_role, but their filtered findings can still
    # identify a DC when an exclusively Domain Controller check is present.
    for key, value in rows.items():
        if str(key).startswith("_") or not isinstance(value, dict):
            continue
        applies_to = value.get("applies_to") or []
        if isinstance(applies_to, str):
            applies_to = [applies_to]
        normalized = {str(item).strip().lower() for item in applies_to}
        if "domain controller" in normalized and "member server" not in normalized:
            return "Domain Controller"

    configured = str(configured_role or "").strip()
    if configured in VALID_SERVER_ROLES:
        return configured
    if "domain controller" in str(target_name or "").lower():
        return "Domain Controller"
    return "Member Server"


def enrich_scan_details(
    details: dict[str, Any] | None,
    version: str = "",   # เก็บไว้เพื่อ backward compat แต่ไม่ใช้แล้ว
    role:    str = "",
) -> list[dict[str, Any]]:
    """
    แปลง result dict จาก scanner v3 → findings list

    result dict มีรูปแบบ:
    {
      "check_id":       "WIN11-COMP-0001",
      "check_name":     "...",
      "category":       "Account Policies",
      "severity":       "High",
      "remediation":    "...",
      "registry_path":  "...",
      "policy_path":    "...",
      "expected_value": "14",
      "applies_to":     ["Windows 11 24H2"],
      "status":         "Pass" | "Fail (...)" | "Manual ...",
      "current_value":  "8",
    }
    """
    findings: list[dict[str, Any]] = []

    for check_id, res in (details or {}).items():
        if str(check_id).startswith("_"):
            continue
        # รองรับทั้ง v3 (dict) และ v2 เก่า (string) เพื่อ backward compat
        if isinstance(res, str):
            findings.append(_from_legacy_string(check_id, res))
            continue

        status = res.get("status", "")
        # normalize status → Pass / Fail / N/A
        if status == "Pass":
            normalized = "Pass"
        elif status.startswith("Fail"):
            normalized = "Fail"
        else:
            normalized = "N/A"

        findings.append({
            "check_id":      res.get("check_id", check_id),
            "check_name":    res.get("check_name", check_id),
            "category":      res.get("category", ""),
            "severity":      res.get("severity", "Info"),
            "registry_path": res.get("registry_path", ""),
            "policy_path":   res.get("policy_path", ""),
            "expected_value": res.get("expected_value", ""),
            "current_value": res.get("current_value", ""),
            "status":        normalized,
            "remediation":   res.get("remediation",
                                     "ตรวจสอบการตั้งค่าใน Group Policy หรือ Local Security Policy"),
            "applies_to":    res.get("applies_to", []),
            "source":        res.get("source", {}),
            "frameworks":     res.get("frameworks", {"nist": [], "cis": []}),
            "raw_result":    status,
        })

    return findings


def _from_legacy_string(key: str, raw_value: str) -> dict[str, Any]:
    """
    backward compat: แปลง string result เก่า (ก่อน v3) → finding dict
    ใช้เมื่อ scan result ใน DB ยังเป็น format เก่า
    """
    import re

    if raw_value == "Pass":
        status, current, expected = "Pass", "", ""
    elif raw_value.startswith("Fail"):
        status = "Fail"
        t = re.search(r"Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)", raw_value)
        a = re.search(r"Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)", raw_value)
        expected = t.group(1).strip() if t else ""
        current  = a.group(1).strip().rstrip(")") if a else (
            "Not Configured" if "Not Configured" in raw_value else ""
        )
    else:
        status, current, expected = "N/A", raw_value, ""

    # ดึง section จาก key เก่า เช่น "[Computer] ..."
    section = "General"
    m = re.match(r"^\[([^\]]+)\]", key)
    if m:
        section = m.group(1)
    name = re.sub(r"^\[[^\]]+\]\s*", "", key).strip()

    return {
        "check_id":      "",
        "check_name":    name,
        "category":      section,
        "severity":      "Info",
        "registry_path": "",
        "policy_path":   "",
        "expected_value": expected,
        "current_value": current,
        "status":        status,
        "remediation":   "ตรวจสอบการตั้งค่าใน Group Policy หรือ Local Security Policy",
        "applies_to":    [],
        "source":        {},
        "frameworks":    {"nist": [], "cis": []},
        "raw_result":    raw_value,
    }


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    """ไม่เปลี่ยน — ใช้งานเหมือนเดิม"""
    summary = {"total": len(findings), "passed": 0, "failed": 0, "na": 0}
    for item in findings:
        s = item.get("status")
        if s == "Pass":
            summary["passed"] += 1
        elif s == "Fail":
            summary["failed"] += 1
        else:
            summary["na"] += 1
    return summary
