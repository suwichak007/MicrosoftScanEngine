# generate_baseline_json.py (v2 - fixed)
# Convert Excel baseline workbooks to JSON check definitions
# Run once: python tools/generate_baseline_json.py

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

try:
    import yaml
except ImportError:
    yaml = None

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.scan.scanner.baseline_config import auto_detect_baseline

# ---------------------------------------------------------------------------
# Category / Severity mapping
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("Account Policies",      ["password", "account lockout", "lockout"]),
    ("Audit Policies",        ["audit", "logon", "logoff", "process creation", "object access"]),
    ("User Rights Assignment",["user rights", "privilege", "deny log on", "access this computer"]),
    ("Security Options",      ["security options", "uac", "lan manager", "ntlm", "anonymous", "smb", "signing"]),
    ("Windows Firewall",      ["firewall", "domain profile", "private profile", "public profile"]),
    ("Windows Defender",      ["defender", "antivirus", "smartscreen", "attack surface", "asr", "cloud protection"]),
    ("Remote Access",         ["remote desktop", "rdp", "terminal services", "nla", "remote assistance"]),
    ("Services & Features",   ["services", "service", "telnet", "ftp", "snmp", "scheduled task"]),
    ("Credential Protection", ["credential", "lsa", "lsass", "wdigest", "delegation", "kerberos"]),
    ("TLS/Cipher Suites",     ["tls", "ssl", "cipher", "rc4", "3des", "schannel"]),
]

CRITICAL_KW = ["debug programs","credential","lsa","lsass","wdigest","kerberos","delegation","remote desktop"]
HIGH_KW     = ["password","lockout","audit","logon","user rights","privilege","uac","ntlm","lan manager",
                "smb","signing","firewall","rdp","tls","ssl","cipher"]
MEDIUM_KW   = ["defender","smartscreen","attack surface","service","scheduled task","autoplay","autorun",
                "printer","bluetooth"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower() or "baseline"


# check_id prefix: WIN11, WS2022, WS2025, DC
_OS_PREFIX_MAP = [
    ("domain controller", "DC"),
    ("server 2025",       "WS2025"),
    ("server 2022",       "WS2022"),
    ("server 2019",       "WS2019"),
    ("windows 11",        "WIN11"),
    ("windows 10",        "WIN10"),
]

_SHEET_PREFIX_MAP = {
    "computer":         "COMP",
    "user":             "USER",
    "security_template":"SEC",
    "advanced_audit":   "AUDIT",
    "firewall":         "FW",
    "services":         "SVC",
    "applocker_dc":     "APL",
}

def _col_to_role(col: str) -> str:
    col_lower = col.lower()
    if "domain controller" in col_lower:
        return "Domain Controller"
    if "member server" in col_lower:
        return "Member Server"
    if "windows 11" in col_lower or "windows 10" in col_lower or "policy value" in col_lower:
        return "Member Server"
    return col


def _os_prefix(version_id: str) -> str:
    low = version_id.lower()
    for keyword, prefix in _OS_PREFIX_MAP:
        if keyword in low:
            return prefix
    return "BASE"


def _extract_registry_path(reg_info: str, sheet_type: str) -> str:
    reg = _clean(reg_info)
    if not reg:
        return ""
    if sheet_type == "applocker_dc" and reg.lower() != "service general setting":
        return f"HKLM\\{reg}"
    low = reg.lower()
    if low in {"not a registry key", "service general setting"} \
            or "not a registry" in low or "not registry" in low:
        return ""
    return reg


def _category(sheet_name: str, sheet_type: str, policy_path: str, check_name: str) -> str:
    haystack = f"{sheet_name} {sheet_type} {policy_path} {check_name}".lower()
    for category, keywords in CATEGORY_KEYWORDS:
        if any(k in haystack for k in keywords):
            return category
    fallback = {
        "firewall":         "Windows Firewall",
        "advanced_audit":   "Audit Policies",
        "services":         "Services & Features",
    }
    if sheet_type in fallback:
        return fallback[sheet_type]
    if policy_path in ("Password Policy", "Account Lockout"):
        return "Account Policies"
    if policy_path == "User Rights Assignments":
        return "User Rights Assignment"
    if policy_path == "Security Options":
        return "Security Options"
    return "Security Options"


def _severity(category: str, policy_path: str, check_name: str, registry_path: str) -> str:
    haystack = f"{category} {policy_path} {check_name} {registry_path}".lower()
    if any(k in haystack for k in CRITICAL_KW):
        return "Critical"
    if category in {"User Rights Assignment", "Credential Protection"}:
        return "Critical"
    if any(k in haystack for k in HIGH_KW):
        return "High"
    if category in {"Account Policies","Audit Policies","Security Options",
                     "Windows Firewall","Remote Access","TLS/Cipher Suites"}:
        return "High"
    if any(k in haystack for k in MEDIUM_KW):
        return "Medium"
    if category in {"Windows Defender","Services & Features"}:
        return "Medium"
    return "Low"


def _remediation(category: str, policy_path: str, check_name: str,
                  registry_path: str, expected_value: str) -> str:
    """คำแนะนำการแก้ไขเป็นภาษาไทย"""
    loc = policy_path or registry_path or "การตั้งค่าความปลอดภัย"

    if registry_path:
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ผ่าน Registry Editor หรือ Group Policy "
            f"(Registry: {registry_path})"
        )
    if category == "Account Policies":
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ใน Local Security Policy (secpol.msc) → Account Policies → {loc}"
        )
    if category == "Audit Policies":
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ใน Advanced Audit Policy Configuration หรือใช้ auditpol.exe"
        )
    if category == "Windows Firewall":
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ใน Windows Defender Firewall with Advanced Security หรือ Group Policy"
        )
    if category == "User Rights Assignment":
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ใน Local Security Policy (secpol.msc) → Local Policies → User Rights Assignment"
        )
    if category == "Services & Features":
        return (
            f"ตั้งค่า service/task '{check_name}' เป็น '{expected_value}' "
            f"ผ่าน services.msc หรือ Group Policy Preferences"
        )
    if category == "Windows Defender":
        return (
            f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
            f"ใน Group Policy → Windows Defender Antivirus หรือ PowerShell Set-MpPreference"
        )
    if category == "Credential Protection":
        return (
            f"เปิดใช้งาน '{check_name}' (ค่าที่ต้องการ: '{expected_value}') "
            f"ใน Group Policy → Credential Guard หรือ Device Guard"
        )
    if category == "TLS/Cipher Suites":
        return (
            f"ปิดการใช้งาน '{check_name}' (ค่าที่ต้องการ: '{expected_value}') "
            f"ผ่าน Registry: {registry_path or 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL'}"
        )
    return (
        f"ตั้งค่า '{check_name}' เป็น '{expected_value}' "
        f"ใน {loc} ผ่าน Group Policy หรือ Local Security Policy (secpol.msc)"
    )


# ---------------------------------------------------------------------------
# Core converter
# ---------------------------------------------------------------------------

def analyze_workbook(path: Path) -> dict[str, Any]:
    cfg = auto_detect_baseline(str(path))
    sheets = pd.read_excel(path, sheet_name=None, nrows=1)
    result = {
        "baseline_id": _slug(cfg.version_id),
        "baseline_name": cfg.display_name,
        "os_family": cfg.os_family,
        "filename": path.name,
        "sheets": [],
    }
    for sheet_name, df in sheets.items():
        sheet_cfg = cfg.sheets.get(sheet_name)
        if sheet_cfg is None or sheet_cfg.sheet_type == "skip":
            continue
        columns = [str(c).strip() for c in df.columns if str(c).strip()]
        detected = [c for c in sheet_cfg.target_columns if c in columns]
        result["sheets"].append({
            "sheet": sheet_name,
            "sheet_type": sheet_cfg.sheet_type,
            "columns": columns,
            "detected_target_columns": detected,
            "selected_target_columns": detected,
        })
    return result


def convert_workbook(path: Path, target_column_overrides: dict[str, list[str]] | None = None) -> dict[str, Any]:
    cfg    = auto_detect_baseline(str(path))
    sheets = pd.read_excel(path, sheet_name=None)
    os_pfx = _os_prefix(cfg.version_id)
    overrides = target_column_overrides or {}

    # key = (sheet_type, check_name, policy_path, expected_value)
    # value = check dict  — ใช้สำหรับ deduplication
    seen: dict[tuple, dict] = {}
    counters: dict[str, int] = {}

    for sheet_name, df in sheets.items():
        sheet_cfg = cfg.sheets.get(sheet_name)
        if sheet_cfg is None or sheet_cfg.sheet_type == "skip":
            continue

        # แก้จาก v1: ใช้ col in df.columns ตรงๆ ไม่ผ่าน resolve_target_col
        requested_columns = overrides.get(sheet_name) or overrides.get(sheet_cfg.sheet_type)
        target_columns = (
            [c for c in requested_columns if c in df.columns]
            if requested_columns
            else [c for c in sheet_cfg.target_columns if c in df.columns]
        )
        if not target_columns:
            continue

        stype    = sheet_cfg.sheet_type
        sh_pfx   = _SHEET_PREFIX_MAP.get(stype, "GEN")
        id_pfx   = f"{os_pfx}-{sh_pfx}"

        for _, row in df.iterrows():
            check_name = _clean(row.get(sheet_cfg.policy_name_col))
            if not check_name:
                continue

            policy_path   = _clean(row.get(sheet_cfg.policy_path_col))
            registry_path = _extract_registry_path(
                _clean(row.get(sheet_cfg.reg_info_col)), stype
            )

            for target_col in target_columns:
                expected_value = _clean(row.get(target_col))
                if not expected_value:
                    continue

                cat = _category(sheet_name, stype, policy_path, check_name)
                sev = _severity(cat, policy_path, check_name, registry_path)

                role = _col_to_role(target_col)
                # deduplication key
                dedup_key = (stype, check_name, policy_path, expected_value, role)

                if dedup_key in seen:
                    continue

                # สร้าง check_id สั้นๆ เช่น WIN11-COMP-0001
                counters[id_pfx] = counters.get(id_pfx, 0) + 1
                check_id = f"{id_pfx}-{counters[id_pfx]:04d}"

                check = {
                    "check_id":      check_id,
                    "check_name":    check_name,
                    "category":      cat,
                    "severity":      sev,
                    "registry_path": registry_path,
                    "policy_path":   policy_path,
                    "expected_value": expected_value,
                    "remediation":   _remediation(cat, policy_path, check_name,
                                                   registry_path, expected_value),
                    "applies_to":    [role],
                    "source": {
                        "sheet":      sheet_name,
                        "sheet_type": stype,
                        "workbook":   path.name,
                    },
                }
                seen[dedup_key] = check

    return {
        "baseline_id":   _slug(cfg.version_id),
        "baseline_name": cfg.display_name,
        "os_family":     cfg.os_family,
        "source_file":   path.name,
        "schema_version": "2.0",
        "checks": list(seen.values()),
    }


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def write_definition(definition: dict[str, Any], output_dir: Path, fmt: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{definition['baseline_id']}.{fmt}"
    if fmt == "json":
        out.write_text(
            json.dumps(definition, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    elif fmt in {"yaml", "yml"}:
        if yaml is None:
            raise RuntimeError("pip install pyyaml")
        out.write_text(
            yaml.safe_dump(definition, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    else:
        raise ValueError(f"Unsupported format: {fmt}")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert Excel baselines to JSON/YAML")
    p.add_argument("--data-dir",   default=str(ROOT_DIR / "backend" / "data"))
    p.add_argument("--output-dir", default=str(ROOT_DIR / "baselines" / "generated"))
    p.add_argument("--format", choices=["json", "yaml", "all"], default="json")
    return p.parse_args()


def main() -> int:
    args       = parse_args()
    data_dir   = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    formats    = ["json", "yaml"] if args.format == "all" else [args.format]

    workbooks = sorted(
        p for p in data_dir.glob("*.xlsx")
        if "security baseline" in p.name.lower() or "securitybaseline" in p.name.lower()
    )
    if not workbooks:
        print(f"ไม่พบ baseline workbooks ใน {data_dir}", file=sys.stderr)
        return 1

    for wb in workbooks:
        print(f"กำลังแปลง {wb.name} ...")
        definition = convert_workbook(wb)
        for fmt in formats:
            out = write_definition(definition, output_dir, fmt)
            print(f"  → {out}  ({len(definition['checks'])} checks)")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
