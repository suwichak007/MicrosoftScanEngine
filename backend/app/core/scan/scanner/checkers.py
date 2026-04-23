"""
checkers.py  (updated – รองรับ Remote Registry)

เปลี่ยนหลักๆ:
  - check_single_registry: ถ้าเป็น remote scanner ให้ใช้
    executor.read_registry_remote() แทน winreg (ซึ่งอ่านได้แค่ local)
  - ฟังก์ชันอื่นทำงานผ่าน executor.run_subprocess อยู่แล้ว จึงไม่ต้องเปลี่ยน
"""

import re
import subprocess

import pandas as pd

from .helpers import norm_yn, normalize_value, resolve_sids
from .mappings import (
    AUDIT_SUBCATEGORY_MAP,
    FIREWALL_PROFILE_MAP,
    FIREWALL_SETTING_MAP,
    SECEDIT_KEY_MAP,
    SID_MAP,
    USER_RIGHTS_MAP,
)

# winreg ใช้ได้เฉพาะ Windows/local เท่านั้น
try:
    import winreg as _winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _winreg = None
    _WINREG_AVAILABLE = False


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _parse_reg_entry(reg_entry: str):
    """แยก path และ key_name จาก registry entry string"""
    if "!" in reg_entry:
        path_part, key_name = reg_entry.split("!", 1)
    else:
        path_part, key_name = reg_entry.rsplit("\\", 1)
    return path_part.strip(), key_name.strip()


def _normalize_hive(path_part: str):
    """
    ส่งคืน (hive_str, sub_path) เช่น ("HKLM", "SOFTWARE\\...") 
    หรือ None ถ้าไม่รู้จัก
    """
    upper = path_part.upper()
    if upper.startswith("HKEY_LOCAL_MACHINE\\") or upper.startswith("HKLM\\"):
        sub = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=re.IGNORECASE)
        return "HKLM", sub
    if upper.startswith("HKEY_CURRENT_USER\\") or upper.startswith("HKCU\\"):
        sub = re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=re.IGNORECASE)
        return "HKCU", sub
    if upper.startswith("MACHINE\\"):
        sub = re.sub(r"^MACHINE\\", "", path_part, flags=re.IGNORECASE)
        return "HKLM", sub
    if upper.startswith("SOFTWARE\\"):
        return "HKLM", path_part
    return None, None


# ---------------------------------------------------------------------------
# check_registry / check_single_registry
# ---------------------------------------------------------------------------

def check_registry(scanner, reg_info, expected):
    reg_str = str(reg_info).strip()
    if not reg_str or reg_str.lower() in ("nan", "not a registry key"):
        return "Manual Check Required"

    entries = [e.strip() for e in reg_str.split(";") if e.strip()]
    if not entries:
        return "Manual Check Required"

    final_fails = []
    any_manual = False
    any_pass = False

    for entry in entries:
        res = check_single_registry(scanner, entry, expected)
        if res == "Pass":
            any_pass = True
        elif str(res).startswith("Fail"):
            final_fails.append(res)
        else:
            any_manual = True

    if any_pass and not final_fails and not any_manual:
        return scanner.mark_pass()
    if final_fails:
        return " | ".join(final_fails)
    if any_manual:
        return "Manual Check Required"
    return "Fail (Not Configured)"


def check_single_registry(scanner, reg_entry, expected):
    try:
        path_part, key_name = _parse_reg_entry(reg_entry)
        hive_str, sub_path = _normalize_hive(path_part)

        if hive_str is None:
            return "Manual Check Required"

        # --- Remote: ใช้ executor.read_registry_remote ---
        if scanner.is_remote:
            actual_val, _ = scanner.executor.read_registry_remote(hive_str, sub_path, key_name)
        else:
            # --- Local: ใช้ winreg ---
            if not _WINREG_AVAILABLE:
                return "Manual Check Required (winreg not available)"
            hive = _winreg.HKEY_LOCAL_MACHINE if hive_str == "HKLM" else _winreg.HKEY_CURRENT_USER
            with _winreg.OpenKey(hive, sub_path) as hkey:
                actual_val, _ = _winreg.QueryValueEx(hkey, key_name)

        # --- Value comparison (เหมือนเดิม) ---
        if "RestrictRemoteSAM" in key_name:
            if str(actual_val).strip() == str(expected).strip():
                return "Pass"
            return f"Fail (Target: {expected}, Actual: {actual_val})"

        if key_name in ("NTLMMinClientSec", "NTLMMinServerSec"):
            try:
                actual_int = int(actual_val)
                expected_norm = normalize_value(expected)
                if expected_norm == "537395200" and actual_int == 537395200:
                    return "Pass"
                return f"Fail (Target: {expected}, Actual: {actual_val})"
            except Exception:
                return f"Fail (Target: {expected}, Actual: {actual_val})"

        actual_norm = normalize_value(actual_val)
        expected_norm = normalize_value(expected)

        if actual_norm == expected_norm:
            return "Pass"
        return f"Fail (Target: {expected}, Actual: {actual_val})"

    except FileNotFoundError:
        return f"Fail (Not Configured, Target: {expected})"
    except OSError as e:
        return f"Manual Check Required ({e})"
    except Exception as e:
        return f"Manual Check Required ({e})"


# ---------------------------------------------------------------------------
# ฟังก์ชันที่เหลือไม่มีการเปลี่ยนแปลง (ทำงานผ่าน executor อยู่แล้ว)
# ---------------------------------------------------------------------------

def check_security_template(scanner, policy_path, policy_name, reg_info, expected):
    reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""

    if policy_path == "Security Options":
        if reg_str and reg_str.lower() not in ("not a registry key", "nan", ""):
            return check_single_registry(scanner, reg_str, expected)
        if policy_name == "Network access: Allow anonymous SID/Name translation":
            return check_lsa_anonymous(scanner, expected)

    if policy_path in ("Password Policy", "Account Lockout"):
        return check_secedit_policy(scanner, policy_name, expected)

    if policy_path == "User Rights Assignments":
        return check_user_rights(scanner, policy_name, expected)

    return "Manual Check Required"


def check_lsa_anonymous(scanner, expected):
    actual = scanner._security_map.get("LSAAnonymousNameLookup")
    if actual is None:
        return f"Fail (Not Configured, Target: {expected})"
    if normalize_value(actual) == normalize_value(expected):
        return scanner.mark_pass()
    return f"Fail (Target: {expected}, Actual: {actual})"


def check_secedit_policy(scanner, policy_name, expected):
    key = SECEDIT_KEY_MAP.get(policy_name)
    if not key:
        return "Manual Check Required"

    raw_actual = scanner._security_map.get(key)
    scanner.debug.append(f"SECEDIT lookup {policy_name} -> {key} -> {raw_actual}")

    if raw_actual is None:
        return f"Fail (Not Configured, Target: {expected})"
    if normalize_value(raw_actual) == normalize_value(expected):
        return scanner.mark_pass()
    return f"Fail (Target: {expected}, Actual: {raw_actual})"


def check_user_rights(scanner, policy_name, expected):
    key = USER_RIGHTS_MAP.get(policy_name)
    if not key:
        return "Manual Check Required"

    expected_str = str(expected).strip()
    raw_actual = scanner._security_map.get(key)
    scanner.debug.append(f"RIGHTS lookup {policy_name} -> {key} -> {raw_actual}")

    if expected_str.lower() == "no one (blank)":
        if raw_actual is None:
            return scanner.mark_pass()
        if str(raw_actual).strip() == "":
            return scanner.mark_pass()
        return f"Fail (Target: empty, Actual: {resolve_sids(raw_actual, SID_MAP)})"

    if raw_actual is None:
        return "Fail (Not Configured)"

    actual_resolved = resolve_sids(raw_actual, SID_MAP).lower()
    expected_parts = [t.strip().lower() for t in re.split(r"[;,]", expected_str) if t.strip()]

    if all(any(ep in part for part in actual_resolved.split("; ")) for ep in expected_parts):
        if "everyone" not in actual_resolved or "everyone" in expected_str.lower():
            return scanner.mark_pass()

    return f"Fail (Target: {expected}, Actual: {resolve_sids(raw_actual, SID_MAP)})"


def check_advanced_audit(scanner, policy_name, expected):
    subcategory = AUDIT_SUBCATEGORY_MAP.get(policy_name, policy_name.replace("Audit ", "").strip())
    actual = scanner._audit_map.get(subcategory)
    scanner.debug.append(f"AUDIT lookup {policy_name} -> {subcategory} -> {actual}")

    if actual is None:
        return f"Fail (Not Configured, Target: {expected})"

    target = str(expected).strip().replace(",", " and")
    if actual.lower() == target.lower():
        return scanner.mark_pass()
    return f"Fail (Target: {target}, Actual: {actual})"


def check_defender_policy(scanner, policy_name, expected):
    data = scanner._mp_pref or {}
    if not data:
        return "Manual Check Required"

    def _bool_false_is_enabled(key):
        actual = data.get(key)
        scanner.debug.append(f"MPPREF lookup {policy_name} -> {key} -> {actual}")
        if actual is None:
            return "Manual Check Required"
        if actual is False:
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def _maps_check():
        actual = data.get("MAPSReporting")
        scanner.debug.append(f"MPPREF lookup {policy_name} -> MAPSReporting -> {actual}")
        if actual is None:
            return "Manual Check Required"
        if int(actual) >= 1:
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def _sample_check():
        actual = data.get("SubmitSamplesConsent")
        scanner.debug.append(f"MPPREF lookup {policy_name} -> SubmitSamplesConsent -> {actual}")
        if actual is None:
            return "Manual Check Required"
        if int(actual) in (1, 3):
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def _network_protection_check():
        actual = data.get("EnableNetworkProtection")
        scanner.debug.append(f"MPPREF lookup {policy_name} -> EnableNetworkProtection -> {actual}")
        if actual is None:
            return "Manual Check Required"
        if str(actual) == "1":
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def _pua_check():
        actual = data.get("PUAProtection")
        scanner.debug.append(f"MPPREF lookup {policy_name} -> PUAProtection -> {actual}")
        if actual is None:
            return "Manual Check Required"
        if str(actual) == "1":
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    mapping = {
        "Turn on behavior monitoring": lambda: _bool_false_is_enabled("DisableBehaviorMonitoring"),
        "Turn off real-time protection": lambda: _bool_false_is_enabled("DisableRealtimeMonitoring"),
        "Scan all downloaded files and attachments": lambda: _bool_false_is_enabled("DisableIOAVProtection"),
        "Turn on script scanning": lambda: _bool_false_is_enabled("DisableScriptScanning"),
        "Monitor file and program activity on your computer": lambda: _bool_false_is_enabled("DisableRealtimeMonitoring"),
        "Join Microsoft MAPS": _maps_check,
        "Send file samples when further analysis is required": _sample_check,
        "Prevent users and apps from accessing dangerous websites": _network_protection_check,
        "Configure detection for potentially unwanted applications": _pua_check,
    }

    func = mapping.get(policy_name)
    if not func:
        return "Manual Check Required"
    try:
        return func()
    except Exception as e:
        return f"Manual Check Required ({e})"


def check_firewall(scanner, policy_path, policy_name, expected):
    profile_name = policy_path.split("\\")[0].strip()
    profile_key = FIREWALL_PROFILE_MAP.get(profile_name)
    if not profile_key:
        return f"Manual Check Required (Unknown profile: {profile_name})"

    setting_info = FIREWALL_SETTING_MAP.get(policy_name)
    if not setting_info:
        return f"Manual Check Required (Unknown setting: {policy_name})"

    setting_type, param = setting_info
    try:
        if profile_key not in scanner._netsh_cache:
            raw = scanner.executor.check_output(
                f"netsh advfirewall show {profile_key}profile",
                shell=True,
                stderr=subprocess.STDOUT,
            ).decode(errors="replace")
            scanner._netsh_cache[profile_key] = raw.lower()

        output_lower = scanner._netsh_cache[profile_key]
        expected_str = str(expected).strip().lower().rstrip()

        if setting_type == "state":
            match = re.search(r"state\s+(on|off)", output_lower)
            actual = match.group(1) if match else "unknown"
            if actual == expected_str:
                return scanner.mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual.upper()})"

        if setting_type == "firewallpolicy":
            match = re.search(r"firewall\s*policy\s+(\w+),(\w+)", output_lower)
            if match:
                inbound_val = "block" if "block" in match.group(1) else "allow"
                outbound_val = "allow" if "allow" in match.group(2) else "block"
                actual = inbound_val if param == "inbound" else outbound_val
                if actual == expected_str:
                    return scanner.mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual})"
            return f"Manual Check Required (Target: {expected})"

        if setting_type == "settings":
            setting_patterns = {
                "inboundusernotification": r"inboundusernotification\s+(\S+)",
                "localfirewallrules": r"localfirewallrules\s+(\S+)",
                "localconsecrules": r"localconsecrules\s+(\S+)",
            }
            pattern = setting_patterns.get(param, fr"{re.escape(param)}\s+(\S+)")
            match = re.search(pattern, output_lower)
            if match:
                actual = match.group(1).strip().rstrip(".")
                if norm_yn(actual) == norm_yn(expected_str):
                    return scanner.mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual})"
            return f"Manual Check Required (Target: {expected})"

        if setting_type == "logging":
            if param == "maxfilesize":
                match = re.search(r"maxfilesize\s+(\d+)", output_lower)
                if match:
                    actual = match.group(1)
                    if actual == str(int(expected)):
                        return scanner.mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
            elif param == "droppedpackets":
                match = re.search(r"logdroppedpackets\s+(\S+)", output_lower)
                if match:
                    if norm_yn(match.group(1)) == norm_yn(expected_str):
                        return scanner.mark_pass()
                    return f"Fail (Target: {expected}, Actual: {match.group(1)})"
            elif param == "allowedconnections":
                match = re.search(r"logallowedconnections\s+(\S+)", output_lower)
                if match:
                    if norm_yn(match.group(1)) == norm_yn(expected_str):
                        return scanner.mark_pass()
                    return f"Fail (Target: {expected}, Actual: {match.group(1)})"

            try:
                log_key = f"{profile_key}_log"
                if log_key not in scanner._netsh_cache:
                    raw_log = scanner.executor.check_output(
                        f"netsh advfirewall show {profile_key}profile logging",
                        shell=True,
                        stderr=subprocess.STDOUT,
                    ).decode(errors="replace")
                    scanner._netsh_cache[log_key] = raw_log.lower()

                log_output = scanner._netsh_cache[log_key]
                patterns_log = {
                    "droppedpackets": r"logdroppedpackets\s+(\S+)",
                    "allowedconnections": r"logallowedconnections\s+(\S+)",
                    "maxfilesize": r"maxfilesize\s+(\d+)",
                }
                if param in patterns_log:
                    m = re.search(patterns_log[param], log_output)
                    if m:
                        actual = m.group(1)
                        if param == "maxfilesize":
                            if actual == str(int(expected)):
                                return scanner.mark_pass()
                            return f"Fail (Target: {expected}, Actual: {actual})"
                        if norm_yn(actual) == norm_yn(expected_str):
                            return scanner.mark_pass()
                        return f"Fail (Target: {expected}, Actual: {actual})"
            except Exception:
                pass

            return f"Fail (Not Configured, Target: {expected})"

    except Exception as e:
        return f"Manual Check Required ({e})"

    return f"Manual Check Required (Target: {expected})"


def check_service(scanner, row_type, service_name, expected):
    if str(row_type).strip() == "Scheduled Task":
        return check_scheduled_task(scanner, service_name, expected)
    try:
        cmd = f"(Get-Service -Name '{service_name}' -ErrorAction Stop).StartType"
        result = scanner.executor.check_output(
            [scanner.POWERSHELL, "-NoProfile", "-Command", cmd],
            stderr=subprocess.STDOUT,
        ).decode(errors="replace").strip()

        if result.lower() == str(expected).lower():
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {result})"
    except subprocess.CalledProcessError:
        return "Service Not Found"
    except Exception as e:
        return f"Manual Check Required ({e})"


def check_scheduled_task(scanner, task_name, expected):
    try:
        cmd = f"(Get-ScheduledTask -TaskName '{task_name}' -ErrorAction Stop).State"
        result = scanner.executor.check_output(
            [scanner.POWERSHELL, "-NoProfile", "-Command", cmd],
            stderr=subprocess.STDOUT,
        ).decode(errors="replace").strip()

        if result.lower() == str(expected).lower():
            return scanner.mark_pass()
        return f"Fail (Target: {expected}, Actual: {result})"
    except subprocess.CalledProcessError:
        return "Task Not Found"
    except Exception as e:
        return f"Manual Check Required ({e})"