"""
security_scanner.py  (updated — config-driven multi-OS support)

เปลี่ยนหลักๆ:
  - รับ BaselineConfig แทนการ hardcode column names / sheet names
  - run_baseline_scan() อ่าน sheet config จาก BaselineConfig
  - รองรับ sheet_type ใหม่: "advanced_audit" ทั้งชื่อ "Advanced Audit" และ "Advanced Auditing"
  - เพิ่ม sheet_type "applocker" (skip / Manual สำหรับตอนนี้)
  - helpers.resolve_target_col ถูกแทนที่ด้วย baseline_config.resolve_target_col
"""

import os
import re
import subprocess

import pandas as pd

from .baseline_config import BaselineConfig, SheetConfig, resolve_target_col
from .mappings import (
    FIREWALL_PROFILE_MAP,
    FIREWALL_SETTING_MAP,
    SID_MAP,
    SPECIAL_VALUE_MAP,
    USER_RIGHTS_MAP,
)

SUBPROCESS_TIMEOUT = 30


class SecurityScanner:

    def __init__(
        self,
        data_path: str = None,
        executor=None,
        baseline_config: BaselineConfig = None,
        role: str = "Member Server",
    ):
        self.results  = {}
        self.passed   = 0
        self.total    = 0
        self.executor = executor
        self._role = role

        # ── Baseline config ──────────────────────────────────────────────
        # ถ้าไม่ส่ง config มา → fallback เป็น Windows 11 v24H2 (backward compat)
        if baseline_config is not None:
            self._cfg = baseline_config
        else:
            from .baseline_config import BASELINE_CONFIGS
            self._cfg = BASELINE_CONFIGS["Windows 11 v24H2"]

        # ── File path ────────────────────────────────────────────────────
        default_data_path = data_path or r"D:\MiniProject\backend\data"
        self.target_file  = os.path.join(default_data_path, self._cfg.filename)

        self.secedit_file        = "secedit_export.inf"
        self.remote_secedit_file = r"C:\Windows\Temp\secedit_export.inf"

        # mappings
        self.sid_map              = SID_MAP
        self.user_rights_map      = USER_RIGHTS_MAP
        self.special_value_map    = SPECIAL_VALUE_MAP
        self.firewall_profile_map = FIREWALL_PROFILE_MAP
        self.firewall_setting_map = FIREWALL_SETTING_MAP

    # ------------------------------------------------------------------
    # Command runner
    # ------------------------------------------------------------------
    def _run_cmd(self, cmd: str, timeout: int = SUBPROCESS_TIMEOUT) -> str:
        if self.executor:
            stdout, _stderr, _rc = self.executor._run_remote_command(cmd)
            return stdout
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout
        )
        return out.decode(errors="replace")

    # ------------------------------------------------------------------
    # secedit
    # ------------------------------------------------------------------
    def _export_security_policy(self):
        try:
            if self.executor:
                self._run_cmd(f"secedit /export /cfg {self.remote_secedit_file}")
                content = self._run_cmd(f"type {self.remote_secedit_file}")
                self._run_cmd(f"del {self.remote_secedit_file}")
                return content
            subprocess.run(
                ["secedit", "/export", "/cfg", self.secedit_file],
                capture_output=True, check=True, timeout=SUBPROCESS_TIMEOUT,
            )
            for enc in ("utf-16", "utf-8", "cp1252"):
                try:
                    with open(self.secedit_file, "r", encoding=enc) as f:
                        return f.read()
                except Exception:
                    continue
            return ""
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def resolve_sids(self, sid_string):
        if not sid_string:
            return "None"
        parts    = [p.strip() for p in sid_string.split(",")]
        resolved = [self.sid_map.get(p, p) for p in parts]
        return "; ".join(resolved)

    def normalize_value(self, value):
        val = str(value).strip().lower()
        if val in ("1", "enabled", "on", "yes", "true"):
            return "1"
        if val in ("0", "disabled", "off", "no", "false"):
            return "0"
        if val.lstrip("-").isdigit():
            return val
        mapped = self.special_value_map.get(val)
        if mapped is not None:
            return mapped
        return val

    def _mark_pass(self):
        self.passed += 1
        return "Pass"

    def _not_configured_is_disabled(self, expected_norm: str) -> bool:
        return expected_norm in ("0",)

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------
    def check_registry(self, reg_info, expected):
        reg_str = str(reg_info).strip()
        entries = [e.strip() for e in reg_str.split(";") if "!" in e]
        if not entries:
            return "Manual Check Required"
        for entry in entries:
            result = self._check_single_registry(entry, expected)
            if result == "Pass":
                return result
        return result

    def _check_single_registry(self, reg_entry, expected):
        import winreg

        try:
            if "!" in reg_entry:
                path_part, key_name = reg_entry.split("!", 1)
            else:
                path_part, key_name = reg_entry.rsplit("\\", 1)

            path_part = path_part.strip()
            key_name  = key_name.strip()
            upper     = path_part.upper()

            if upper.startswith("HKEY_LOCAL_MACHINE\\") or upper.startswith("HKLM\\"):
                hive     = winreg.HKEY_LOCAL_MACHINE
                sub_path = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("HKEY_CURRENT_USER\\") or upper.startswith("HKCU\\"):
                hive     = winreg.HKEY_CURRENT_USER
                sub_path = re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("MACHINE\\"):
                hive     = winreg.HKEY_LOCAL_MACHINE
                sub_path = re.sub(r"^MACHINE\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("SOFTWARE\\"):
                hive     = winreg.HKEY_LOCAL_MACHINE
                sub_path = path_part
            else:
                return "Manual Check Required"

            with winreg.OpenKey(hive, sub_path) as hkey:
                actual_val, _ = winreg.QueryValueEx(hkey, key_name)
                actual_norm   = self.normalize_value(actual_val)
                expected_norm = self.normalize_value(expected)

                if "RestrictRemoteSAM" in key_name:
                    if str(actual_val).strip() == str(expected).strip():
                        return self._mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual_val})"

                if actual_norm == expected_norm:
                    return self._mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual_val})"

        except FileNotFoundError:
            expected_norm = self.normalize_value(expected)
            if self._not_configured_is_disabled(expected_norm):
                return self._mark_pass()
            return f"Fail (Not Configured, Target: {expected})"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # ------------------------------------------------------------------
    # Security Template
    # ------------------------------------------------------------------
    def check_security_template(self, policy_path, policy_name, reg_info, expected, security_data):
        reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""

        if policy_path == "Security Options":
            if reg_str and reg_str.lower() not in ("not a registry key", "nan", ""):
                return self._check_single_registry(reg_str, expected)
            if policy_name == "Network access: Allow anonymous SID/Name translation":
                return self._check_lsa_anonymous(expected, security_data)

        if policy_path in ("Password Policy", "Account Lockout"):
            return self.check_secedit_policy(policy_name, expected, security_data)

        if policy_path == "User Rights Assignments":
            return self.check_user_rights(policy_name, expected, security_data)

        return "Manual Check Required"

    def _check_lsa_anonymous(self, expected, security_data):
        match = re.search(r"LSAAnonymousNameLookup\s*=\s*(\d+)", security_data, re.IGNORECASE)
        if match:
            actual = match.group(1)
            if self.normalize_value(actual) == self.normalize_value(expected):
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual})"
        return f"Fail (Not Configured, Target: {expected})"

    def check_secedit_policy(self, policy_name, expected, security_data):
        secedit_key_map = {
            "Minimum password length":                    "MinimumPasswordLength",
            "Maximum password age":                       "MaximumPasswordAge",
            "Minimum password age":                       "MinimumPasswordAge",
            "Enforce password history":                   "PasswordHistorySize",
            "Password must meet complexity requirements":  "PasswordComplexity",
            "Store passwords using reversible encryption": "ClearTextPassword",
            "Account lockout duration":                   "LockoutDuration",
            "Account lockout threshold":                  "LockoutBadCount",
            "Reset account lockout counter after":        "ResetLockoutCount",
            "Allow Administrator account lockout":        "AllowAdministratorLockout",
        }
        key = secedit_key_map.get(policy_name)
        if not key:
            return "Manual Check Required"
        match = re.search(fr"^{key}\s*=\s*(.*)", security_data, re.MULTILINE | re.IGNORECASE)
        if match:
            raw_actual = match.group(1).strip()
            if self.normalize_value(raw_actual) == self.normalize_value(expected):
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {raw_actual})"
        if self._not_configured_is_disabled(self.normalize_value(expected)):
            return self._mark_pass()
        return f"Fail (Not Configured, Target: {expected})"

    def check_user_rights(self, policy_name, expected, security_data):
        key = self.user_rights_map.get(policy_name)
        if not key:
            return "Manual Check Required"
        match = re.search(fr"^{key}\s*=\s*(.*)", security_data, re.MULTILINE | re.IGNORECASE)
        expected_str = str(expected).strip()
        if expected_str.lower() in ("no one (blank)",):
            if match:
                raw = match.group(1).strip()
                if raw == "":
                    return self._mark_pass()
                return f"Fail (Target: empty, Actual: {self.resolve_sids(raw)})"
            return self._mark_pass()
        if not match:
            return f"Fail (Not Configured, Target: {expected})"
        raw_actual       = match.group(1).strip()
        actual_resolved  = self.resolve_sids(raw_actual).lower()
        expected_parts   = [t.strip().lower() for t in re.split(r"[;,]", expected_str)]
        if all(any(ep in part for part in actual_resolved.split("; ")) for ep in expected_parts):
            if "everyone" not in actual_resolved or "everyone" in expected_str.lower():
                return self._mark_pass()
        return f"Fail (Target: {expected}, Actual: {self.resolve_sids(raw_actual)})"

    # ------------------------------------------------------------------
    # Advanced Audit  (รองรับทั้ง "Advanced Audit" และ "Advanced Auditing")
    # ------------------------------------------------------------------
    def _fetch_all_audit_policies(self):
        if hasattr(self, "_audit_cache"):
            return self._audit_cache
        try:
            if self.executor:
                output = self._run_cmd("auditpol /get /category:*")
            else:
                output = subprocess.check_output(
                    "auditpol /get /category:*",
                    shell=True, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                ).decode(errors="replace")

            cache = {}
            valid_settings = {"No Auditing", "Success", "Failure", "Success and Failure"}

            for line in output.splitlines():
                # subcategory lines มี leading space เสมอ — category headers ไม่มี
                if not line.startswith(" "):
                    continue

                parts = re.split(r"\s{2,}", line.strip())
                if len(parts) >= 2 and parts[-1] in valid_settings:
                    subcat  = parts[0].strip()
                    setting = parts[-1].strip()

                    parts_found = []
                    if "Success" in setting:
                        parts_found.append("Success")
                    if "Failure" in setting:
                        parts_found.append("Failure")

                    cache[subcat.lower()] = (
                        " and ".join(parts_found) if parts_found else "No Auditing"
                    )

            self._audit_cache = cache
            return cache

        except Exception:
            self._audit_cache = {}
            return {}

    def _fetch_applocker_policy(self) -> str:
        if hasattr(self, "_applocker_xml"):
            return self._applocker_xml
        try:
            cmd = "Get-AppLockerPolicy -Effective -Xml"
            if self.executor:
                output = self._run_cmd(cmd)
            else:
                output = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", cmd],
                    stderr=subprocess.STDOUT,
                    timeout=SUBPROCESS_TIMEOUT,
                ).decode(errors="replace")
            self._applocker_xml = output
            return output
        except Exception:
            self._applocker_xml = ""
            return ""


    def check_applocker_dc(self, row) -> str | None:
        """
        Check AppLocker for Domain Controller
        3 ประเภท:
        1. EnforcementMode  — check registry
        2. Value (Rule)     — check XML guid
        3. Service          — check AppIDSvc
        """
        reg_key        = str(row.get("Policy Group or Registry Key") or "").strip()
        policy_setting = str(row.get("Policy Setting") or "").strip()
        expected_val   = str(row.get("Domain Controller") or "").strip()

        # ── Case 3: Application Identity Service ─────────────────────────
        if reg_key == "Service General Setting":
            service_name   = policy_setting.strip('"')
            expected_start = "Automatic" if "Automatic" in expected_val else expected_val
            actual         = self._svc_cache.get(service_name)
            if actual is None or actual == "NOT_FOUND":
                return f"Fail (Not Configured, Target: {expected_start})"
            if actual.lower() == expected_start.lower():
                return self._mark_pass()
            return f"Fail (Target: {expected_start}, Actual: {actual})"

        # ── Case 1: EnforcementMode ───────────────────────────────────────
        if policy_setting == "EnforcementMode":
            reg_entry = f"HKLM\\{reg_key}!EnforcementMode"
            expected_norm = "1"  # Enforce rules = 1
            return self.check_registry(reg_entry, expected_norm)

        # ── Case 2: Rule GUID — check XML ────────────────────────────────
        if policy_setting == "Value":
            guid = reg_key.split("\\")[-1] if "\\" in reg_key else ""
            if not guid:
                return "Manual Check Required (No GUID)"

            xml = self._fetch_applocker_policy()
            if not xml:
                return "Manual Check Required (Cannot get AppLocker policy)"

            if guid.lower() in xml.lower():
                return self._mark_pass()

            rule_desc = expected_val.split("|")[-1].strip() if "|" in expected_val else expected_val
            return f"Fail (Rule not found: {rule_desc})"

        # ── empty expected (DLL/Script/MSI ไม่มี rule) ───────────────────
        if not expected_val:
            self.total -= 1
            return None

        return "Manual Check Required"

    def check_advanced_audit(self, policy_name, expected):
        subcategory_map = {
            "Audit Credential Validation":              "Credential Validation",
            "Audit Kerberos Authentication Service":    "Kerberos Authentication Service",
            "Audit Kerberos Service Ticket Operations": "Kerberos Service Ticket Operations",
            "Audit Security Group Management":          "Security Group Management",
            "Audit User Account Management":            "User Account Management",
            "Audit Computer Account Management":        "Computer Account Management",
            "Audit Distribution Group Management":      "Distribution Group Management",
            "Audit Other Account Management Events":    "Other Account Management Events",
            "Audit PNP Activity":                       "Plug and Play Events",
            "Audit Process Creation":                   "Process Creation",
            "Audit Process Termination":                "Process Termination",
            "Audit Account Lockout":                    "Account Lockout",
            "Audit Group Membership":                   "Group Membership",
            "Audit Logon":                              "Logon",
            "Audit Logoff":                             "Logoff",
            "Audit Other Logon/Logoff Events":          "Other Logon/Logoff Events",
            "Audit Special Logon":                      "Special Logon",
            "Audit Network Policy Server":              "Network Policy Server",
            "Audit Detailed File Share":                "Detailed File Share",
            "Audit File Share":                         "File Share",
            "Audit File System":                        "File System",
            "Audit Other Object Access Events":         "Other Object Access Events",
            "Audit Registry":                           "Registry",
            "Audit Removable Storage":                  "Removable Storage",
            "Audit SAM":                                "SAM",
            "Audit Audit Policy Change":                "Audit Policy Change",
            "Audit Authentication Policy Change":       "Authentication Policy Change",
            "Audit MPSSVC Rule-Level Policy Change":    "MPSSVC Rule-Level Policy Change",
            "Audit Other Policy Change Events":         "Other Policy Change Events",
            "Audit Authorization Policy Change":        "Authorization Policy Change",
            "Audit Sensitive Privilege Use":            "Sensitive Privilege Use",
            "Audit Non Sensitive Privilege Use":        "Non Sensitive Privilege Use",
            "Audit Other System Events":                "Other System Events",
            "Audit Security State Change":              "Security State Change",
            "Audit Security System Extension":          "Security System Extension",
            "Audit System Integrity":                   "System Integrity",
        }
        subcategory = subcategory_map.get(policy_name, policy_name.replace("Audit ", "").strip())
        audit_cache = self._fetch_all_audit_policies()
        actual      = audit_cache.get(subcategory.lower())
        target      = str(expected).strip().replace(",", " and")
        if actual is None:
            if target.lower() == "no auditing":
                return self._mark_pass()
            return f"Fail (Not Configured, Target: {target})"
        if actual.lower() == target.lower():
            return self._mark_pass()
        return f"Fail (Target: {target}, Actual: {actual})"

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------
    def check_firewall(self, policy_path, policy_name, expected):
        profile_name = policy_path.split("\\")[0].strip()
        profile_key  = self.firewall_profile_map.get(profile_name)
        if not profile_key:
            return f"Manual Check Required (Unknown profile: {profile_name})"
        setting_info = self.firewall_setting_map.get(policy_name)
        if not setting_info:
            return f"Manual Check Required (Unknown setting: {policy_name})"
        setting_type, param = setting_info

        try:
            if profile_key not in self._netsh_cache:
                if self.executor:
                    raw = self._run_cmd(f"netsh advfirewall show {profile_key}profile")
                else:
                    raw = subprocess.check_output(
                        f"netsh advfirewall show {profile_key}profile",
                        shell=True, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                    ).decode(errors="replace")
                self._netsh_cache[profile_key] = raw.lower()
            output_lower = self._netsh_cache[profile_key]
            expected_str = str(expected).strip().lower().rstrip()

            if setting_type == "state":
                match  = re.search(r"state\s+(on|off)", output_lower)
                actual = match.group(1) if match else "unknown"
                if actual == expected_str:
                    return self._mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual.upper()})"

            if setting_type == "firewallpolicy":
                match = re.search(r"firewall\s*policy\s+(\w+),(\w+)", output_lower)
                if match:
                    inbound_val  = "block" if "block" in match.group(1) else "allow"
                    outbound_val = "allow" if "allow" in match.group(2) else "block"
                    actual       = inbound_val if param == "inbound" else outbound_val
                    if actual == expected_str:
                        return self._mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            if setting_type == "settings":
                setting_patterns = {
                    "inboundusernotification": r"inboundusernotification\s+(\S+)",
                    "localfirewallrules":       r"localfirewallrules\s+(\S+)",
                    "localconsecrules":         r"localconsecrules\s+(\S+)",
                }
                pattern = setting_patterns.get(param, fr"{re.escape(param)}\s+(\S+)")
                match   = re.search(pattern, output_lower)
                if match:
                    actual = match.group(1).strip().rstrip(".")
                    if self._norm_yn(actual) == self._norm_yn(expected_str):
                        return self._mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            if setting_type == "logging":
                if param == "maxfilesize":
                    match = re.search(r"maxfilesize\s+(\d+)", output_lower)
                    if match:
                        actual = match.group(1)
                        if actual == str(int(expected)):
                            return self._mark_pass()
                        return f"Fail (Target: {expected}, Actual: {actual})"
                elif param == "droppedpackets":
                    match = re.search(r"logdroppedpackets\s+(\S+)", output_lower)
                    if match:
                        if self._norm_yn(match.group(1)) == self._norm_yn(expected_str):
                            return self._mark_pass()
                        return f"Fail (Target: {expected}, Actual: {match.group(1)})"
                elif param == "allowedconnections":
                    match = re.search(r"logallowedconnections\s+(\S+)", output_lower)
                    if match:
                        if self._norm_yn(match.group(1)) == self._norm_yn(expected_str):
                            return self._mark_pass()
                        return f"Fail (Target: {expected}, Actual: {match.group(1)})"
                return f"Fail (Not Configured, Target: {expected})"

        except Exception as e:
            return f"Manual Check Required ({e})"

        return f"Manual Check Required (Target: {expected})"

    def _norm_yn(self, val):
        v = str(val).strip().lower()
        if v in ("yes", "enable", "enabled", "on", "1", "true"):
            return "yes"
        if v in ("no", "disable", "disabled", "off", "0", "false", "n/a"):
            return "no"
        return v

    # ------------------------------------------------------------------
    # Services / Scheduled Tasks
    # ------------------------------------------------------------------
    def _fetch_all_services(self, service_names, task_names):
        if hasattr(self, "_svc_cache"):
            return self._svc_cache
        svc_cache = {}

        def _parse_output(out):
            for line in out.strip().splitlines():
                if "|" in line:
                    name, val = line.split("|", 1)
                    svc_cache[name.strip()] = val.strip()

        if self.executor:
            if service_names:
                names_ps = ",".join(f"'{n}'" for n in service_names)
                cmd = (
                    f"@({names_ps}) | ForEach-Object {{ "
                    f"$s = Get-Service -Name $_ -ErrorAction SilentlyContinue; "
                    f"if ($s) {{ \"$_|\" + $s.StartType }} else {{ \"$_|NOT_FOUND\" }} }}"
                )
                _parse_output(self._run_cmd(cmd))
            if task_names:
                names_ps = ",".join(f"'{n}'" for n in task_names)
                cmd = (
                    f"@({names_ps}) | ForEach-Object {{ "
                    f"$t = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue; "
                    f"if ($t) {{ \"$_|\" + $t.State }} else {{ \"$_|NOT_FOUND\" }} }}"
                )
                _parse_output(self._run_cmd(cmd))
        else:
            for names, is_task in [(service_names, False), (task_names, True)]:
                if not names:
                    continue
                names_ps = ",".join(f"'{n}'" for n in names)
                if is_task:
                    cmd = (
                        f"@({names_ps}) | ForEach-Object {{ "
                        f"$t = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue; "
                        f"if ($t) {{ \"$_|\" + $t.State }} else {{ \"$_|NOT_FOUND\" }} }}"
                    )
                else:
                    cmd = (
                        f"@({names_ps}) | ForEach-Object {{ "
                        f"$s = Get-Service -Name $_ -ErrorAction SilentlyContinue; "
                        f"if ($s) {{ \"$_|\" + $s.StartType }} else {{ \"$_|NOT_FOUND\" }} }}"
                    )
                try:
                    out = subprocess.check_output(
                        ["powershell", "-NoProfile", "-Command", cmd],
                        stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                    ).decode(errors="replace")
                    _parse_output(out)
                except Exception:
                    pass

        self._svc_cache = svc_cache
        return svc_cache

    def check_service(self, row_type, service_name, expected):
        actual = self._svc_cache.get(service_name)
        if actual is None or actual == "NOT_FOUND":
            if str(expected).lower() in ("disabled", "manual"):
                return self._mark_pass()
            return f"Fail (Not Configured, Target: {expected})"
        if actual.lower() == str(expected).lower():
            return self._mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def check_scheduled_task(self, task_name, expected):
        actual = self._svc_cache.get(task_name)
        if actual is None or actual == "NOT_FOUND":
            return f"Fail (Not Configured, Target: {expected})"
        if actual.lower() == str(expected).lower():
            return self._mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    # ------------------------------------------------------------------
    # Main Scan  (config-driven)
    # ------------------------------------------------------------------
    def run_baseline_scan(self):
        """สแกนตาม BaselineConfig — รองรับทุก OS version"""
        if not os.path.exists(self.target_file):
            return 0, {"Error": f"Baseline file not found: {self.target_file}"}

        all_sheets = pd.read_excel(self.target_file, sheet_name=None)

        # ── Pre-fetch ──────────────────────────────────────────────────
        security_data     = self._export_security_policy()
        self._netsh_cache = {}
        self._fetch_all_audit_policies()

        # Pre-fetch services (เฉพาะ OS ที่มี Services sheet)
        svc_sheet_cfg = self._cfg.sheets.get("Services")
        service_names, task_names = [], []
        if svc_sheet_cfg and svc_sheet_cfg.sheet_type == "services":
            svc_df = all_sheets.get("Services", pd.DataFrame())
            if not svc_df.empty:
                target_col = resolve_target_col(svc_sheet_cfg, list(svc_df.columns))
                if target_col:
                    for _, row in svc_df.iterrows():
                        if pd.isna(row.get(target_col)):
                            continue
                        row_type = str(row.get(svc_sheet_cfg.service_type_col) or "Services").strip()
                        name     = str(row.get(svc_sheet_cfg.service_name_col) or "").strip()
                        if not name:
                            continue
                        (task_names if row_type == "Scheduled Task" else service_names).append(name)
        if self._role == "Domain Controller" and "AppIDSvc" not in service_names:
            service_names.append("AppIDSvc")

        self._fetch_all_services(service_names, task_names)
        if not hasattr(self, "_svc_cache"):
            self._svc_cache = {}
        # ───────────────────────────────────────────────────────────────

        for sheet_name, df in all_sheets.items():
            # skip_sheets จาก config
            if sheet_name in self._cfg.skip_sheets:
                continue

            # หา SheetConfig — ถ้าไม่มีใน config ให้ skip
            sheet_cfg = self._cfg.sheets.get(sheet_name)
            if sheet_cfg is None or sheet_cfg.sheet_type == "skip":
                continue

            # หา target column
            target_col = resolve_target_col(sheet_cfg, list(df.columns), role=self._role)
            if not target_col:
                continue

            for _, row in df.iterrows():
                expected = row.get(target_col)
                if pd.isna(expected) or str(expected).strip() == "":
                    continue

                policy_name = str(
                    row.get(sheet_cfg.policy_name_col) or ""
                ).strip()
                if not policy_name or policy_name == "nan":
                    continue

                policy_path = str(row.get(sheet_cfg.policy_path_col) or "").strip()
                reg_info    = row.get(sheet_cfg.reg_info_col)

                self.total += 1

                # key สำหรับ result dict
                if sheet_cfg.sheet_type == "firewall":
                    profile_name = policy_path.split("\\")[0].strip()
                    full_key     = f"[Firewall] {profile_name} - {policy_name}"
                else:
                    full_key = f"[{sheet_name}] {policy_name}"

                # ── Dispatch ──────────────────────────────────────────
                stype = sheet_cfg.sheet_type

                if stype == "firewall":
                    self.results[full_key] = self.check_firewall(policy_path, policy_name, expected)

                elif stype == "advanced_audit":
                    self.results[full_key] = self.check_advanced_audit(policy_name, expected)

                elif stype == "security_template":
                    self.results[full_key] = self.check_security_template(
                        policy_path, policy_name, reg_info, expected, security_data
                    )

                elif stype == "services":
                    row_type     = str(row.get(sheet_cfg.service_type_col) or "Services").strip()
                    service_name = str(row.get(sheet_cfg.service_name_col) or policy_name).strip()
                    self.results[full_key] = self.check_service(row_type, service_name, expected)

                elif stype in ("computer", "user"):
                    reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                    if "!" in reg_str:
                        self.results[full_key] = self.check_registry(reg_str, expected)
                    else:
                        self.results[full_key] = "Manual Check Required"

                elif stype == "applocker":
                    self.results[full_key] = "Manual Check Required (AppLocker)"

                elif stype == "applocker_dc":
                    if self._role != "Domain Controller":
                        self.total -= 1
                        continue
                    result = self.check_applocker_dc(row)
                    if result is None:
                        continue
                    self.results[full_key] = result

                elif stype == "applocker_dc":
                    # check เฉพาะเมื่อ role เป็น Domain Controller
                    if self._role == "Domain Controller":
                        reg_path = str(row.get(sheet_cfg.policy_path_col) or "").strip()
                        reg_group = str(row.get("Policy Group or Registry Key") or "").strip()
                        policy_setting = str(row.get("Policy Setting") or "").strip()
                        expected_val = str(expected).strip()

                        if reg_group and policy_setting and expected_val:
                            full_reg = f"HKLM\\{reg_group}!{policy_setting}"
                            self.results[full_key] = self.check_registry(full_reg, expected_val)
                        else:
                            self.results[full_key] = "Manual Check Required (AppLocker Rule)"
                    else:
                        # Member Server ไม่ต้องสแกน AppLocker for DCs
                        self.total -= 1   # ไม่นับ

                else:
                    self.results[full_key] = "Manual Check Required"

        # ── Cleanup ────────────────────────────────────────────────────
        if os.path.exists(self.secedit_file):
            os.remove(self.secedit_file)

        score = int((self.passed / self.total) * 100) if self.total > 0 else 0

        # ── Section Summary Log ────────────────────────────────────────
        section_stats: dict = {}
        for key, val in self.results.items():
            m       = re.match(r"^\[([^\]]+)\]", key)
            section = m.group(1) if m else "Unknown"
            if section not in section_stats:
                section_stats[section] = {"Total": 0, "Pass": 0, "Fail": 0, "Manual": 0, "Other": 0}
            section_stats[section]["Total"] += 1
            v = str(val)
            if v == "Pass":
                section_stats[section]["Pass"] += 1
            elif v.startswith("Fail"):
                section_stats[section]["Fail"] += 1
            elif "Manual" in v:
                section_stats[section]["Manual"] += 1
            else:
                section_stats[section]["Other"] += 1

        lines = ["=" * 70, "SECTION SUMMARY", "=" * 70]
        for sec, s in sorted(section_stats.items()):
            pct = round(s["Pass"] / s["Total"] * 100, 2) if s["Total"] else 0
            lines.append(
                f"[{sec}] Total={s['Total']} | Pass={s['Pass']} | "
                f"Fail={s['Fail']} | Manual={s['Manual']} | "
                f"Other={s['Other']} | Pass%={pct}"
            )
        grand_total = sum(s["Total"]  for s in section_stats.values())
        grand_pass  = sum(s["Pass"]   for s in section_stats.values())
        grand_fail  = sum(s["Fail"]   for s in section_stats.values())
        grand_man   = sum(s["Manual"] for s in section_stats.values())
        grand_pct   = round(grand_pass / grand_total * 100, 2) if grand_total else 0
        lines += [
            "-" * 70,
            f"[ALL] Total={grand_total} | Pass={grand_pass} | "
            f"Fail={grand_fail} | Manual={grand_man} | Pass%={grand_pct}",
            "=" * 70,
        ]

        log_path = os.path.join(os.path.dirname(self.target_file), "scan_summary.log")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))

        return score, self.results

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def print_summary(self, score, results):
        pass_list   = [k for k, v in results.items() if v == "Pass"]
        fail_list   = [k for k, v in results.items() if v.startswith("Fail")]
        manual_list = [k for k, v in results.items() if "Manual" in str(v)]
        print(f"\n{'='*60}")
        print(f"  {self._cfg.display_name}")
        print(f"{'='*60}")
        print(f"  Health Score : {score}%")
        print(f"  Total Checks : {self.total}")
        print(f"  Passed       : {len(pass_list)}")
        print(f"  Failed       : {len(fail_list)}")
        print(f"  Manual Check : {len(manual_list)}")
        print(f"{'='*60}\n")
        if fail_list:
            print("[ FAILED ]")
            for k in fail_list:
                print(f"  ✗ {k}")
                print(f"    → {results[k]}")
            print()
        if manual_list:
            print("[ MANUAL CHECK REQUIRED ]")
            for k in manual_list:
                print(f"  ? {k}")
            print()