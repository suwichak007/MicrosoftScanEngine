import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import winreg


class SecurityScanner:
    def __init__(self, data_path=None):
        self.results = {}
        self.passed = 0
        self.total = 0
        self.debug = []
        self.section_stats = {}

        if data_path:
            self.target_file = os.path.join(
                data_path, "MS Security Baseline Windows 11 v25H2.xlsx"
            )
            self.debug_log = os.path.join(data_path, "scanner_debug.log")
        else:
            self.target_file = r"D:\MiniProject\backend\data\MS Security Baseline Windows 11 v25H2.xlsx"
            self.debug_log = r"D:\MiniProject\backend\data\scanner_debug.log"

        temp_dir = Path(tempfile.gettempdir())
        self.secedit_file = str(temp_dir / "secedit_export.inf")
        self.audit_file = str(temp_dir / "auditpol_export.txt")

        self.SECEDIT = r"C:\Windows\System32\secedit.exe"
        self.AUDITPOL = r"C:\Windows\System32\auditpol.exe"
        self.POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

        self.sid_map = {
            "*S-1-1-0": "Everyone",
            "*S-1-5-32-544": "Administrators",
            "*S-1-5-32-545": "Users",
            "*S-1-5-32-546": "Guests",
            "*S-1-5-32-551": "Backup Operators",
            "*S-1-5-32-555": "Remote Desktop Users",
            "*S-1-5-19": "Local Service",
            "*S-1-5-20": "Network Service",
            "*S-1-5-6": "Service",
            "*S-1-5-90-0": "Window Manager",
            "*S-1-5-113": "NT AUTHORITY\\Local Account",
            "*S-1-5-114": "NT AUTHORITY\\Local Account and member of Administrators group",
        }

        self.user_rights_map = {
            "Access Credential Manager as a trusted caller": "SeTrustedCredManAccessPrivilege",
            "Access this computer from the network": "SeNetworkLogonRight",
            "Act as part of the operating system": "SeTcbPrivilege",
            "Allow log on locally": "SeInteractiveLogonRight",
            "Back up files and directories": "SeBackupPrivilege",
            "Bypass traverse checking": "SeChangeNotifyPrivilege",
            "Change the system time": "SeSystemtimePrivilege",
            "Create a pagefile": "SeCreatePagefilePrivilege",
            "Create a token object": "SeCreateTokenPrivilege",
            "Create global objects": "SeCreateGlobalPrivilege",
            "Create permanent shared objects": "SeCreatePermanentPrivilege",
            "Create symbolic links": "SeCreateSymbolicLinkPrivilege",
            "Debug programs": "SeDebugPrivilege",
            "Deny access to this computer from the network": "SeDenyNetworkLogonRight",
            "Deny log on as a batch job": "SeDenyBatchLogonRight",
            "Deny log on as a service": "SeDenyServiceLogonRight",
            "Deny log on locally": "SeDenyInteractiveLogonRight",
            "Deny log on through Remote Desktop Services": "SeDenyRemoteInteractiveLogonRight",
            "Enable computer and user accounts to be trusted for delegation": "SeEnableDelegationPrivilege",
            "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
            "Generate security audits": "SeAuditPrivilege",
            "Impersonate a client after authentication": "SeImpersonatePrivilege",
            "Increase scheduling priority": "SeIncreaseBasePriorityPrivilege",
            "Load and unload device drivers": "SeLoadDriverPrivilege",
            "Lock pages in memory": "SeLockMemoryPrivilege",
            "Log on as a batch job": "SeBatchLogonRight",
            "Log on as a service": "SeServiceLogonRight",
            "Manage auditing and security log": "SeSecurityPrivilege",
            "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
            "Modify an object label": "SeRelabelPrivilege",
            "Perform volume maintenance tasks": "SeManageVolumePrivilege",
            "Profile single process": "SeProfileSingleProcessPrivilege",
            "Profile system performance": "SeSystemProfilePrivilege",
            "Replace a process level token": "SeAssignPrimaryTokenPrivilege",
            "Restore files and directories": "SeRestorePrivilege",
            "Shut down the system": "SeShutdownPrivilege",
            "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
        }

        self.special_value_map = {
            "send ntlmv2 response only. refuse lm & ntlm": "5",
            "negotiate signing": "1",
            # Baseline text expects both bits; raw registry commonly appears as 537395200 or 536870912
            "require ntlmv2 session security and require 128-bit encryption": "537395200",
            "lock workstation": "1",
            # Correct Windows UAC registry values
            "prompt for consent on the secure desktop": "5",
            "prompt for credentials on secure desktop": "1",
            "automatically deny elevation requests": "3",
            "admin approval mode with enhanced privilege protection": "2",
            "no one (blank)": "",
            "block": "block",
        }

        self.firewall_profile_map = {
            "Domain Profile": "domain",
            "Private Profile": "private",
            "Public Profile": "public",
        }
        self.firewall_setting_map = {
            "Firewall State": ("state", None),
            "Inbound Connections": ("firewallpolicy", "inbound"),
            "Outbound Connections": ("firewallpolicy", "outbound"),
            "Display a notification": ("settings", "inboundusernotification"),
            "Apply local firewall rules": ("settings", "localfirewallrules"),
            "Apply local connection security rules": ("settings", "localconsecrules"),
            "Size limit": ("logging", "maxfilesize"),
            "Log dropped packets": ("logging", "droppedpackets"),
            "Log successful connections": ("logging", "allowedconnections"),
        }

        self._security_map = {}
        self._audit_map = {}
        self._netsh_cache = {}
        self._mp_pref = None

    # --------------------------
    # Debug / summary helpers
    # --------------------------
    def _write_debug_log(self):
        try:
            os.makedirs(os.path.dirname(self.debug_log), exist_ok=True)
            with open(self.debug_log, "w", encoding="utf-8", errors="replace") as f:
                for line in self.debug:
                    f.write(str(line) + "\n")

                f.write("\n" + "=" * 70 + "\n")
                f.write("SECTION SUMMARY\n")
                f.write("=" * 70 + "\n")

                grand_total = grand_pass = grand_fail = grand_manual = grand_other = 0

                for section in sorted(self.section_stats.keys()):
                    stats = self.section_stats[section]
                    grand_total += stats["Total"]
                    grand_pass += stats["Pass"]
                    grand_fail += stats["Fail"]
                    grand_manual += stats["Manual"]
                    grand_other += stats["Other"]

                    pass_pct = round((stats["Pass"] / stats["Total"]) * 100, 2) if stats["Total"] else 0
                    f.write(
                        f"[{section}] Total={stats['Total']} | Pass={stats['Pass']} | "
                        f"Fail={stats['Fail']} | Manual={stats['Manual']} | Other={stats['Other']} | Pass%={pass_pct}\n"
                    )

                f.write("-" * 70 + "\n")
                grand_pass_pct = round((grand_pass / grand_total) * 100, 2) if grand_total else 0
                f.write(
                    f"[ALL] Total={grand_total} | Pass={grand_pass} | Fail={grand_fail} | "
                    f"Manual={grand_manual} | Other={grand_other} | Pass%={grand_pass_pct}\n"
                )
        except Exception:
            pass

    def _update_section_stats(self, full_key, result):
        m = re.match(r"^\[([^\]]+)\]", str(full_key))
        section = m.group(1) if m else "Unknown"

        if section not in self.section_stats:
            self.section_stats[section] = {
                "Total": 0,
                "Pass": 0,
                "Fail": 0,
                "Manual": 0,
                "Other": 0,
            }

        self.section_stats[section]["Total"] += 1
        text = str(result)
        if text == "Pass":
            self.section_stats[section]["Pass"] += 1
        elif text.startswith("Fail"):
            self.section_stats[section]["Fail"] += 1
        elif "Manual" in text:
            self.section_stats[section]["Manual"] += 1
        else:
            self.section_stats[section]["Other"] += 1

    def _mark_pass(self):
        self.passed += 1
        return "Pass"

    # --------------------------
    # Generic helpers
    # --------------------------
    def normalize_value(self, value):
        val = str(value).strip().lower()
        if val in ["1", "enabled", "on", "yes", "true"]:
            return "1"
        if val in ["0", "disabled", "off", "no", "false"]:
            return "0"
        if val.lstrip("-").isdigit():
            return val
        mapped = self.special_value_map.get(val)
        if mapped is not None:
            return mapped
        return val

    def resolve_sids(self, sid_string):
        if sid_string is None:
            return "None"
        raw = str(sid_string).strip()
        if raw == "":
            return ""
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        resolved = [self.sid_map.get(p, p) for p in parts]
        return "; ".join(resolved)

    def _collect_environment_debug(self):
        try:
            self.debug.append(f"cwd={os.getcwd()}")
        except Exception as e:
            self.debug.append(f"cwd_error={e}")
        try:
            self.debug.append(f"whoami={os.getlogin()}")
        except Exception as e:
            self.debug.append(f"whoami_error={e}")
        try:
            self.debug.append(f"is_admin={ctypes.windll.shell32.IsUserAnAdmin()}")
        except Exception as e:
            self.debug.append(f"is_admin_error={e}")

        self.debug.append(f"python_exe={sys.executable}")
        self.debug.append(f"secedit_path_exists={os.path.exists(self.SECEDIT)}")
        self.debug.append(f"auditpol_path_exists={os.path.exists(self.AUDITPOL)}")
        self.debug.append(f"powershell_path_exists={os.path.exists(self.POWERSHELL)}")

    # --------------------------
    # Export + parse sources
    # --------------------------
    def _export_security_policy(self):
        try:
            if os.path.exists(self.secedit_file):
                os.remove(self.secedit_file)
        except Exception:
            pass

        try:
            proc = subprocess.run(
                [self.SECEDIT, "/export", "/cfg", self.secedit_file],
                capture_output=True,
                text=True,
                shell=False,
            )
            self.debug.append(f"SECEDIT rc={proc.returncode}")
            self.debug.append(f"SECEDIT stdout={proc.stdout[:300]}")
            self.debug.append(f"SECEDIT stderr={proc.stderr[:300]}")
            self.debug.append(f"SECEDIT file={self.secedit_file}")
            self.debug.append(f"SECEDIT file_exists={os.path.exists(self.secedit_file)}")
        except Exception as e:
            self.debug.append(f"SECEDIT exception={e}")
            return ""

        if not os.path.exists(self.secedit_file):
            return ""

        for enc in ("utf-16", "utf-8-sig", "cp1252", "latin-1"):
            try:
                with open(self.secedit_file, "r", encoding=enc, errors="replace") as f:
                    data = f.read()
                self.debug.append(f"SECEDIT read_ok encoding={enc} len={len(data)}")
                self.debug.append(f"SECEDIT head={data[:500]}")
                return data
            except Exception as e:
                self.debug.append(f"SECEDIT read_fail encoding={enc} err={e}")
        return ""

    def _parse_security_data(self, security_data):
        parsed = {}
        for line in security_data.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            parsed[k.strip()] = v.strip()

        self.debug.append(f"SECEDIT parsed_count={len(parsed)}")
        self.debug.append(f"SECEDIT parsed_keys_sample={list(parsed.keys())[:20]}")
        self.debug.append(f"SECEDIT has_MinimumPasswordLength={'MinimumPasswordLength' in parsed}")
        self.debug.append(f"SECEDIT has_PasswordComplexity={'PasswordComplexity' in parsed}")
        self.debug.append(f"SECEDIT has_LockoutBadCount={'LockoutBadCount' in parsed}")
        self.debug.append(f"SECEDIT has_SeNetworkLogonRight={'SeNetworkLogonRight' in parsed}")
        return parsed

    def _export_audit_policy(self):
        try:
            proc = subprocess.run(
                [self.AUDITPOL, "/get", "/category:*"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            self.debug.append(f"AUDIT rc={proc.returncode}")
            self.debug.append(f"AUDIT stdout={proc.stdout[:1000]}")
            self.debug.append(f"AUDIT stderr={proc.stderr[:300]}")
            return proc.stdout if proc.returncode == 0 else ""
        except Exception as e:
            self.debug.append(f"AUDIT exception={e}")
            return ""

    def _parse_audit_data(self, audit_text):
        mapping = {}
        for raw in audit_text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line in ("System audit policy", "Category/Subcategory                      Setting"):
                continue
            if line in (
                "Account Logon",
                "Account Management",
                "Detailed Tracking",
                "DS Access",
                "Logon/Logoff",
                "Object Access",
                "Policy Change",
                "Privilege Use",
                "System",
            ):
                continue

            m = re.match(r"^(.*?)\s{2,}(No Auditing|Success|Failure|Success and Failure)$", line)
            if m:
                subcat = m.group(1).strip()
                setting = m.group(2).strip()
                mapping[subcat] = setting

        self.debug.append(f"AUDIT parsed_count={len(mapping)}")
        self.debug.append(f"AUDIT parsed_keys_sample={list(mapping.keys())[:20]}")
        self.debug.append(f"AUDIT has_Logon={'Logon' in mapping}")
        self.debug.append(f"AUDIT value_Logon={mapping.get('Logon')}")
        return mapping

    def _load_mp_preference(self):
        try:
            cmd = "Get-MpPreference | ConvertTo-Json -Depth 4"
            proc = subprocess.run(
                [self.POWERSHELL, "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            self.debug.append(f"MPPREF rc={proc.returncode}")
            self.debug.append(f"MPPREF stdout={proc.stdout[:600]}")
            self.debug.append(f"MPPREF stderr={proc.stderr[:300]}")
            if proc.returncode != 0 or not proc.stdout.strip():
                return {}
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
            self.debug.append(f"MPPREF keys_sample={list(data.keys())[:20]}")
            return data if isinstance(data, dict) else {}
        except Exception as e:
            self.debug.append(f"MPPREF exception={e}")
            return {}

    def _resolve_target_col(self, sheet_name, columns):
        if sheet_name in ("Computer", "User"):
            for candidate in ("Windows 11 25H2", "Windows 11 24H2", "Policy Value"):
                if candidate in columns:
                    return candidate
            return None
        return "Windows 11" if "Windows 11" in columns else None

    def _norm_yn(self, val):
        v = str(val).strip().lower()
        if v in ("yes", "enable", "enabled", "on", "1", "true"):
            return "yes"
        if v in ("no", "disable", "disabled", "off", "0", "false", "n/a"):
            return "no"
        return v

    # --------------------------
    # Registry checks
    # --------------------------
    def check_registry(self, reg_info, expected):
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
            res = self._check_single_registry(entry, expected)
            if res == "Pass":
                any_pass = True
            elif str(res).startswith("Fail"):
                final_fails.append(res)
            else:
                any_manual = True

        if any_pass and not final_fails and not any_manual:
            return self._mark_pass()
        if final_fails:
            return " | ".join(final_fails)
        if any_manual:
            return "Manual Check Required"
        return "Fail (Not Configured)"

    def _check_single_registry(self, reg_entry, expected):
        try:
            if "!" in reg_entry:
                path_part, key_name = reg_entry.split("!", 1)
            else:
                path_part, key_name = reg_entry.rsplit("\\", 1)

            path_part = path_part.strip()
            key_name = key_name.strip()
            upper = path_part.upper()

            if upper.startswith("HKEY_LOCAL_MACHINE\\") or upper.startswith("HKLM\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                sub_path = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("HKEY_CURRENT_USER\\") or upper.startswith("HKCU\\"):
                hive = winreg.HKEY_CURRENT_USER
                sub_path = re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("MACHINE\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                sub_path = re.sub(r"^MACHINE\\", "", path_part, flags=re.IGNORECASE)
            elif upper.startswith("SOFTWARE\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                sub_path = path_part
            else:
                return "Manual Check Required"

            with winreg.OpenKey(hive, sub_path) as hkey:
                actual_val, _ = winreg.QueryValueEx(hkey, key_name)

            if "RestrictRemoteSAM" in key_name:
                if str(actual_val).strip() == str(expected).strip():
                    return "Pass"
                return f"Fail (Target: {expected}, Actual: {actual_val})"

            # NTLM min sec special handling
            if key_name in ("NTLMMinClientSec", "NTLMMinServerSec"):
                try:
                    actual_int = int(actual_val)
                    expected_norm = self.normalize_value(expected)
                    # Baseline text maps to 537395200, but some systems may only have 536870912.
                    # Treat only full baseline bitmask as pass.
                    if expected_norm == "537395200" and actual_int == 537395200:
                        return "Pass"
                    return f"Fail (Target: {expected}, Actual: {actual_val})"
                except Exception:
                    return f"Fail (Target: {expected}, Actual: {actual_val})"

            actual_norm = self.normalize_value(actual_val)
            expected_norm = self.normalize_value(expected)

            if actual_norm == expected_norm:
                return "Pass"
            return f"Fail (Target: {expected}, Actual: {actual_val})"

        except FileNotFoundError:
            return f"Fail (Not Configured, Target: {expected})"
        except OSError as e:
            return f"Manual Check Required ({e})"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # --------------------------
    # Security template checks
    # --------------------------
    def check_security_template(self, policy_path, policy_name, reg_info, expected):
        reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""

        if policy_path == "Security Options":
            if reg_str and reg_str.lower() not in ("not a registry key", "nan", ""):
                return self._check_single_registry(reg_str, expected)
            if policy_name == "Network access: Allow anonymous SID/Name translation":
                return self._check_lsa_anonymous(expected)

        if policy_path in ("Password Policy", "Account Lockout"):
            return self.check_secedit_policy(policy_name, expected)

        if policy_path == "User Rights Assignments":
            return self.check_user_rights(policy_name, expected)

        return "Manual Check Required"

    def _check_lsa_anonymous(self, expected):
        actual = self._security_map.get("LSAAnonymousNameLookup")
        if actual is None:
            return f"Fail (Not Configured, Target: {expected})"
        if self.normalize_value(actual) == self.normalize_value(expected):
            return self._mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    def check_secedit_policy(self, policy_name, expected):
        secedit_key_map = {
            "Minimum password length": "MinimumPasswordLength",
            "Maximum password age": "MaximumPasswordAge",
            "Minimum password age": "MinimumPasswordAge",
            "Enforce password history": "PasswordHistorySize",
            "Password must meet complexity requirements": "PasswordComplexity",
            "Store passwords using reversible encryption": "ClearTextPassword",
            "Account lockout duration": "LockoutDuration",
            "Account lockout threshold": "LockoutBadCount",
            "Reset account lockout counter after": "ResetLockoutCount",
            "Allow Administrator account lockout": "AllowAdministratorLockout",
        }

        key = secedit_key_map.get(policy_name)
        if not key:
            return "Manual Check Required"

        raw_actual = self._security_map.get(key)
        self.debug.append(f"SECEDIT lookup {policy_name} -> {key} -> {raw_actual}")

        if raw_actual is None:
            return f"Fail (Not Configured, Target: {expected})"
        if self.normalize_value(raw_actual) == self.normalize_value(expected):
            return self._mark_pass()
        return f"Fail (Target: {expected}, Actual: {raw_actual})"

    def check_user_rights(self, policy_name, expected):
        key = self.user_rights_map.get(policy_name)
        if not key:
            return "Manual Check Required"

        expected_str = str(expected).strip()
        raw_actual = self._security_map.get(key)
        self.debug.append(f"RIGHTS lookup {policy_name} -> {key} -> {raw_actual}")

        if expected_str.lower() == "no one (blank)":
            if raw_actual is None:
                return self._mark_pass()
            if str(raw_actual).strip() == "":
                return self._mark_pass()
            return f"Fail (Target: empty, Actual: {self.resolve_sids(raw_actual)})"

        if raw_actual is None:
            return "Fail (Not Configured)"

        actual_resolved = self.resolve_sids(raw_actual).lower()
        expected_parts = [t.strip().lower() for t in re.split(r"[;,]", expected_str) if t.strip()]

        if all(any(ep in part for part in actual_resolved.split("; ")) for ep in expected_parts):
            if "everyone" not in actual_resolved or "everyone" in expected_str.lower():
                return self._mark_pass()

        return f"Fail (Target: {expected}, Actual: {self.resolve_sids(raw_actual)})"

    # --------------------------
    # Audit checks
    # --------------------------
    def check_advanced_audit(self, policy_name, expected):
        subcategory_map = {
            "Audit Credential Validation": "Credential Validation",
            "Audit Kerberos Authentication Service": "Kerberos Authentication Service",
            "Audit Kerberos Service Ticket Operations": "Kerberos Service Ticket Operations",
            "Audit Security Group Management": "Security Group Management",
            "Audit User Account Management": "User Account Management",
            "Audit Computer Account Management": "Computer Account Management",
            "Audit Distribution Group Management": "Distribution Group Management",
            "Audit Other Account Management Events": "Other Account Management Events",
            "Audit PNP Activity": "Plug and Play Events",
            "Audit Process Creation": "Process Creation",
            "Audit Process Termination": "Process Termination",
            "Audit Account Lockout": "Account Lockout",
            "Audit Group Membership": "Group Membership",
            "Audit Logon": "Logon",
            "Audit Logoff": "Logoff",
            "Audit Other Logon/Logoff Events": "Other Logon/Logoff Events",
            "Audit Special Logon": "Special Logon",
            "Audit Network Policy Server": "Network Policy Server",
            "Audit Detailed File Share": "Detailed File Share",
            "Audit File Share": "File Share",
            "Audit File System": "File System",
            "Audit Other Object Access Events": "Other Object Access Events",
            "Audit Registry": "Registry",
            "Audit Removable Storage": "Removable Storage",
            "Audit SAM": "SAM",
            "Audit Audit Policy Change": "Audit Policy Change",
            "Audit Authentication Policy Change": "Authentication Policy Change",
            "Audit MPSSVC Rule-Level Policy Change": "MPSSVC Rule-Level Policy Change",
            "Audit Other Policy Change Events": "Other Policy Change Events",
            "Audit Authorization Policy Change": "Authorization Policy Change",
            "Audit Sensitive Privilege Use": "Sensitive Privilege Use",
            "Audit Non Sensitive Privilege Use": "Non Sensitive Privilege Use",
            "Audit Other System Events": "Other System Events",
            "Audit Security State Change": "Security State Change",
            "Audit Security System Extension": "Security System Extension",
            "Audit System Integrity": "System Integrity",
        }

        subcategory = subcategory_map.get(policy_name, policy_name.replace("Audit ", "").strip())
        actual = self._audit_map.get(subcategory)
        self.debug.append(f"AUDIT lookup {policy_name} -> {subcategory} -> {actual}")

        if actual is None:
            return f"Fail (Not Configured, Target: {expected})"

        target = str(expected).strip().replace(",", " and")
        if actual.lower() == target.lower():
            return self._mark_pass()
        return f"Fail (Target: {target}, Actual: {actual})"

    # --------------------------
    # Defender / Computer policy checks
    # --------------------------
    def check_defender_policy(self, policy_name, expected):
        data = self._mp_pref or {}
        if not data:
            return "Manual Check Required"

        def _bool_false_is_enabled(key):
            actual = data.get(key)
            self.debug.append(f"MPPREF lookup {policy_name} -> {key} -> {actual}")
            if actual is None:
                return "Manual Check Required"
            if actual is False:
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual})"

        def _maps_check():
            actual = data.get("MAPSReporting")
            self.debug.append(f"MPPREF lookup {policy_name} -> MAPSReporting -> {actual}")
            if actual is None:
                return "Manual Check Required"
            if int(actual) >= 1:
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual})"

        def _sample_check():
            actual = data.get("SubmitSamplesConsent")
            self.debug.append(f"MPPREF lookup {policy_name} -> SubmitSamplesConsent -> {actual}")
            if actual is None:
                return "Manual Check Required"
            # Common acceptable secure settings are 1 or 3; 2 = never send is generally below baseline.
            if int(actual) in (1, 3):
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual})"

        def _network_protection_check():
            actual = data.get("EnableNetworkProtection")
            self.debug.append(f"MPPREF lookup {policy_name} -> EnableNetworkProtection -> {actual}")
            if actual is None:
                return "Manual Check Required"
            if str(actual) == "1":
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual})"

        def _pua_check():
            actual = data.get("PUAProtection")
            self.debug.append(f"MPPREF lookup {policy_name} -> PUAProtection -> {actual}")
            if actual is None:
                return "Manual Check Required"
            if str(actual) == "1":
                return self._mark_pass()
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

    # --------------------------
    # Firewall / service checks
    # --------------------------
    def check_firewall(self, policy_path, policy_name, expected):
        profile_name = policy_path.split("\\")[0].strip()
        profile_key = self.firewall_profile_map.get(profile_name)
        if not profile_key:
            return f"Manual Check Required (Unknown profile: {profile_name})"

        setting_info = self.firewall_setting_map.get(policy_name)
        if not setting_info:
            return f"Manual Check Required (Unknown setting: {policy_name})"

        setting_type, param = setting_info
        try:
            if profile_key not in self._netsh_cache:
                raw = subprocess.check_output(
                    f"netsh advfirewall show {profile_key}profile",
                    shell=True,
                    stderr=subprocess.STDOUT,
                ).decode(errors="replace")
                self._netsh_cache[profile_key] = raw.lower()

            output_lower = self._netsh_cache[profile_key]
            expected_str = str(expected).strip().lower().rstrip()

            if setting_type == "state":
                match = re.search(r"state\s+(on|off)", output_lower)
                actual = match.group(1) if match else "unknown"
                if actual == expected_str:
                    return self._mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual.upper()})"

            if setting_type == "firewallpolicy":
                match = re.search(r"firewall\s*policy\s+(\w+),(\w+)", output_lower)
                if match:
                    inbound_val = "block" if "block" in match.group(1) else "allow"
                    outbound_val = "allow" if "allow" in match.group(2) else "block"
                    actual = inbound_val if param == "inbound" else outbound_val
                    if actual == expected_str:
                        return self._mark_pass()
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

                try:
                    log_key = f"{profile_key}_log"
                    if log_key not in self._netsh_cache:
                        raw_log = subprocess.check_output(
                            f"netsh advfirewall show {profile_key}profile logging",
                            shell=True,
                            stderr=subprocess.STDOUT,
                        ).decode(errors="replace")
                        self._netsh_cache[log_key] = raw_log.lower()

                    log_output = self._netsh_cache[log_key]
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
                                    return self._mark_pass()
                                return f"Fail (Target: {expected}, Actual: {actual})"
                            if self._norm_yn(actual) == self._norm_yn(expected_str):
                                return self._mark_pass()
                            return f"Fail (Target: {expected}, Actual: {actual})"
                except Exception:
                    pass

                return f"Fail (Not Configured, Target: {expected})"

        except Exception as e:
            return f"Manual Check Required ({e})"

        return f"Manual Check Required (Target: {expected})"

    def check_service(self, row_type, service_name, expected):
        if str(row_type).strip() == "Scheduled Task":
            return self.check_scheduled_task(service_name, expected)
        try:
            cmd = f"(Get-Service -Name '{service_name}' -ErrorAction Stop).StartType"
            result = subprocess.check_output(
                [self.POWERSHELL, "-NoProfile", "-Command", cmd], stderr=subprocess.STDOUT
            ).decode(errors="replace").strip()

            if result.lower() == str(expected).lower():
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {result})"
        except subprocess.CalledProcessError:
            return "Service Not Found"
        except Exception as e:
            return f"Manual Check Required ({e})"

    def check_scheduled_task(self, task_name, expected):
        try:
            cmd = f"(Get-ScheduledTask -TaskName '{task_name}' -ErrorAction Stop).State"
            result = subprocess.check_output(
                [self.POWERSHELL, "-NoProfile", "-Command", cmd], stderr=subprocess.STDOUT
            ).decode(errors="replace").strip()

            if result.lower() == str(expected).lower():
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {result})"
        except subprocess.CalledProcessError:
            return "Task Not Found"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # --------------------------
    # Main scan
    # --------------------------
    def run_baseline_scan(self):
        if not os.path.exists(self.target_file):
            return 0, {"Error": f"Baseline file not found: {self.target_file}"}

        self._collect_environment_debug()

        security_text = self._export_security_policy()
        self._security_map = self._parse_security_data(security_text) if security_text else {}

        audit_text = self._export_audit_policy()
        self._audit_map = self._parse_audit_data(audit_text) if audit_text else {}

        self._mp_pref = self._load_mp_preference()

        all_sheets = pd.read_excel(self.target_file, sheet_name=None)
        skip_sheets = {"Information", "Revision History"}

        for sheet_name, df in all_sheets.items():
            if sheet_name in skip_sheets:
                continue

            target_col = self._resolve_target_col(sheet_name, df.columns.tolist())
            if target_col is None or target_col not in df.columns:
                continue

            for _, row in df.iterrows():
                expected = row.get(target_col)
                if pd.isna(expected) or str(expected).strip() == "":
                    continue

                policy_name = str(row.get("Policy Setting Name") or row.get("Name") or "").strip()
                if not policy_name or policy_name == "nan":
                    continue

                policy_path = str(row.get("Policy Path") or "").strip()
                reg_info = row.get("Registry Information")
                self.total += 1

                if sheet_name == "Firewall":
                    profile_name = policy_path.split("\\")[0].strip()
                    full_key = f"[Firewall] {profile_name} - {policy_name}"
                else:
                    full_key = f"[{sheet_name}] {policy_name}"

                if sheet_name == "Firewall":
                    self.results[full_key] = self.check_firewall(policy_path, policy_name, expected)

                elif sheet_name == "Advanced Audit":
                    self.results[full_key] = self.check_advanced_audit(policy_name, expected)

                elif sheet_name == "Security Template":
                    self.results[full_key] = self.check_security_template(
                        policy_path, policy_name, reg_info, expected
                    )

                elif sheet_name == "Services":
                    row_type = str(row.get("Type") or "Services").strip()
                    service_name = str(row.get("Name") or policy_name).strip()
                    self.results[full_key] = self.check_service(row_type, service_name, expected)

                elif sheet_name == "Computer":
                    defender_check = self.check_defender_policy(policy_name, expected)
                    if defender_check != "Manual Check Required":
                        self.results[full_key] = defender_check
                    else:
                        reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                        if reg_str and reg_str.lower() not in ("nan", ""):
                            self.results[full_key] = self.check_registry(reg_str, expected)
                        else:
                            self.results[full_key] = "Manual Check Required"

                elif sheet_name == "User":
                    reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                    if reg_str and reg_str.lower() not in ("nan", ""):
                        self.results[full_key] = self.check_registry(reg_str, expected)
                    else:
                        self.results[full_key] = "Manual Check Required"

                else:
                    self.results[full_key] = "Manual Check Required"

                self._update_section_stats(full_key, self.results[full_key])
        pass_count = sum(1 for v in self.results.values() if v == "Pass")
        score = int((pass_count / self.total) * 100) if self.total > 0 else 0
        self._write_debug_log()
        return score, self.results

    def print_summary(self, score, results):
        pass_list = [k for k, v in results.items() if v == "Pass"]
        fail_list = [k for k, v in results.items() if str(v).startswith("Fail")]
        manual_list = [k for k, v in results.items() if "Manual" in str(v)]

        print(f"\n{'='*60}")
        print("  MS Security Baseline - Windows 11 v25H2 Scan Report")
        print(f"{'='*60}")
        print(f"  Health Score : {score}%")
        print(f"  Total Checks : {self.total}")
        print(f"  Passed       : {len(pass_list)}")
        print(f"  Failed       : {len(fail_list)}")
        print(f"  Manual Check : {len(manual_list)}")
        print(f"  Debug Log    : {self.debug_log}")
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



SecurityBaselineScanner = SecurityScanner

if __name__ == "__main__":
    scanner = SecurityScanner()
    score, results = scanner.run_baseline_scan()
    scanner.print_summary(score, results)
