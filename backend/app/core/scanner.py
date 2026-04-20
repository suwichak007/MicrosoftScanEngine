import winreg
import pandas as pd
import os
import subprocess
import re


class SecurityScanner:
    def __init__(self, data_path=None):
        self.results = {}
        self.passed = 0
        self.total = 0

        # รองรับทั้งการส่ง data_path จากภายนอก และค่า default
        if data_path:
            self.target_file = os.path.join(
                data_path, "MS Security Baseline Windows 11 v25H2.xlsx"
            )
        else:
            self.target_file = r"D:\MiniProject\backend\data\MS Security Baseline Windows 11 v25H2.xlsx"

        self.secedit_file = "secedit_export.inf"

        # SID Mapping สำหรับเปรียบเทียบสิทธิ์ User
        self.sid_map = {
            "*S-1-1-0":      "Everyone",
            "*S-1-5-32-544": "Administrators",
            "*S-1-5-32-545": "Users",
            "*S-1-5-32-546": "Guests",
            "*S-1-5-32-551": "Backup Operators",
            "*S-1-5-32-555": "Remote Desktop Users",
            "*S-1-5-19":     "Local Service",
            "*S-1-5-20":     "Network Service",
            "*S-1-5-6":      "Service",
            "*S-1-5-90-0":   "Window Manager",
            "*S-1-5-113":    "NT AUTHORITY\\Local Account",
            "*S-1-5-114":    "NT AUTHORITY\\Local Account and member of Administrators group",
        }

        # Map ชื่อ Policy ใน User Rights Assignments → secedit key
        self.user_rights_map = {
            "Access Credential Manager as a trusted caller":                  "SeTrustedCredManAccessPrivilege",
            "Access this computer from the network":                           "SeNetworkLogonRight",
            "Act as part of the operating system":                             "SeTcbPrivilege",
            "Allow log on locally":                                            "SeInteractiveLogonRight",
            "Back up files and directories":                                   "SeBackupPrivilege",
            "Bypass traverse checking":                                        "SeChangeNotifyPrivilege",
            "Change the system time":                                          "SeSystemtimePrivilege",
            "Create a pagefile":                                               "SeCreatePagefilePrivilege",
            "Create a token object":                                           "SeCreateTokenPrivilege",
            "Create global objects":                                           "SeCreateGlobalPrivilege",
            "Create permanent shared objects":                                 "SeCreatePermanentPrivilege",
            "Create symbolic links":                                           "SeCreateSymbolicLinkPrivilege",
            "Debug programs":                                                  "SeDebugPrivilege",
            "Deny access to this computer from the network":                   "SeDenyNetworkLogonRight",
            "Deny log on as a batch job":                                      "SeDenyBatchLogonRight",
            "Deny log on as a service":                                        "SeDenyServiceLogonRight",
            "Deny log on locally":                                             "SeDenyInteractiveLogonRight",
            "Deny log on through Remote Desktop Services":                     "SeDenyRemoteInteractiveLogonRight",
            "Enable computer and user accounts to be trusted for delegation":  "SeEnableDelegationPrivilege",
            "Force shutdown from a remote system":                             "SeRemoteShutdownPrivilege",
            "Generate security audits":                                        "SeAuditPrivilege",
            "Impersonate a client after authentication":                       "SeImpersonatePrivilege",
            "Increase scheduling priority":                                    "SeIncreaseBasePriorityPrivilege",
            "Load and unload device drivers":                                  "SeLoadDriverPrivilege",
            "Lock pages in memory":                                            "SeLockMemoryPrivilege",
            "Log on as a batch job":                                           "SeBatchLogonRight",
            "Log on as a service":                                             "SeServiceLogonRight",
            "Manage auditing and security log":                                "SeSecurityPrivilege",
            "Modify firmware environment values":                              "SeSystemEnvironmentPrivilege",
            "Modify an object label":                                          "SeRelabelPrivilege",
            "Perform volume maintenance tasks":                                "SeManageVolumePrivilege",
            "Profile single process":                                          "SeProfileSingleProcessPrivilege",
            "Profile system performance":                                      "SeSystemProfilePrivilege",
            "Replace a process level token":                                   "SeAssignPrimaryTokenPrivilege",
            "Restore files and directories":                                   "SeRestorePrivilege",
            "Shut down the system":                                            "SeShutdownPrivilege",
            "Take ownership of files or other objects":                        "SeTakeOwnershipPrivilege",
        }

        # Map ค่าข้อความพิเศษของ Security Options → registry value จริง
        self.special_value_map = {
            "send ntlmv2 response only. refuse lm & ntlm":                    "5",
            "negotiate signing":                                               "1",
            "require ntlmv2 session security and require 128-bit encryption":  "537395200",
            "lock workstation":                                                "1",
            "prompt for consent on the secure desktop":                        "2",
            "prompt for credentials on secure desktop":                        "4",
            "automatically deny elevation requests":                           "0",
            "admin approval mode with enhanced privilege protection":          "2",
            "no one (blank)":                                                  "",
        }

        # Map ชื่อ Firewall policy → netsh parameter
        self.firewall_profile_map = {
            "Domain Profile":  "domain",
            "Private Profile": "private",
            "Public Profile":  "public",
        }
        self.firewall_setting_map = {
            "Firewall State":                        ("state",          None),
            "Inbound Connections":                   ("firewallpolicy", "inbound"),
            "Outbound Connections":                  ("firewallpolicy", "outbound"),
            "Display a notification":                ("settings",       "inboundusernotification"),
            "Apply local firewall rules":            ("settings",       "localfirewallrules"),
            "Apply local connection security rules": ("settings",       "localconsecrules"),
            "Size limit":                            ("logging",        "maxfilesize"),
            "Log dropped packets":                   ("logging",        "droppedpackets"),
            "Log successful connections":            ("logging",        "allowedconnections"),
        }

    # ------------------------------------------------------------------
    # ส่วน secedit
    # ------------------------------------------------------------------
    def _export_security_policy(self):
        """ส่งออกนโยบายความปลอดภัยจาก Windows Security Database"""
        try:
            subprocess.run(
                ["secedit", "/export", "/cfg", self.secedit_file],
                capture_output=True, check=True,
            )
            for encoding in ["utf-16", "utf-8", "cp1252"]:
                try:
                    with open(self.secedit_file, "r", encoding=encoding) as f:
                        return f.read()
                except Exception:
                    continue
            return ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # ฟังก์ชันช่วย
    # ------------------------------------------------------------------
    def resolve_sids(self, sid_string):
        """แปลง SID string ให้เป็นชื่อที่อ่านได้"""
        if not sid_string:
            return "None"
        parts = [p.strip() for p in sid_string.split(",")]
        resolved = [self.sid_map.get(p, p) for p in parts]
        return "; ".join(resolved)

    def normalize_value(self, value):
        """ทำให้ค่าเป็นรูปแบบมาตรฐานสำหรับเปรียบเทียบ"""
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

    def _mark_pass(self):
        self.passed += 1
        return "Pass"

    # ------------------------------------------------------------------
    # ตรวจ Registry (รองรับทั้ง HKLM และ HKCU)
    # ------------------------------------------------------------------
    def check_registry(self, reg_info, expected):
        """ตรวจสอบค่าผ่าน Windows Registry"""
        reg_str = str(reg_info).strip()
        entries = [e.strip() for e in reg_str.split(";") if "!" in e]
        if not entries:
            return "Manual Check Required"

        result = "Manual Check Required"
        for entry in entries:
            result = self._check_single_registry(entry, expected)
            if result == "Pass":
                return result
        return result

    def _check_single_registry(self, reg_entry, expected):
        try:
            if "!" in reg_entry:
                path_part, key_name = reg_entry.split("!", 1)
            else:
                path_part, key_name = reg_entry.rsplit("\\", 1)

            path_part = path_part.strip()
            key_name  = key_name.strip()

            upper = path_part.upper()
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
            return f"Fail (Not Configured, Target: {expected})"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # ------------------------------------------------------------------
    # ตรวจ Security Template
    # ------------------------------------------------------------------
    def check_security_template(self, policy_path, policy_name, reg_info, expected, security_data):
        """ตรวจสอบนโยบายใน Security Template sheet"""
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
        return "Fail (Not Configured)"

    def check_secedit_policy(self, policy_name, expected, security_data):
        """ตรวจ Password Policy / Account Lockout ผ่าน secedit"""
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
        return "Fail (Not Configured)"

    def check_user_rights(self, policy_name, expected, security_data):
        """ตรวจ User Rights Assignments ผ่าน secedit"""
        key = self.user_rights_map.get(policy_name)
        if not key:
            return "Manual Check Required"

        match        = re.search(fr"^{key}\s*=\s*(.*)", security_data, re.MULTILINE | re.IGNORECASE)
        expected_str = str(expected).strip()

        if expected_str.lower() in ("no one (blank)",):
            if match:
                raw = match.group(1).strip()
                if raw == "":
                    return self._mark_pass()
                return f"Fail (Target: empty, Actual: {self.resolve_sids(raw)})"
            return self._mark_pass()

        if not match:
            return "Fail (Not Configured)"

        raw_actual       = match.group(1).strip()
        actual_resolved  = self.resolve_sids(raw_actual).lower()
        expected_parts   = [t.strip().lower() for t in re.split(r"[;,]", expected_str)]

        if all(any(ep in part for part in actual_resolved.split("; ")) for ep in expected_parts):
            if "everyone" not in actual_resolved or "everyone" in expected_str.lower():
                return self._mark_pass()

        return f"Fail (Target: {expected}, Actual: {self.resolve_sids(raw_actual)})"

    # ------------------------------------------------------------------
    # ตรวจ Advanced Audit
    # ------------------------------------------------------------------
    def check_advanced_audit(self, policy_name, expected):
        """ตรวจสอบ Advanced Audit Policy ผ่าน auditpol"""
        subcategory_map = {
            "Audit Credential Validation":               "Credential Validation",
            "Audit Kerberos Authentication Service":     "Kerberos Authentication Service",
            "Audit Kerberos Service Ticket Operations":  "Kerberos Service Ticket Operations",
            "Audit Security Group Management":           "Security Group Management",
            "Audit User Account Management":             "User Account Management",
            "Audit Computer Account Management":         "Computer Account Management",
            "Audit Distribution Group Management":       "Distribution Group Management",
            "Audit Other Account Management Events":     "Other Account Management Events",
            "Audit PNP Activity":                        "Plug and Play Events",
            "Audit Process Creation":                    "Process Creation",
            "Audit Process Termination":                 "Process Termination",
            "Audit Account Lockout":                     "Account Lockout",
            "Audit Group Membership":                    "Group Membership",
            "Audit Logon":                               "Logon",
            "Audit Logoff":                              "Logoff",
            "Audit Other Logon/Logoff Events":           "Other Logon/Logoff Events",
            "Audit Special Logon":                       "Special Logon",
            "Audit Network Policy Server":               "Network Policy Server",
            "Audit Detailed File Share":                 "Detailed File Share",
            "Audit File Share":                          "File Share",
            "Audit File System":                         "File System",
            "Audit Other Object Access Events":          "Other Object Access Events",
            "Audit Registry":                            "Registry",
            "Audit Removable Storage":                   "Removable Storage",
            "Audit SAM":                                 "SAM",
            "Audit Audit Policy Change":                 "Audit Policy Change",
            "Audit Authentication Policy Change":        "Authentication Policy Change",
            "Audit MPSSVC Rule-Level Policy Change":     "MPSSVC Rule-Level Policy Change",
            "Audit Other Policy Change Events":          "Other Policy Change Events",
            "Audit Authorization Policy Change":         "Authorization Policy Change",
            "Audit Sensitive Privilege Use":             "Sensitive Privilege Use",
            "Audit Non Sensitive Privilege Use":         "Non Sensitive Privilege Use",
            "Audit Other System Events":                 "Other System Events",
            "Audit Security State Change":               "Security State Change",
            "Audit Security System Extension":           "Security System Extension",
            "Audit System Integrity":                    "System Integrity",
        }
        subcategory = subcategory_map.get(policy_name, policy_name.replace("Audit ", "").strip())

        try:
            output = subprocess.check_output(
                f'auditpol /get /subcategory:"{subcategory}"',
                shell=True, stderr=subprocess.STDOUT,
            ).decode(errors="replace")

            actual_parts = []
            if "Success" in output:
                actual_parts.append("Success")
            if "Failure" in output:
                actual_parts.append("Failure")

            actual = " and ".join(actual_parts) if actual_parts else "No Auditing"
            target = str(expected).strip().replace(",", " and")

            if actual.lower() == target.lower():
                return self._mark_pass()
            return f"Fail (Target: {target}, Actual: {actual})"
        except subprocess.CalledProcessError:
            return f"Manual Check Required (subcategory not found: {subcategory})"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # ------------------------------------------------------------------
    # ตรวจ Firewall
    # ------------------------------------------------------------------
    def check_firewall(self, policy_path, policy_name, expected):
        """ตรวจสอบ Windows Firewall ผ่าน netsh advfirewall"""
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
                raw = subprocess.check_output(
                    f"netsh advfirewall show {profile_key}profile",
                    shell=True, stderr=subprocess.STDOUT,
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

            elif setting_type == "firewallpolicy":
                match = re.search(r"firewall\s*policy\s+(\w+),(\w+)", output_lower)
                if match:
                    inbound_val  = "block" if "block" in match.group(1) else "allow"
                    outbound_val = "allow" if "allow" in match.group(2) else "block"
                    actual = inbound_val if param == "inbound" else outbound_val
                    if actual == expected_str:
                        return self._mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            elif setting_type == "settings":
                setting_patterns = {
                    "inboundusernotification": r"inboundusernotification\s+(\S+)",
                    "localfirewallrules":       r"localfirewallrules\s+(\S+)",
                    "localconsecrules":         r"localconsecrules\s+(\S+)",
                }
                pattern = setting_patterns.get(param, fr"{re.escape(param)}\s+(\S+)")
                match = re.search(pattern, output_lower)
                if match:
                    actual = match.group(1).strip().rstrip(".")
                    if self._norm_yn(actual) == self._norm_yn(expected_str):
                        return self._mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            elif setting_type == "logging":
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

                # fallback: logging subcommand
                try:
                    log_key = f"{profile_key}_log"
                    if log_key not in self._netsh_cache:
                        raw_log = subprocess.check_output(
                            f"netsh advfirewall show {profile_key}profile logging",
                            shell=True, stderr=subprocess.STDOUT,
                        ).decode(errors="replace")
                        self._netsh_cache[log_key] = raw_log.lower()
                    log_output = self._netsh_cache[log_key]

                    patterns_log = {
                        "droppedpackets":     r"logdroppedpackets\s+(\S+)",
                        "allowedconnections": r"logallowedconnections\s+(\S+)",
                        "maxfilesize":        r"maxfilesize\s+(\d+)",
                    }
                    if param in patterns_log:
                        m = re.search(patterns_log[param], log_output)
                        if m:
                            actual = m.group(1)
                            if param == "maxfilesize":
                                if actual == str(int(expected)):
                                    return self._mark_pass()
                                return f"Fail (Target: {expected}, Actual: {actual})"
                            else:
                                if self._norm_yn(actual) == self._norm_yn(expected_str):
                                    return self._mark_pass()
                                return f"Fail (Target: {expected}, Actual: {actual})"
                except Exception:
                    pass

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
    # ตรวจ Services / Scheduled Tasks
    # ------------------------------------------------------------------
    def check_service(self, row_type, service_name, expected):
        """ตรวจสอบ Windows Services และ Scheduled Tasks"""
        if str(row_type).strip() == "Scheduled Task":
            return self.check_scheduled_task(service_name, expected)

        try:
            cmd    = f"(Get-Service -Name '{service_name}' -ErrorAction Stop).StartType"
            result = subprocess.check_output(
                ["powershell", "-Command", cmd], stderr=subprocess.STDOUT
            ).decode().strip()

            if result.lower() == str(expected).lower():
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {result})"
        except subprocess.CalledProcessError:
            return "Service Not Found"
        except Exception as e:
            return f"Manual Check Required ({e})"

    def check_scheduled_task(self, task_name, expected):
        """ตรวจสอบ Scheduled Task"""
        try:
            cmd    = f"(Get-ScheduledTask -TaskName '{task_name}' -ErrorAction Stop).State"
            result = subprocess.check_output(
                ["powershell", "-Command", cmd], stderr=subprocess.STDOUT
            ).decode().strip()

            if result.lower() == str(expected).lower():
                return self._mark_pass()
            return f"Fail (Target: {expected}, Actual: {result})"
        except subprocess.CalledProcessError:
            return "Task Not Found"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # ------------------------------------------------------------------
    # ระบุ target column ตาม sheet และ version ของไฟล์
    # ------------------------------------------------------------------
    def _resolve_target_col(self, sheet_name, columns):
        """
        คืนชื่อ column ที่เก็บ expected value ตาม sheet name
        รองรับทั้ง v24H2 ('Policy Value') และ v25H2 ('Windows 11 25H2')
        """
        if sheet_name in ("Computer", "User"):
            for candidate in ("Windows 11 25H2", "Windows 11 24H2", "Policy Value"):
                if candidate in columns:
                    return candidate
            return None  # ไม่เจอ column ใดเลย
        else:
            return "Windows 11" if "Windows 11" in columns else None

    # ------------------------------------------------------------------
    # Main Scan
    # ------------------------------------------------------------------
    def run_baseline_scan(self):
        """สแกนทุก Policy เทียบกับ MS Security Baseline"""
        if not os.path.exists(self.target_file):
            return 0, {"Error": f"Baseline file not found: {self.target_file}"}

        all_sheets    = pd.read_excel(self.target_file, sheet_name=None)
        security_data = self._export_security_policy()
        self._netsh_cache = {}

        skip_sheets = {"Information", "Revision History"}

        for sheet_name, df in all_sheets.items():
            if sheet_name in skip_sheets:
                continue

            # ✅ แก้ไขจุดนี้: ระบุ column ให้ตรงกับ version ของไฟล์
            target_col = self._resolve_target_col(sheet_name, df.columns.tolist())
            if target_col is None or target_col not in df.columns:
                continue

            for _, row in df.iterrows():
                expected = row.get(target_col)
                if pd.isna(expected) or str(expected).strip() == "":
                    continue

                policy_name = str(
                    row.get("Policy Setting Name") or row.get("Name") or ""
                ).strip()
                if not policy_name or policy_name == "nan":
                    continue

                policy_path = str(row.get("Policy Path") or "").strip()
                reg_info    = row.get("Registry Information")

                self.total += 1

                # สร้าง key ป้องกันชื่อซ้ำข้าม profile (Firewall)
                if sheet_name == "Firewall":
                    profile_name = policy_path.split("\\")[0].strip()
                    full_key = f"[Firewall] {profile_name} - {policy_name}"
                else:
                    full_key = f"[{sheet_name}] {policy_name}"

                # ---- จัดส่งให้ checker ที่เหมาะสม ----
                if sheet_name == "Firewall":
                    self.results[full_key] = self.check_firewall(policy_path, policy_name, expected)

                elif sheet_name == "Advanced Audit":
                    self.results[full_key] = self.check_advanced_audit(policy_name, expected)

                elif sheet_name == "Security Template":
                    self.results[full_key] = self.check_security_template(
                        policy_path, policy_name, reg_info, expected, security_data
                    )

                elif sheet_name == "Services":
                    row_type     = str(row.get("Type") or "Services").strip()
                    service_name = str(row.get("Name") or policy_name).strip()
                    self.results[full_key] = self.check_service(row_type, service_name, expected)

                elif sheet_name in ("Computer", "User"):
                    reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                    if "!" in reg_str:
                        self.results[full_key] = self.check_registry(reg_str, expected)
                    else:
                        self.results[full_key] = "Manual Check Required"

                else:
                    self.results[full_key] = "Manual Check Required"

        # ทำความสะอาด temp file
        if os.path.exists(self.secedit_file):
            os.remove(self.secedit_file)

        score = int((self.passed / self.total) * 100) if self.total > 0 else 0
        return score, self.results

    # ------------------------------------------------------------------
    # รายงานสรุป
    # ------------------------------------------------------------------
    def print_summary(self, score, results):
        """แสดงผลสรุปการสแกน"""
        pass_list   = [k for k, v in results.items() if v == "Pass"]
        fail_list   = [k for k, v in results.items() if str(v).startswith("Fail")]
        manual_list = [k for k, v in results.items() if "Manual" in str(v)]

        print(f"\n{'='*60}")
        print(f"  MS Security Baseline - Windows 11 v25H2 Scan Report")
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


# ใช้ชื่อ alias เดียวกับที่ main.py import
SecurityBaselineScanner = SecurityScanner


if __name__ == "__main__":
    scanner = SecurityScanner()
    score, results = scanner.run_baseline_scan()
    scanner.print_summary(score, results)