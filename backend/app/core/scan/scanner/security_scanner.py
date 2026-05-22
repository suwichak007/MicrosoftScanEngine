

from __future__ import annotations

import os
import re
import subprocess
from typing import Any

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
        executor=None,
        role: str = "Member Server",
    ):
        self.executor = executor
        self._role    = role

        # runtime state
        self.results: dict[str, dict] = {}   # check_id → result dict
        self.passed  = 0
        self.total   = 0

        # mappings
        self.sid_map              = SID_MAP
        self.user_rights_map      = USER_RIGHTS_MAP
        self.special_value_map    = SPECIAL_VALUE_MAP
        self.firewall_profile_map = FIREWALL_PROFILE_MAP
        self.firewall_setting_map = FIREWALL_SETTING_MAP

        # caches
        self._netsh_cache: dict[str, str] = {}
        self._svc_cache:   dict[str, str] = {}
        self._audit_cache: dict[str, str] = {}
        self._security_map: dict[str, str] = {}
        self._mp_pref:     dict[str, Any] = {}
        self._applocker_xml: str = ""

    # ------------------------------------------------------------------
    # Command runner
    # ------------------------------------------------------------------

    POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    SECEDIT    = r"C:\Windows\System32\secedit.exe"
    AUDITPOL   = r"C:\Windows\System32\auditpol.exe"

    def _run_cmd(self, cmd: str, timeout: int = SUBPROCESS_TIMEOUT) -> str:
        if self.executor:
            stdout, _stderr, _rc = self.executor._run_remote_command(cmd)
            return stdout
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout
        )
        return out.decode(errors="replace")

    def mark_pass(self) -> str:
        self.passed += 1
        return "Pass"

    # ------------------------------------------------------------------
    # Pre-fetch helpers (เรียกครั้งเดียวก่อน loop)
    # ------------------------------------------------------------------

    def _prefetch_security_policy(self):
        """export secedit แล้ว parse เป็น dict"""
        remote_path = r"C:\Windows\Temp\secedit_export.inf"
        try:
            if self.executor:
                self.executor.run_subprocess(
                    [self.SECEDIT, "/export", "/cfg", remote_path],
                    capture_output=True, text=True,
                )
                proc = self.executor.run_subprocess(
                    [self.POWERSHELL, "-NoProfile", "-Command",
                     f"Get-Content -Path '{remote_path}' -Encoding Unicode -Raw"],
                    capture_output=True, text=True,
                )
                content = proc.stdout if proc.returncode == 0 else ""
            else:
                local_path = "secedit_export.inf"
                subprocess.run(
                    [self.SECEDIT, "/export", "/cfg", local_path],
                    capture_output=True, timeout=SUBPROCESS_TIMEOUT,
                )
                content = ""
                for enc in ("utf-16", "utf-8-sig", "cp1252"):
                    try:
                        with open(local_path, "r", encoding=enc, errors="replace") as f:
                            content = f.read()
                        break
                    except Exception:
                        continue
                if os.path.exists(local_path):
                    os.remove(local_path)
        except Exception:
            content = ""

        parsed = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            parsed[k.strip()] = v.strip()
        self._security_map = parsed

    def _prefetch_audit_policy(self):
        try:
            if self.executor:
                proc = self.executor.run_subprocess(
                    [self.AUDITPOL, "/get", "/category:*"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                )
                output = proc.stdout if proc.returncode == 0 else ""
            else:
                output = subprocess.check_output(
                    "auditpol /get /category:*",
                    shell=True, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                ).decode(errors="replace")
        except Exception:
            output = ""

        cache = {}
        valid = {"No Auditing", "Success", "Failure", "Success and Failure"}
        for line in output.splitlines():
            if not line.startswith(" "):
                continue
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 2 and parts[-1] in valid:
                subcat  = parts[0].strip()
                setting = parts[-1].strip()
                found   = []
                if "Success" in setting:
                    found.append("Success")
                if "Failure" in setting:
                    found.append("Failure")
                cache[subcat.lower()] = " and ".join(found) if found else "No Auditing"
        self._audit_cache = cache

    def _prefetch_mp_preference(self):
        try:
            cmd = "Get-MpPreference | ConvertTo-Json -Depth 4"
            if self.executor:
                proc = self.executor.run_subprocess(
                    [self.POWERSHELL, "-NoProfile", "-Command", cmd],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                )
                raw = proc.stdout if proc.returncode == 0 else ""
            else:
                raw = subprocess.check_output(
                    [self.POWERSHELL, "-NoProfile", "-Command", cmd],
                    stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                ).decode(errors="replace")
            import json
            data = json.loads(raw)
            self._mp_pref = (data[0] if isinstance(data, list) else data) or {}
        except Exception:
            self._mp_pref = {}

    def _prefetch_services(self, service_names: list[str], task_names: list[str]):
        svc_cache: dict[str, str] = {}

        def _parse(out: str):
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
                _parse(self._run_cmd(cmd))
            if task_names:
                names_ps = ",".join(f"'{n}'" for n in task_names)
                cmd = (
                    f"@({names_ps}) | ForEach-Object {{ "
                    f"$t = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue; "
                    f"if ($t) {{ \"$_|\" + $t.State }} else {{ \"$_|NOT_FOUND\" }} }}"
                )
                _parse(self._run_cmd(cmd))
        else:
            for names, is_task in [(service_names, False), (task_names, True)]:
                if not names:
                    continue
                names_ps = ",".join(f"'{n}'" for n in names)
                cmd = (
                    f"@({names_ps}) | ForEach-Object {{ "
                    + (
                        "$t = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue; "
                        "if ($t) { \"$_|\" + $t.State } else { \"$_|NOT_FOUND\" } }"
                        if is_task else
                        "$s = Get-Service -Name $_ -ErrorAction SilentlyContinue; "
                        "if ($s) { \"$_|\" + $s.StartType } else { \"$_|NOT_FOUND\" } }"
                    )
                )
                try:
                    out = subprocess.check_output(
                        [self.POWERSHELL, "-NoProfile", "-Command", cmd],
                        stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT,
                    ).decode(errors="replace")
                    _parse(out)
                except Exception:
                    pass

        self._svc_cache = svc_cache

    # ------------------------------------------------------------------
    # Check dispatcher  (อ่าน sheet_type จาก check["source"]["sheet_type"])
    # ------------------------------------------------------------------

    def _dispatch(self, check: dict) -> str:
        stype          = check["source"]["sheet_type"]
        check_name     = check["check_name"]
        policy_path    = check["policy_path"]
        registry_path  = check["registry_path"]
        expected       = check["expected_value"]

        if stype == "firewall":
            return self._check_firewall(policy_path, check_name, expected)

        if stype == "advanced_audit":
            return self._check_advanced_audit(check_name, expected)

        if stype == "security_template":
            return self._check_security_template(
                policy_path, check_name, registry_path, expected
            )

        if stype == "services":
            row_type = check.get("source", {}).get("row_type", "Services")
            return self._check_service(row_type, check_name, expected)

        if stype in ("computer", "user"):
            if registry_path and "!" in registry_path:
                return self._check_registry(registry_path, expected)
            if registry_path:
                # format: HKLM\path\key  ไม่มี "!"
                last = registry_path.rfind("\\")
                if last != -1:
                    reg_bang = registry_path[:last] + "!" + registry_path[last+1:]
                    return self._check_registry(reg_bang, expected)
            return "Manual Check Required"

        if stype == "applocker":
            return "Manual Check Required (AppLocker)"

        if stype == "applocker_dc":
            if self._role != "Domain Controller":
                return "__SKIP__"
            return self._check_applocker_dc(check, expected)

        return "Manual Check Required"

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def _normalize(self, value: Any) -> str:
        val = str(value).strip().lower()
        if val in ("1", "enabled", "on", "yes", "true"):
            return "1"
        if val in ("0", "disabled", "off", "no", "false"):
            return "0"
        if val.lstrip("-").isdigit():
            return val
        mapped = self.special_value_map.get(val)
        return mapped if mapped is not None else val

    def _parse_reg_entry(self, reg_entry: str):
        if "!" in reg_entry:
            path_part, key_name = reg_entry.split("!", 1)
        else:
            path_part, key_name = reg_entry.rsplit("\\", 1)
        return path_part.strip(), key_name.strip()

    def _normalize_hive(self, path_part: str):
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

    def _check_registry(self, reg_entry: str, expected: str) -> str:
        try:
            path_part, key_name = self._parse_reg_entry(reg_entry)
            hive_str, sub_path  = self._normalize_hive(path_part)
            if hive_str is None:
                return "Manual Check Required"

            if self.executor and hasattr(self.executor, "read_registry_remote"):
                actual_val, _ = self.executor.read_registry_remote(hive_str, sub_path, key_name)
            else:
                try:
                    import winreg
                    hive = winreg.HKEY_LOCAL_MACHINE if hive_str == "HKLM" else winreg.HKEY_CURRENT_USER
                    with winreg.OpenKey(hive, sub_path) as hkey:
                        actual_val, _ = winreg.QueryValueEx(hkey, key_name)
                except ImportError:
                    return "Manual Check Required (winreg not available)"

            if "RestrictRemoteSAM" in key_name:
                if str(actual_val).strip() == str(expected).strip():
                    return self.mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual_val})"

            if key_name in ("NTLMMinClientSec", "NTLMMinServerSec"):
                try:
                    if int(actual_val) == int(self._normalize(expected).replace("537395200", "537395200")):
                        return self.mark_pass()
                except Exception:
                    pass
                return f"Fail (Target: {expected}, Actual: {actual_val})"

            if self._normalize(actual_val) == self._normalize(expected):
                return self.mark_pass()
            return f"Fail (Target: {expected}, Actual: {actual_val})"

        except FileNotFoundError:
            return f"Fail (Not Configured, Target: {expected})"
        except OSError as e:
            return f"Manual Check Required ({e})"
        except Exception as e:
            return f"Manual Check Required ({e})"

    # ------------------------------------------------------------------
    # Security Template
    # ------------------------------------------------------------------

    def _check_security_template(self, policy_path: str, policy_name: str,
                                   reg_info: str, expected: str) -> str:
        if policy_path == "Security Options":
            if reg_info:
                if "!" not in reg_info:
                    last = reg_info.rfind("\\")
                    if last != -1:
                        reg_info = reg_info[:last] + "!" + reg_info[last+1:]
                return self._check_registry(reg_info, expected)
            if policy_name == "Network access: Allow anonymous SID/Name translation":
                actual = self._security_map.get("LSAAnonymousNameLookup")
                if actual is None:
                    return f"Fail (Not Configured, Target: {expected})"
                if self._normalize(actual) == self._normalize(expected):
                    return self.mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual})"

        if policy_path in ("Password Policy", "Account Lockout"):
            return self._check_secedit(policy_name, expected)

        if policy_path == "User Rights Assignments":
            return self._check_user_rights(policy_name, expected)

        return "Manual Check Required"

    def _check_secedit(self, policy_name: str, expected: str) -> str:
        from .mappings import SECEDIT_KEY_MAP
        key = SECEDIT_KEY_MAP.get(policy_name)
        if not key:
            return "Manual Check Required"
        raw = self._security_map.get(key)
        if raw is None:
            return f"Fail (Not Configured, Target: {expected})"
        if self._normalize(raw) == self._normalize(expected):
            return self.mark_pass()
        return f"Fail (Target: {expected}, Actual: {raw})"

    def _check_user_rights(self, policy_name: str, expected: str) -> str:
        from .mappings import USER_RIGHTS_MAP
        key = USER_RIGHTS_MAP.get(policy_name)
        if not key:
            return "Manual Check Required"
        raw    = self._security_map.get(key)
        exp_str = str(expected).strip()

        if exp_str.lower() == "no one (blank)":
            if raw is None or str(raw).strip() == "":
                return self.mark_pass()
            return f"Fail (Target: empty, Actual: {self._resolve_sids(raw)})"

        if raw is None:
            return "Fail (Not Configured)"

        actual_resolved = self._resolve_sids(raw).lower()
        expected_parts  = [t.strip().lower() for t in re.split(r"[;,]", exp_str) if t.strip()]
        if all(any(ep in part for part in actual_resolved.split("; ")) for ep in expected_parts):
            if "everyone" not in actual_resolved or "everyone" in exp_str.lower():
                return self.mark_pass()
        return f"Fail (Target: {expected}, Actual: {self._resolve_sids(raw)})"

    def _resolve_sids(self, sid_string: str) -> str:
        if not sid_string:
            return "None"
        parts = [p.strip() for p in str(sid_string).split(",") if p.strip()]
        return "; ".join(self.sid_map.get(p, p) for p in parts)

    # ------------------------------------------------------------------
    # Advanced Audit
    # ------------------------------------------------------------------

    def _check_advanced_audit(self, policy_name: str, expected: str) -> str:
        from .mappings import AUDIT_SUBCATEGORY_MAP
        subcategory = AUDIT_SUBCATEGORY_MAP.get(
            policy_name, policy_name.replace("Audit ", "").strip()
        )
        actual = self._audit_cache.get(subcategory.lower())
        target = str(expected).strip().replace(",", " and")
        if actual is None:
            if target.lower() == "no auditing":
                return self.mark_pass()
            return f"Fail (Not Configured, Target: {target})"
        if actual.lower() == target.lower():
            return self.mark_pass()
        return f"Fail (Target: {target}, Actual: {actual})"

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------

    def _norm_yn(self, val: str) -> str:
        v = str(val).strip().lower()
        if v in ("yes","enable","enabled","on","1","true"):
            return "yes"
        if v in ("no","disable","disabled","off","0","false","n/a"):
            return "no"
        return v

    def _check_firewall(self, policy_path: str, policy_name: str, expected: str) -> str:
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
                raw = self._run_cmd(f"netsh advfirewall show {profile_key}profile")
                self._netsh_cache[profile_key] = raw.lower()
            output_lower = self._netsh_cache[profile_key]
            expected_str = str(expected).strip().lower().rstrip()

            if setting_type == "state":
                match  = re.search(r"state\s+(on|off)", output_lower)
                actual = match.group(1) if match else "unknown"
                if actual == expected_str:
                    return self.mark_pass()
                return f"Fail (Target: {expected}, Actual: {actual.upper()})"

            if setting_type == "firewallpolicy":
                match = re.search(r"firewall\s*policy\s+(\w+),(\w+)", output_lower)
                if match:
                    inbound  = "block" if "block" in match.group(1) else "allow"
                    outbound = "allow" if "allow" in match.group(2) else "block"
                    actual   = inbound if param == "inbound" else outbound
                    if actual == expected_str:
                        return self.mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            if setting_type == "settings":
                patterns = {
                    "inboundusernotification": r"inboundusernotification\s+(\S+)",
                    "localfirewallrules":       r"localfirewallrules\s+(\S+)",
                    "localconsecrules":         r"localconsecrules\s+(\S+)",
                }
                pattern = patterns.get(param, fr"{re.escape(param)}\s+(\S+)")
                match   = re.search(pattern, output_lower)
                if match:
                    actual = match.group(1).strip().rstrip(".")
                    if self._norm_yn(actual) == self._norm_yn(expected_str):
                        return self.mark_pass()
                    return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Manual Check Required (Target: {expected})"

            if setting_type == "logging":
                patterns_log = {
                    "droppedpackets":   r"logdroppedpackets\s+(\S+)",
                    "allowedconnections": r"logallowedconnections\s+(\S+)",
                    "maxfilesize":      r"maxfilesize\s+(\d+)",
                }
                pat = patterns_log.get(param)
                if pat:
                    match = re.search(pat, output_lower)
                    if match:
                        actual = match.group(1)
                        if param == "maxfilesize":
                            if actual == str(int(expected)):
                                return self.mark_pass()
                            return f"Fail (Target: {expected}, Actual: {actual})"
                        if self._norm_yn(actual) == self._norm_yn(expected_str):
                            return self.mark_pass()
                        return f"Fail (Target: {expected}, Actual: {actual})"
                return f"Fail (Not Configured, Target: {expected})"

        except Exception as e:
            return f"Manual Check Required ({e})"

        return f"Manual Check Required (Target: {expected})"

    # ------------------------------------------------------------------
    # Services / Tasks
    # ------------------------------------------------------------------

    def _check_service(self, row_type: str, service_name: str, expected: str) -> str:
        actual = self._svc_cache.get(service_name)
        if actual is None or actual == "NOT_FOUND":
            if str(expected).lower() in ("disabled", "manual"):
                return self.mark_pass()
            return f"Fail (Not Configured, Target: {expected})"
        if actual.lower() == str(expected).lower():
            return self.mark_pass()
        return f"Fail (Target: {expected}, Actual: {actual})"

    # ------------------------------------------------------------------
    # AppLocker DC
    # ------------------------------------------------------------------

    def _check_applocker_dc(self, check: dict, expected: str) -> str:
        reg_path       = check.get("registry_path", "")
        policy_setting = check.get("check_name", "")

        if not self._applocker_xml:
            try:
                cmd = "Get-AppLockerPolicy -Effective -Xml"
                self._applocker_xml = self._run_cmd(cmd)
            except Exception:
                self._applocker_xml = ""

        if "EnforcementMode" in policy_setting:
            return self._check_registry(f"{reg_path}!EnforcementMode", "1")

        if reg_path:
            guid = reg_path.split("\\")[-1] if "\\" in reg_path else ""
            if guid and self._applocker_xml:
                if guid.lower() in self._applocker_xml.lower():
                    return self.mark_pass()
                return f"Fail (Rule not found: {expected})"

        return "Manual Check Required"

    # ------------------------------------------------------------------
    # Main Scan  (JSON-driven)
    # ------------------------------------------------------------------

    def run_baseline_scan(self, checks: list[dict]) -> tuple[int, dict[str, dict]]:
        """
        สแกนตาม check definitions จาก JSON

        Parameters
        ----------
        checks : list[dict]
            ผลจาก baseline_config.load_checks(version_id, role)

        Returns
        -------
        score   : int  (0-100)
        results : dict[check_id, result_dict]
            result_dict มีครบ: check_id, check_name, category, severity,
            remediation, registry_path, policy_path, expected_value,
            status, current_value, applies_to
        """
        self.results = {}
        self.passed  = 0
        self.total   = 0

        # ── Pre-fetch ──────────────────────────────────────────────────
        self._prefetch_security_policy()
        self._prefetch_audit_policy()
        self._prefetch_mp_preference()

        service_names = []
        task_names    = []
        for c in checks:
            if c["source"]["sheet_type"] == "services":
                row_type = c.get("source", {}).get("row_type", "Services")
                name     = c["check_name"]
                (task_names if row_type == "Scheduled Task" else service_names).append(name)
        if self._role == "Domain Controller" and "AppIDSvc" not in service_names:
            service_names.append("AppIDSvc")
        self._prefetch_services(service_names, task_names)

        # ── Main loop ──────────────────────────────────────────────────
        for check in checks:
            status = self._dispatch(check)
            if status == "__SKIP__":
                continue

            self.total += 1
            if status == "Pass":
                self.passed += 1

            # parse current_value จาก status string
            current_value = ""
            if status.startswith("Fail"):
                m = re.search(r"Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)", status)
                if m:
                    current_value = m.group(1).strip().rstrip(")")
                if not current_value and "Not Configured" in status:
                    current_value = "Not Configured"

            self.results[check["check_id"]] = {
                "check_id":      check["check_id"],
                "check_name":    check["check_name"],
                "category":      check["category"],
                "severity":      check["severity"],
                "remediation":   check["remediation"],
                "registry_path": check["registry_path"],
                "policy_path":   check["policy_path"],
                "expected_value": check["expected_value"],
                "applies_to":    check.get("applies_to", []),
                "status":        status,
                "current_value": current_value,
            }

        score = int((self.passed / self.total) * 100) if self.total > 0 else 0
        self._print_summary(score)
        return score, self.results

    # ------------------------------------------------------------------
    # Summary log
    # ------------------------------------------------------------------

    def _print_summary(self, score: int):
        section_stats: dict[str, dict] = {}
        for res in self.results.values():
            sec = res["category"]
            if sec not in section_stats:
                section_stats[sec] = {"Total": 0, "Pass": 0, "Fail": 0, "Manual": 0}
            section_stats[sec]["Total"] += 1
            st = res["status"]
            if st == "Pass":
                section_stats[sec]["Pass"] += 1
            elif st.startswith("Fail"):
                section_stats[sec]["Fail"] += 1
            else:
                section_stats[sec]["Manual"] += 1

        lines = ["=" * 70, "SECTION SUMMARY", "=" * 70]
        for sec, s in sorted(section_stats.items()):
            pct = round(s["Pass"] / s["Total"] * 100, 2) if s["Total"] else 0
            lines.append(
                f"[{sec}] Total={s['Total']} Pass={s['Pass']} "
                f"Fail={s['Fail']} Manual={s['Manual']} Pass%={pct}"
            )
        grand = {k: sum(s[k] for s in section_stats.values())
                 for k in ("Total","Pass","Fail","Manual")}
        grand_pct = round(grand["Pass"]/grand["Total"]*100, 2) if grand["Total"] else 0
        lines += [
            "-" * 70,
            f"[ALL] Total={grand['Total']} Pass={grand['Pass']} "
            f"Fail={grand['Fail']} Manual={grand['Manual']} Pass%={grand_pct}",
            "=" * 70,
        ]
        print("\n".join(lines))

    # ------------------------------------------------------------------
    # Print summary (public)
    # ------------------------------------------------------------------

    def print_summary(self, score: int, results: dict):
        pass_list   = [k for k, v in results.items() if v["status"] == "Pass"]
        fail_list   = [k for k, v in results.items() if v["status"].startswith("Fail")]
        manual_list = [k for k, v in results.items() if "Manual" in v["status"]]
        print(f"\n{'='*60}")
        print(f"  Security Baseline Scan")
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
                r = results[k]
                print(f"  ✗ [{r['severity']}] {r['check_name']}")
                print(f"    → {r['status']}")
            print()