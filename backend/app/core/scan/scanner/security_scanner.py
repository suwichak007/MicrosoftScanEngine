"""
security_scanner.py  (updated – รองรับ Local + Remote Scan)
------------------------------------------------------------
การใช้งาน Remote Scan:

    from app.core.scan.scanner.executors.remote_executor import RemoteExecutor

    executor = RemoteExecutor(
        host="192.168.1.50",
        username=".\\Administrator",   # หรือ "DOMAIN\\user"
        password="P@ssw0rd",
    )
    scanner = SecurityScanner(data_path=DATA_PATH, executor=executor)
    score, results = scanner.run_baseline_scan()
"""

import ctypes
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd

from app.core.scan.scanner.executors.local_executor import LocalExecutor
from . import checkers, data_sources
from .helpers import resolve_target_col, update_section_stats
from .mappings import SID_MAP


class SecurityScanner:
    def __init__(self, data_path=None, executor=None):
        self.results = {}
        self.passed = 0
        self.total = 0
        self.debug = []
        self.section_stats = {}

        if data_path:
            self.target_file = os.path.join(data_path, "MS Security Baseline Windows 11 v25H2.xlsx")
            self.debug_log = os.path.join(data_path, "scanner_debug.log")
        else:
            self.target_file = r"C:\MicrosoftScanEngine\backend\data\MS Security Baseline Windows 11 v25H2.xlsx"
            self.debug_log = r"C:\MicrosoftScanEngine\backend\data\scanner_debug.log"

        temp_dir = Path(tempfile.gettempdir())
        self.secedit_file = str(temp_dir / "secedit_export.inf")
        self.audit_file = str(temp_dir / "auditpol_export.txt")

        self.SECEDIT = r"C:\Windows\System32\secedit.exe"
        self.AUDITPOL = r"C:\Windows\System32\auditpol.exe"
        self.POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.python_exe = sys.executable

        self.sid_map = SID_MAP
        self._security_map = {}
        self._audit_map = {}
        self._netsh_cache = {}
        self._mp_pref = None
        self.executor = executor or LocalExecutor()

        # ตรวจว่าเป็น remote executor หรือไม่ (ใช้ใน data_sources)
        self.is_remote = hasattr(self.executor, "host")

        # ถ้า remote ให้เก็บ secedit_file ไว้ที่ remote temp ด้วย
        if self.is_remote:
            self.remote_secedit_file = r"C:\Windows\Temp\secedit_export.inf"
            self.debug.append(f"REMOTE mode: host={self.executor.host}")
        else:
            self.remote_secedit_file = self.secedit_file

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def mark_pass(self):
        self.passed += 1
        return "Pass"

    def write_debug_log(self):
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

    def run_baseline_scan(self):
        if not os.path.exists(self.target_file):
            return 0, {"Error": f"Baseline file not found: {self.target_file}"}

        # ถ้า remote ให้ test connection ก่อน
        if self.is_remote:
            conn = self.executor.test_connection()
            self.debug.append(f"REMOTE connection_test={conn}")
            if not conn["success"]:
                return 0, {"Error": f"Cannot connect to {self.executor.host}: {conn['message']}"}

        data_sources.collect_environment_debug(self)

        security_text = data_sources.export_security_policy(self)
        self._security_map = data_sources.parse_security_data(self, security_text) if security_text else {}

        audit_text = data_sources.export_audit_policy(self)
        self._audit_map = data_sources.parse_audit_data(self, audit_text) if audit_text else {}

        self._mp_pref = data_sources.load_mp_preference(self)

        all_sheets = pd.read_excel(self.target_file, sheet_name=None)
        skip_sheets = {"Information", "Revision History"}

        for sheet_name, df in all_sheets.items():
            if sheet_name in skip_sheets:
                continue

            target_col = resolve_target_col(sheet_name, df.columns.tolist())
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
                    self.results[full_key] = checkers.check_firewall(self, policy_path, policy_name, expected)
                elif sheet_name == "Advanced Audit":
                    self.results[full_key] = checkers.check_advanced_audit(self, policy_name, expected)
                elif sheet_name == "Security Template":
                    self.results[full_key] = checkers.check_security_template(
                        self, policy_path, policy_name, reg_info, expected
                    )
                elif sheet_name == "Services":
                    row_type = str(row.get("Type") or "Services").strip()
                    service_name = str(row.get("Name") or policy_name).strip()
                    self.results[full_key] = checkers.check_service(self, row_type, service_name, expected)
                elif sheet_name == "Computer":
                    defender_check = checkers.check_defender_policy(self, policy_name, expected)
                    if defender_check != "Manual Check Required":
                        self.results[full_key] = defender_check
                    else:
                        reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                        if reg_str and reg_str.lower() not in ("nan", ""):
                            self.results[full_key] = checkers.check_registry(self, reg_str, expected)
                        else:
                            self.results[full_key] = "Manual Check Required"
                elif sheet_name == "User":
                    reg_str = str(reg_info).strip() if pd.notna(reg_info) else ""
                    if reg_str and reg_str.lower() not in ("nan", ""):
                        self.results[full_key] = checkers.check_registry(self, reg_str, expected)
                    else:
                        self.results[full_key] = "Manual Check Required"
                else:
                    self.results[full_key] = "Manual Check Required"

                update_section_stats(self.section_stats, full_key, self.results[full_key])

        pass_count = sum(1 for v in self.results.values() if v == "Pass")
        score = int((pass_count / self.total) * 100) if self.total > 0 else 0
        self.write_debug_log()
        return score, self.results

    def print_summary(self, score, results):
        pass_list = [k for k, v in results.items() if v == "Pass"]
        fail_list = [k for k, v in results.items() if str(v).startswith("Fail")]
        manual_list = [k for k, v in results.items() if "Manual" in str(v)]

        target_label = f"{self.executor.host}" if self.is_remote else "localhost"

        print(f"\n{'='*60}")
        print(f"  MS Security Baseline – Windows 11 v25H2")
        print(f"  Target : {target_label}")
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