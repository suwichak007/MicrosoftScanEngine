"""
security_scanner.py for agent

ใช้ JSON-first baseline API (load_checks) แทน Excel
- โหลด checks จาก /baselines/generated/*.json
- ไม่อ่าน Excel โดยตรง
"""

import os
import re
import subprocess
from typing import Any

from .baseline_config import load_checks, list_available_versions
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
        version_id: str = None,
    ):
        self.executor = executor
        self._role = role
        self._version_id = version_id

        # runtime state
        self.results: dict[str, dict] = {}   # check_id → result dict
        self.passed = 0
        self.total = 0

        # mappings
        self.sid_map = SID_MAP
        self.user_rights_map = USER_RIGHTS_MAP
        self.special_value_map = SPECIAL_VALUE_MAP
        self.firewall_profile_map = FIREWALL_PROFILE_MAP
        self.firewall_setting_map = FIREWALL_SETTING_MAP

        # caches
        self._netsh_cache: dict[str, str] = {}
        self._svc_cache: dict[str, str] = {}
        self._audit_cache: dict[str, str] = {}
        self._security_map: dict[str, str] = {}
        self._mp_pref: dict[str, Any] = {}
        self._applocker_xml: str = ""

    # ------------------------------------------------------------------
    # Command runner
    # ------------------------------------------------------------------

    POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    SECEDIT = r"C:\Windows\System32\secedit.exe"
    AUDITPOL = r"C:\Windows\System32\auditpol.exe"

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
    # Baseline loading
    # ------------------------------------------------------------------

    def load_baseline(self, version_id: str = None) -> list[dict]:
        """
        โหลด baseline checks จาก JSON

        Returns
        -------
        list[dict]  — baseline checks ที่กรองแล้วตาม role
        """
        version = version_id or self._version_id
        if not version:
            # Auto-detect บริชฯแรก
            versions = list_available_versions()
            if not versions:
                return []
            version = versions[0]["version_id"]
            print(f"[Agent] Auto-detect baseline: {version}")

        try:
            checks = load_checks(version, self._role)
            print(f"[Agent] Loaded {len(checks)} checks from {version}")
            return checks
        except Exception as e:
            print(f"[Agent] Error loading baseline: {e}")
            return []

    # ------------------------------------------------------------------
    # Placeholder scan methods
    # ------------------------------------------------------------------

    def run_baseline_scan(self) -> tuple[int, dict]:
        """
        รัน baseline scan

        Returns
        -------
        (passed_count, results_dict)
        """
        checks = self.load_baseline()
        if not checks:
            return 0, {"error": "No checks loaded"}

        results = {}
        for check in checks:
            check_id = check.get("check_id", "unknown")
            # TODO: implement check logic
            results[check_id] = {
                "status": "NotImplemented",
                "check_name": check.get("check_name", ""),
                "category": check.get("category", ""),
                "severity": check.get("severity", ""),
            }

        self.results = results
        return len(results), results

    # ------------------------------------------------------------------
    # Stub methods (for compatibility)
    # ------------------------------------------------------------------

    def _prefetch_security_policy(self):
        pass

    def _prefetch_audit_policy(self):
        pass

    def _prefetch_mp_preference(self):
        pass

    def _prefetch_services(self, service_names: list[str], task_names: list[str]):
        pass
