"""
remote_executor.py
------------------
Executor สำหรับรันคำสั่งบนเครื่องระยะไกลผ่าน PowerShell Remoting (WinRM)

ข้อกำหนดฝั่ง target machine:
  - Enable-PSRemoting -Force
  - WinRM Service ต้องรันอยู่
  - Firewall เปิดพอร์ต 5985 (HTTP) หรือ 5986 (HTTPS)
  - User ที่ใช้ต้องเป็น Administrator หรือ WinRMRemoteWMIUsers__
"""

import json
import subprocess
import tempfile
import textwrap
from pathlib import Path

from .base_executor import BaseExecutor


# ---------------------------------------------------------------------------
# Helper: สร้าง PSCredential และ Session ผ่าน Invoke-Command
# ---------------------------------------------------------------------------

def _build_invoke_command(
    host: str,
    username: str,
    password: str,
    inner_cmd: str,
    use_ssl: bool = False,
    skip_ca_check: bool = True,
) -> list[str]:
    ssl_flag = "true" if use_ssl else "false"
    skip_ca = "true" if skip_ca_check else "false"

    ps_script = textwrap.dedent(f"""
        $pass   = ConvertTo-SecureString '{password}' -AsPlainText -Force
        $cred   = New-Object System.Management.Automation.PSCredential('{username}', $pass)
        $so     = New-PSSessionOption -SkipCACheck:${skip_ca} -SkipCNCheck:$true
        $result = Invoke-Command `
            -ComputerName '{host}' `
            -Credential $cred `
            -Authentication Negotiate `
            -UseSSL:${ssl_flag} `
            -SessionOption $so `
            -ScriptBlock {{ {inner_cmd} }}
        $result
    """).strip()

    powershell_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return [powershell_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script]


# ---------------------------------------------------------------------------
# subprocess.CompletedProcess-compatible wrapper
# ---------------------------------------------------------------------------

class _FakeCompletedProcess:
    """เลียนแบบ subprocess.CompletedProcess เพื่อ compatibility กับ SecurityScanner"""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# ---------------------------------------------------------------------------
# RemoteExecutor
# ---------------------------------------------------------------------------

class RemoteExecutor(BaseExecutor):
    """
    ส่งคำสั่งไปรันบน remote Windows machine ผ่าน PowerShell Invoke-Command (WinRM)

    Parameters
    ----------
    host : str
        IP address หรือ hostname ของเครื่องเป้าหมาย
    username : str
        ชื่อผู้ใช้งาน (domain\\user หรือ .\\localuser)
    password : str
        รหัสผ่าน
    use_ssl : bool
        True = ใช้ HTTPS (พอร์ต 5986), False = HTTP (พอร์ต 5985)
    skip_ca_check : bool
        ข้ามการตรวจสอบ CA Certificate (ใช้กับ self-signed cert)
    powershell_exe : str
        Path ของ powershell.exe ฝั่ง controller (เครื่องที่รัน backend)
    timeout : int
        Timeout สำหรับแต่ละ command (วินาที)
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        use_ssl: bool = False,
        skip_ca_check: bool = True,
        powershell_exe: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        timeout: int = 120,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.skip_ca_check = skip_ca_check
        self.powershell_exe = powershell_exe
        self.timeout = timeout
        self._session_cache: dict[str, str] = {}  # cache สำหรับ netsh output

    # ------------------------------------------------------------------
    # Public API (ต้องตรงกับ BaseExecutor / LocalExecutor)
    # ------------------------------------------------------------------

    def run_subprocess(self, args, **kwargs) -> _FakeCompletedProcess:
        """
        เลียนแบบ subprocess.run()
        args คือ list ของ argv ที่ SecurityScanner สร้างไว้สำหรับ local
        แต่ RemoteExecutor จะแปลงเป็น Invoke-Command แทน
        """
        inner_cmd = self._argv_to_remote_cmd(args)
        argv = _build_invoke_command(
            self.host, self.username, self.password,
            inner_cmd, self.use_ssl, self.skip_ca_check,
        )
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                shell=False,
            )
            return _FakeCompletedProcess(
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return _FakeCompletedProcess(stderr="Timeout", returncode=1)
        except Exception as e:
            return _FakeCompletedProcess(stderr=str(e), returncode=1)

    def check_output(self, args, **kwargs) -> bytes:
        """
        เลียนแบบ subprocess.check_output()
        ส่งคืน bytes เหมือน original
        """
        inner_cmd = self._argv_to_remote_cmd(args)
        argv = _build_invoke_command(
            self.host, self.username, self.password,
            inner_cmd, self.use_ssl, self.skip_ca_check,
        )
        try:
            result = subprocess.check_output(
                argv,
                stderr=subprocess.STDOUT,
                timeout=self.timeout,
                shell=False,
            )
            return result
        except subprocess.CalledProcessError as e:
            raise subprocess.CalledProcessError(
                e.returncode, e.cmd, output=e.output, stderr=e.stderr
            )
        except subprocess.TimeoutExpired:
            raise subprocess.CalledProcessError(1, args, output=b"Timeout")

    # ------------------------------------------------------------------
    # Remote-specific helpers
    # ------------------------------------------------------------------

    def test_connection(self) -> dict:
            ps_script = textwrap.dedent(f"""
                $pass = ConvertTo-SecureString '{self.password}' -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential('{self.username}', $pass)
                $so   = New-PSSessionOption -SkipCACheck:$true -SkipCNCheck:$true
                try {{
                    $session = New-PSSession `
                        -ComputerName '{self.host}' `
                        -Credential $cred `
                        -UseSSL:${str(self.use_ssl).lower()} `
                        -SessionOption $so `
                        -ErrorAction Stop
                    $hostname = Invoke-Command -Session $session -ScriptBlock {{ $env:COMPUTERNAME }}
                    Remove-PSSession $session
                    Write-Output "OK:$hostname"
                }} catch {{
                    Write-Output "ERR:$($_.Exception.Message)"
                }}
            """).strip()

            argv = [self.powershell_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script]
            try:
                out = subprocess.check_output(
                    argv, stderr=subprocess.STDOUT, timeout=30, shell=False
                ).decode(errors="replace").strip()

                if out.startswith("OK:"):
                    return {"success": True, "message": "Connected", "hostname": out[3:]}
                err_msg = out[4:] if out.startswith("ERR:") else out
                return {"success": False, "message": err_msg, "hostname": ""}
            except Exception as e:
                return {"success": False, "message": str(e), "hostname": ""}

    def copy_baseline_file(self, local_path: str, remote_dest: str = r"C:\MicrosoftScanEngine\data") -> bool:
            ps_script = textwrap.dedent(f"""
                $pass    = ConvertTo-SecureString '{self.password}' -AsPlainText -Force
                $cred    = New-Object System.Management.Automation.PSCredential('{self.username}', $pass)
                $so      = New-PSSessionOption -SkipCACheck:$true -SkipCNCheck:$true
                $session = New-PSSession `
                    -ComputerName '{self.host}' `
                    -Credential $cred `
                    -Authentication Negotiate `  <-- เพิ่มบรรทัดนี้
                    -UseSSL:${str(self.use_ssl).lower()} `
                    -SessionOption $so
                Copy-Item -Path '{local_path}' -Destination '{remote_dest}' -ToSession $session -Force
                Remove-PSSession $session
            """).strip()
            # ... โค้ดเดิมด้านล่าง ...

            argv = [self.powershell_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script]
            try:
                subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=60, shell=False)
                return True
            except Exception:
                return False

    # ------------------------------------------------------------------
    # Registry override: อ่าน registry จาก remote ผ่าน Invoke-Command
    # ------------------------------------------------------------------

    def read_registry_remote(self, hive: str, sub_path: str, key_name: str):
        """
        อ่านค่า registry จาก remote machine โดยตรง
        hive: "HKLM" หรือ "HKCU"
        ส่งคืน (value, type) หรือ raise FileNotFoundError
        """
        ps_inner = (
            f"(Get-ItemProperty -Path '{hive}:\\{sub_path}' "
            f"-Name '{key_name}' -ErrorAction Stop).'{key_name}'"
        )
        argv = _build_invoke_command(
            self.host, self.username, self.password,
            ps_inner, self.use_ssl, self.skip_ca_check,
        )
        result = subprocess.check_output(
            argv, stderr=subprocess.STDOUT, timeout=self.timeout, shell=False
        ).decode(errors="replace").strip()

        if not result or "Cannot find" in result:
            raise FileNotFoundError(f"Registry key not found: {hive}\\{sub_path}\\{key_name}")
        return result, None  # (value, type) - type ไม่จำเป็นสำหรับ scanner

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _argv_to_remote_cmd(self, args) -> str:
        """
        แปลง argv list จาก SecurityScanner เป็น PowerShell command string
        สำหรับส่งผ่าน Invoke-Command

        SecurityScanner จะส่ง args แบบนี้:
          [powershell_exe, "-NoProfile", "-Command", "Get-Service ..."]
          หรือ ["secedit.exe", "/export", ...]
          หรือ ["auditpol.exe", "/get", ...]
          หรือ string เช่น "netsh advfirewall show domainprofile"
        """
        if isinstance(args, str):
            return args

        if not isinstance(args, (list, tuple)):
            return str(args)

        exe = args[0].lower() if args else ""

        # --- PowerShell command ---
        if "powershell" in exe:
            # ค้นหา -Command flag แล้วดึง command ออกมา
            try:
                idx = next(
                    i for i, a in enumerate(args)
                    if str(a).lower() in ("-command", "-c")
                )
                cmd_parts = args[idx + 1:]
                return " ".join(str(p) for p in cmd_parts)
            except StopIteration:
                return " ".join(str(a) for a in args[1:])

        # --- secedit.exe ---
        if "secedit" in exe:
            # secedit /export /cfg <path>  →  ให้รันบน remote แล้วส่ง output กลับมา
            # แต่ export file จะอยู่บน remote ดังนั้นต้องอ่านกลับด้วย
            parts = list(args)
            return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in parts)

        # --- auditpol.exe ---
        if "auditpol" in exe:
            parts = list(args)
            return " ".join(str(p) for p in parts)

        # --- netsh (จะถูกส่งมาเป็น string ผ่าน check_output shell=True) ---
        return " ".join(str(a) for a in args)