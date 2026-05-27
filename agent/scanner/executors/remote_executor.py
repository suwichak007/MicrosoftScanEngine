"""
remote_executor.py
------------------
Executor สำหรับรันคำสั่งบนเครื่องระยะไกลผ่าน PowerShell Remoting (WinRM)

การปรับปรุงด้านประสิทธิภาพ:
  - Persistent PSSession: เปิด session ครั้งเดียวแล้วใช้ซ้ำตลอด (ลด overhead ~70-80%)
  - Bulk Registry Prefetch: อ่าน registry ทุก key ในครั้งเดียว (ลด round-trip ~15-20%)
  - Registry Cache: เก็บค่าที่อ่านแล้วไม่ต้องอ่านซ้ำ

ข้อกำหนดฝั่ง target machine:
  - Enable-PSRemoting -Force
  - WinRM Service ต้องรันอยู่
  - Firewall เปิดพอร์ต 5985 (HTTP) หรือ 5986 (HTTPS)
  - User ที่ใช้ต้องเป็น Administrator หรือ WinRMRemoteWMIUsers__
"""

import json
import subprocess
import textwrap
import threading
import time
from pathlib import Path

from .base_executor import BaseExecutor


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

    การปรับปรุง: ใช้ Persistent PSSession แทนการสร้าง session ใหม่ทุกครั้ง
    ทำให้ scan เร็วขึ้น ~70-80%

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

    # Sentinel string สำหรับแยก output แต่ละ command
    _SENTINEL = "<<<CMD_END_8f3a2b1c>>>"
    _REGISTRY_PREFETCH_TIMEOUT = 25

    def _log_timing(self, label: str, elapsed: float, detail: str = ""):
        suffix = f" ({detail})" if detail else ""
        print(f"[scan-timing] {label}: {elapsed:.2f}s{suffix}")

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

        # Persistent PS process (local side)
        self._ps_process: subprocess.Popen | None = None
        self._ps_lock = threading.Lock()

        # Registry cache (key -> value) เพื่อไม่ต้องอ่านซ้ำ
        self._registry_cache: dict[str, str] = {}
        self._registry_cache_loaded = False

        # netsh output cache
        self._session_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Persistent PowerShell Process
    # ------------------------------------------------------------------

    def _get_or_create_ps_process(self) -> subprocess.Popen:
        if self._ps_process is not None and self._ps_process.poll() is None:
            return self._ps_process

        print(f"[ps-session] creating new PSSession to {self.host}...")
        ssl_flag = "$true" if self.use_ssl else "$false"
        skip_ca  = "$true" if self.skip_ca_check else "$false"

        # สร้าง session ด้วย one-shot ก่อน เพื่อทดสอบว่า connect ได้
        init_script = (
            f"$ErrorActionPreference = 'Stop';"
            f"$pass = ConvertTo-SecureString '{self.password}' -AsPlainText -Force;"
            f"$cred = New-Object System.Management.Automation.PSCredential('{self.username}', $pass);"
            f"$so = New-PSSessionOption -SkipCACheck:{skip_ca} -SkipCNCheck:$true;"
            f"$global:_RemoteSession = New-PSSession "
            f"-ComputerName '{self.host}' "
            f"-Credential $cred "
            f"-Authentication Negotiate "
            f"-UseSSL:{ssl_flag} "
            f"-SessionOption $so "
            f"-ErrorAction Stop;"
            f"Write-Output 'SESSION_READY'"
        )

        self._ps_process = subprocess.Popen(
            [self.powershell_exe, "-NoProfile", "-NonInteractive",
            "-OutputFormat", "Text",   # ← เพิ่ม
            "-Command", init_script],  # ← เปลี่ยนจาก "-" เป็น script โดยตรง
            stdin=subprocess.DEVNULL,   # ← ปิด stdin
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        deadline = time.time() + 30
        while time.time() < deadline:
            line = self._ps_process.stdout.readline()
            if not line:
                err = ""
                try:
                    err = self._ps_process.stderr.read(1000)
                except Exception:
                    pass
                print(f"[ps-session] EOF — stderr: {err}")
                raise RuntimeError(f"PSSession init failed: {err}")
            print(f"[ps-session] init line: {repr(line)}")
            if "SESSION_READY" in line:
                print(f"[ps-session] session ready ✓")
                return self._ps_process
            if "ERROR" in line.upper() or "EXCEPTION" in line.upper():
                raise RuntimeError(f"PSSession init failed: {line.strip()}")

        raise RuntimeError("Timeout waiting for PSSession to be ready")

    def _run_remote_command(self, inner_cmd: str) -> tuple[str, str, int]:
        """
        รัน command บน remote — ใช้ oneshot ทุกครั้ง (เสถียรกว่า persistent pipe)
        """
        started_at = time.perf_counter()
        result = self._run_oneshot_command(inner_cmd)
        self._log_timing("remote_command", time.perf_counter() - started_at, 
                        f"rc={result[2]} bytes={len(result[0])}")
        return result

    def close(self):
        """ปิด persistent session และ process"""
        with self._ps_lock:
            if self._ps_process and self._ps_process.poll() is None:
                try:
                    close_cmd = "if ($global:_RemoteSession) { Remove-PSSession $global:_RemoteSession }\n"
                    self._ps_process.stdin.write(close_cmd)
                    self._ps_process.stdin.flush()
                    self._ps_process.stdin.close()
                    self._ps_process.wait(timeout=5)
                except Exception:
                    pass
                finally:
                    try:
                        self._ps_process.terminate()
                    except Exception:
                        pass
            self._ps_process = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API (ต้องตรงกับ BaseExecutor / LocalExecutor)
    # ------------------------------------------------------------------

    def run_subprocess(self, args, **kwargs) -> _FakeCompletedProcess:
        """
        เลียนแบบ subprocess.run()
        ใช้ persistent session แทนการสร้างใหม่ทุกครั้ง
        """
        inner_cmd = self._argv_to_remote_cmd(args)
        stdout, stderr, returncode = self._run_remote_command(inner_cmd)
        return _FakeCompletedProcess(stdout=stdout, stderr=stderr, returncode=returncode)

    def check_output(self, args, **kwargs) -> bytes:
        """
        เลียนแบบ subprocess.check_output()
        ส่งคืน bytes เหมือน original
        """
        inner_cmd = self._argv_to_remote_cmd(args)
        stdout, stderr, returncode = self._run_remote_command(inner_cmd)

        if returncode != 0:
            raise subprocess.CalledProcessError(
                returncode, args,
                output=stdout.encode("utf-8", errors="replace"),
                stderr=stderr.encode("utf-8", errors="replace"),
            )
        return stdout.encode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Registry: Bulk Prefetch + Cache
    # ------------------------------------------------------------------
    def prefetch_registry_bulk(self, keys: list[tuple]) -> dict:
        """
        อ่าน registry หลาย key พร้อมกันในครั้งเดียว (batch)
        keys = [(hive, sub_path, key_name), ...]
        ส่งคืน dict: "HIVE\\sub_path\\key_name" -> value_string
        """
        started_at = time.perf_counter()
        if not keys:
            return {}

        original_timeout = self.timeout
        self.timeout = min(self.timeout, self._REGISTRY_PREFETCH_TIMEOUT)
        try:
            try:
                test_out, _, test_rc = self._run_remote_command("Write-Output 'PING'")
                if test_rc != 0 or "PING" not in test_out:
                    print(f"[prefetch_registry_bulk] session not ready, skipping prefetch")
                    return {}
            except Exception as e:
                print(f"[prefetch_registry_bulk] session test failed: {e}, skipping prefetch")
                return {}            
            # ส่ง key list เป็น JSON เข้า PowerShell แทนการ inline ทุก key
            # ทำให้ script size คงที่ ~700 bytes ไม่ว่าจะมีกี่ key
            keys_json = json.dumps([
                {"hive": h, "sub": s, "key": k}
                for h, s, k in keys
            ])

            ps_script = f"""
    $keys = '{keys_json}' | ConvertFrom-Json
    $out = @{{}}
    $cache = @{{}}
    foreach ($item in $keys) {{
        $path = "$($item.hive):\\$($item.sub)"
        $cacheKey = "$($item.hive)\\$($item.sub)\\$($item.key)"
        if (-not $cache.ContainsKey($path)) {{
            try {{
                $cache[$path] = Get-ItemProperty -Path $path -ErrorAction Stop
            }} catch {{
                $cache[$path] = $null
            }}
        }}
        $props = $cache[$path]
        if ($props -ne $null -and $props.PSObject.Properties.Match($item.key)) {{
            $out[$cacheKey] = [string]$props.($item.key)
        }} else {{
            $out[$cacheKey] = $null
        }}
    }}
    $out | ConvertTo-Json -Compress -Depth 1
    """.strip()

            self._log_timing("prefetch_registry_bulk_call", time.perf_counter() - started_at,
                            f"keys={len(keys)} script_bytes={len(ps_script)}")

            stdout, stderr, returncode = self._run_remote_command(ps_script)
            result = {}

            self._log_timing("prefetch_registry_bulk_ret", time.perf_counter() - started_at,
                            f"rc={returncode} out_bytes={len(stdout)} err_bytes={len(stderr) if stderr else 0}")

            if returncode != 0 and stderr:
                snippet = stderr.strip().replace('\n', ' ')[:300]
                print(f"[prefetch_registry_bulk] remote stderr: {snippet}")

            # fallback ไป oneshot ถ้า persistent session timeout
            if returncode == 1 and stderr and "Timeout waiting for sentinel" in stderr:
                print(f"[prefetch_registry_bulk] persistent session timeout, trying oneshot")
                try:
                    out2, err2, rc2 = self._run_oneshot_command(ps_script)
                    self._log_timing("prefetch_registry_bulk_oneshot_ret", time.perf_counter() - started_at,
                                    f"rc={rc2} out_bytes={len(out2)} err_bytes={len(err2) if err2 else 0}")
                    if rc2 != 0 and err2:
                        print(f"[prefetch_registry_bulk] oneshot stderr: {err2.strip()[:800]}")
                    stdout = out2
                    stderr = err2
                    returncode = rc2
                except Exception as e:
                    print(f"[prefetch_registry_bulk] oneshot fallback failed: {e}")

            if stdout.strip():
                for line in reversed(stdout.strip().splitlines()):
                    line = line.strip()
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            raw = json.loads(line)
                            for k, v in raw.items():
                                result[k] = v
                            break
                        except json.JSONDecodeError:
                            continue

            self._registry_cache.update(result)
            self._registry_cache_loaded = True
            self._log_timing("prefetch_registry_bulk", time.perf_counter() - started_at,
                            f"keys={len(keys)} hits={len(result)}")
            return result
        finally:
            self.timeout = original_timeout

    def read_registry_remote(self, hive: str, sub_path: str, key_name: str):
        cache_key = f"{hive}\\{sub_path}\\{key_name}"

        if self._registry_cache_loaded and cache_key in self._registry_cache:
            val = self._registry_cache[cache_key]
            if val is None:
                raise FileNotFoundError(f"Registry key not found: {cache_key}")
            return val, None

        # CACHE MISS — log เพื่อดูว่า key format ต่างกันยังไง
        print(f"[cache-miss] {cache_key}")
        print(f"[cache-keys-sample] {list(self._registry_cache.keys())[:5]}")  # ดู format จริง

        ps_inner = (
            f"(Get-ItemProperty -Path '{hive}:\\{sub_path}' "
            f"-Name '{key_name}' -ErrorAction Stop).'{key_name}'"
        )
        stdout, _, returncode = self._run_remote_command(ps_inner)
        result = stdout.strip()

        if not result or "Cannot find" in result or returncode != 0:
            self._registry_cache[cache_key] = None
            raise FileNotFoundError(f"Registry key not found: {cache_key}")

        self._registry_cache[cache_key] = result
        return result, None

    # ------------------------------------------------------------------
    # Remote-specific helpers
    # ------------------------------------------------------------------

    def test_connection(self) -> dict:
        """ทดสอบการเชื่อมต่อ WinRM ไปยัง remote host"""
        started_at = time.perf_counter()
        ps_script = textwrap.dedent(f"""
            $pass = ConvertTo-SecureString '{self.password}' -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential('{self.username}', $pass)
            $so = New-PSSessionOption -SkipCACheck:$true -SkipCNCheck:$true

            try {{
                $isLocal = ($env:COMPUTERNAME -eq '{self.host}') -or ('{self.host}' -eq '127.0.0.1') -or ('{self.host}' -eq 'localhost')

                if ($isLocal) {{
                    $session = New-PSSession -ComputerName '{self.host}' -Credential $cred -ErrorAction Stop
                }} else {{
                    $session = New-PSSession `
                        -ComputerName '{self.host}' `
                        -Credential $cred `
                        -Authentication Negotiate `
                        -UseSSL:${str(self.use_ssl).lower()} `
                        -SessionOption $so `
                        -ErrorAction Stop
                }}

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
                result = {"success": True, "message": "Connected", "hostname": out[3:]}
                self._log_timing("test_connection", time.perf_counter() - started_at, "success")
                return result

            err_msg = out[4:] if out.startswith("ERR:") else out
            result = {"success": False, "message": err_msg, "hostname": ""}
            self._log_timing("test_connection", time.perf_counter() - started_at, "failed")
            return result

        except Exception as e:
            self._log_timing("test_connection", time.perf_counter() - started_at, f"error={type(e).__name__}")
            return {"success": False, "message": str(e), "hostname": ""}

    def copy_baseline_file(self, local_path: str, remote_dest: str = r"C:\MicrosoftScanEngine\data") -> bool:
        """คัดลอกไฟล์ไปยัง remote machine ผ่าน PSSession"""
        started_at = time.perf_counter()
        ps_script = textwrap.dedent(f"""
            $pass    = ConvertTo-SecureString '{self.password}' -AsPlainText -Force
            $cred    = New-Object System.Management.Automation.PSCredential('{self.username}', $pass)
            $so      = New-PSSessionOption -SkipCACheck:$true -SkipCNCheck:$true
            $session = New-PSSession `
                -ComputerName '{self.host}' `
                -Credential $cred `
                -Authentication Negotiate `
                -UseSSL:${str(self.use_ssl).lower()} `
                -SessionOption $so
            Copy-Item -Path '{local_path}' -Destination '{remote_dest}' -ToSession $session -Force
            Remove-PSSession $session
        """).strip()

        argv = [self.powershell_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script]
        try:
            subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=60, shell=False)
            self._log_timing("copy_baseline_file", time.perf_counter() - started_at, "success")
            return True
        except Exception:
            self._log_timing("copy_baseline_file", time.perf_counter() - started_at, "failed")
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _argv_to_remote_cmd(self, args) -> str:
        """
        แปลง argv list จาก SecurityScanner เป็น PowerShell command string
        สำหรับส่งผ่าน Invoke-Command
        """
        if isinstance(args, str):
            return args

        if not isinstance(args, (list, tuple)):
            return str(args)

        exe = args[0].lower() if args else ""

        # --- PowerShell command ---
        if "powershell" in exe:
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
            parts = list(args)
            return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in parts)

        # --- auditpol.exe ---
        if "auditpol" in exe:
            parts = list(args)
            return " ".join(str(p) for p in parts)

        # --- netsh หรืออื่นๆ ---
        return " ".join(str(a) for a in args)

    def _run_oneshot_command(self, inner_cmd: str) -> tuple[str, str, int]:
        started_at = time.perf_counter()
        ssl_flag = "$true" if self.use_ssl else "$false"
        skip_ca  = "$true" if self.skip_ca_check else "$false"

        # ตัด inner_cmd ให้สั้นสำหรับ log
        cmd_preview = inner_cmd[:80].replace('\n', ' ')
        print(f"[oneshot] starting: {cmd_preview}...")

        ps_script = textwrap.dedent(f"""
            $pass   = ConvertTo-SecureString '{self.password}' -AsPlainText -Force
            $cred   = New-Object System.Management.Automation.PSCredential('{self.username}', $pass)
            $so     = New-PSSessionOption -SkipCACheck:{skip_ca} -SkipCNCheck:$true
            $result = Invoke-Command `
                -ComputerName '{self.host}' `
                -Credential $cred `
                -Authentication Negotiate `
                -UseSSL:{ssl_flag} `
                -SessionOption $so `
                -ScriptBlock {{ {inner_cmd} }}
            $result
        """).strip()

        print(f"[oneshot] script_bytes={len(ps_script)} launching subprocess...")  # ← เพิ่ม

        try:
            proc = subprocess.run(
                [self.powershell_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                shell=False,
            )
            elapsed = time.perf_counter() - started_at
            print(f"[oneshot] done: rc={proc.returncode} bytes={len(proc.stdout)} elapsed={elapsed:.2f}s")
            if proc.stderr:
                print(f"[oneshot] stderr: {proc.stderr[:300]}")
            self._log_timing("remote_command_oneshot", elapsed, f"rc={proc.returncode} bytes={len(proc.stdout)}")
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - started_at
            print(f"[oneshot] TIMEOUT after {elapsed:.2f}s")
            self._log_timing("remote_command_oneshot", elapsed, "timeout")
            return "", "Timeout", 1
        except Exception as e:
            elapsed = time.perf_counter() - started_at
            print(f"[oneshot] ERROR: {type(e).__name__}: {e}")
            self._log_timing("remote_command_oneshot", elapsed, f"error={type(e).__name__}")
            return "", str(e), 1