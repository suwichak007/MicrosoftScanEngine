# agent.py
import json
import os
import sys
import time
import io
import socket
import hashlib
import shutil
import zipfile
import re
from pathlib import Path
from urllib.parse import urljoin

import requests

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    INTERNAL = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INTERNAL = BASE_DIR

sys.path.insert(0, INTERNAL)

CONFIG_PATH = os.path.join(BASE_DIR, "agent_config.json")
ACTIVE_SCANNER_ROOT = ""

VALID_ROLES = {"Member Server", "Domain Controller"}
AGENT_VERSION = "1.0.0"

REGISTRY_VALUE_LABEL_MAP = {
    "always": 2,
    "require signing": 2,
    "lock workstation": 1,
    "classic": 0,
    "guest only": 1,
    "negotiate signing": 1,
    "send ntlmv2 response only. refuse lm & ntlm": 5,
    "send ntlmv2 responses only, refuse lm and ntlm": 5,
    "require ntlmv2 session security and require 128-bit encryption": 537395200,
    "require ntlmv2 session security, require 128bit encryption": 537395200,
    "audit all": 1,
    "enable auditing for all accounts": 2,
    "p-node (recommended)": 2,
    "highest protection, source routing is completely disabled": 2,
    "block all": 0,
    "authenticated": 1,
    "do not execute any autorun commands": 1,
    "all drives": 255,
    "use tls 1.1 and tls 1.2": 2560,
    "disable java": 0,
    "high safety": 65536,
    "prompt": 1,
    "anonymous logon": 0,
    "high level": 3,
    "on, but disallow access above lock": 1,
}


def get_agent_runtime_version() -> str:
    try:
        runtime_path = sys.executable if getattr(sys, "frozen", False) else __file__
        stamp = time.strftime("%Y%m%d%H%M", time.localtime(os.path.getmtime(runtime_path)))
        return f"{AGENT_VERSION}+build{stamp}"
    except Exception:
        return AGENT_VERSION


def get_ipv4_addresses() -> list[str]:
    addresses = set()
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                addresses.add(ip)
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
            addresses.add(ip)
    except Exception:
        pass

    return sorted(addresses)


def detect_os_metadata() -> dict:
    meta = {
        "os_name": "",
        "os_version": "",
        "os_build": "",
        "os_release": "",
        "os_family": "",
    }
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        values = {}
        for name in [
            "ProductName",
            "DisplayVersion",
            "ReleaseId",
            "CurrentBuildNumber",
            "CurrentVersion",
            "EditionID",
            "InstallationType",
        ]:
            try:
                values[name], _ = winreg.QueryValueEx(key, name)
            except OSError:
                pass
        winreg.CloseKey(key)

        product_name = str(values.get("ProductName", "")).strip()
        build = str(values.get("CurrentBuildNumber", "")).strip()
        release = str(values.get("DisplayVersion") or values.get("ReleaseId") or "").strip()
        installation_type = str(values.get("InstallationType", "")).lower()

        try:
            build_number = int(build)
        except ValueError:
            build_number = 0

        if "server" in product_name.lower() or "server" in installation_type:
            os_family = "windows_server"
        elif "windows" in product_name.lower():
            os_family = "windows_client"
        else:
            os_family = ""

        if os_family == "windows_client" and build_number >= 22000 and "windows 11" not in product_name.lower():
            product_name = "Windows 11"

        meta.update({
            "os_name": product_name,
            "os_version": str(values.get("CurrentVersion", "")).strip(),
            "os_build": build,
            "os_release": release,
            "os_family": os_family,
        })
    except Exception as e:
        print(f"[Agent] OS detect warning: {e}")
    return meta


# ── เพิ่มตรงนี้ ก่อน run_scan ──────────────────────────────────
def detect_role() -> str:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ProductOptions"
        )
        product_type, _ = winreg.QueryValueEx(key, "ProductType")
        winreg.CloseKey(key)

        product_type = product_type.strip().lower()
        if product_type == "lanmannt":
            return "Domain Controller"
        elif product_type == "servernt":
            return "Member Server"
        else:
            return "Member Server"
    except Exception:
        return "Member Server"


def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        default = {
            "backend_url":      "http://BACKEND_IP:8000",
            "agent_token":      "ใส่ token ที่ได้จาก POST /agent/register",
            "poll_interval":    10,
            "request_timeout":  300,
            "data_path":        os.path.join(BASE_DIR, "data"),
            "package_path":     os.path.join(BASE_DIR, "packages"),
            "scanner_auto_update": True,
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
        print(f"[Agent] สร้าง config ที่ {CONFIG_PATH}")
        print("[Agent] กรุณาแก้ไข config แล้วรันใหม่")
        sys.exit(1)

    with open(CONFIG_PATH, encoding="utf-8-sig") as f:
        return json.load(f)


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(zip_path: str, dest_dir: str):
    dest = Path(dest_dir).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if target != dest and dest not in target.parents:
                raise ValueError(f"Unsafe package path: {member.filename}")
        zf.extractall(dest)


def _activate_scanner_root(root: str):
    global ACTIVE_SCANNER_ROOT
    if not root:
        return
    root = os.path.abspath(root)
    if ACTIVE_SCANNER_ROOT == root:
        return

    for name in list(sys.modules):
        if name == "scanner" or name.startswith("scanner."):
            del sys.modules[name]

    if root in sys.path:
        sys.path.remove(root)
    sys.path.insert(0, root)
    os.environ["BASELINES_DIR"] = os.path.join(root, "baselines", "generated")
    ACTIVE_SCANNER_ROOT = root
    print(f"[Agent] scanner package active -> {root}")


def ensure_scanner_package(cfg: dict, headers: dict, timeout: int):
    if not cfg.get("scanner_auto_update", True):
        return

    url = cfg["backend_url"].rstrip("/")
    package_base = cfg.get("package_path") or os.path.join(BASE_DIR, "packages")
    os.makedirs(package_base, exist_ok=True)

    latest = requests.get(
        f"{url}/agent/scanner-package/latest",
        headers=headers,
        timeout=timeout,
    )
    latest.raise_for_status()
    info = latest.json()
    version = str(info.get("version", "")).strip()
    sha256 = str(info.get("sha256", "")).strip().lower()
    download_url = str(info.get("download_url", "")).strip()
    if not version or not sha256 or not download_url:
        raise RuntimeError("Invalid scanner package manifest from backend")

    target_dir = os.path.join(package_base, version)
    manifest_path = os.path.join(target_dir, "package_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                local = json.load(f)
            if local.get("sha256", "").lower() == sha256:
                _activate_scanner_root(target_dir)
                return
        except Exception:
            pass

    tmp_zip = os.path.join(package_base, f"{version}.download")
    package_url = download_url if download_url.lower().startswith(("http://", "https://")) else urljoin(f"{url}/", download_url.lstrip("/"))
    print(f"[Agent] downloading scanner package {version}...")
    with requests.get(package_url, headers=headers, stream=True, timeout=timeout) as resp:
        resp.raise_for_status()
        with open(tmp_zip, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

    actual_hash = _hash_file(tmp_zip).lower()
    if actual_hash != sha256:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass
        raise RuntimeError(f"Scanner package checksum mismatch: expected {sha256}, got {actual_hash}")

    staging_dir = os.path.join(package_base, f".{version}.staging")
    if os.path.isdir(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir, exist_ok=True)
    _safe_extract(tmp_zip, staging_dir)
    os.remove(tmp_zip)

    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir)
    shutil.move(staging_dir, target_dir)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    _activate_scanner_root(target_dir)


def run_scan(job: dict, data_path: str):
    from scanner.security_scanner import SecurityScanner
    from scanner.baseline_config import load_checks

    version = job.get("version", "")

    # detect role
    detected_role = detect_role()
    role = detected_role

    print(f"[Agent] detected={detected_role}  job_role={job.get('role', '-')}  final={role}")

    # โหลด checks จาก JSON
    checks = load_checks(version, role=role)
    print(f"[Agent] baseline={version}  role={role}  checks={len(checks)}")

    s = SecurityScanner(role=role)
    score, details = s.run_baseline_scan(checks)
    stored_details = dict(details or {})
    stored_details["_detected_role"] = detected_role
    return score, stored_details


def _normalize_autofix_hive(path_part: str):
    import re
    import winreg

    upper = path_part.upper()
    if upper.startswith("HKEY_LOCAL_MACHINE\\") or upper.startswith("HKLM\\"):
        sub_path = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=re.IGNORECASE)
        return winreg.HKEY_LOCAL_MACHINE, "HKLM", sub_path
    if upper.startswith("HKEY_CURRENT_USER\\") or upper.startswith("HKCU\\"):
        sub_path = re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=re.IGNORECASE)
        return winreg.HKEY_CURRENT_USER, "HKCU", sub_path
    if upper.startswith("MACHINE\\"):
        sub_path = re.sub(r"^MACHINE\\", "", path_part, flags=re.IGNORECASE)
        return winreg.HKEY_LOCAL_MACHINE, "HKLM", sub_path
    if upper.startswith("SOFTWARE\\"):
        return winreg.HKEY_LOCAL_MACHINE, "HKLM", path_part
    raise ValueError("unsupported registry hive")


def _split_autofix_registry_entries(registry_path: str) -> list[dict]:
    entries = []
    normalized_path = re.sub(
        r"\s+(?=(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|MACHINE|SOFTWARE)\\)",
        ";",
        str(registry_path or "").replace("\r", "\n"),
        flags=re.IGNORECASE,
    )
    for raw_entry in re.split(r"[;\n]+", normalized_path):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "!" in entry:
            path_part, value_name = entry.split("!", 1)
        else:
            last_slash = entry.rfind("\\")
            if last_slash == -1:
                raise ValueError("registry path missing value name")
            path_part = entry[:last_slash]
            value_name = entry[last_slash + 1:]
        if not value_name.strip():
            raise ValueError("registry value name is empty")
        entries.append({"path": path_part.strip(), "value_name": value_name.strip(), "raw": entry})
    if not entries:
        raise ValueError("registry path is empty")
    return entries


def _looks_like_sddl(value: str) -> bool:
    text = str(value or "").strip()
    return bool(re.match(r"^(O:|G:|D:|S:)[A-Za-z0-9:;()]+$", text))


def _convert_autofix_value(expected_value: str):
    import winreg

    value = str(expected_value or "").strip()
    lower = value.lower()
    if not value:
        raise ValueError("missing expected value")
    if _looks_like_sddl(value):
        return value, winreg.REG_SZ
    if "\n" in value or "\r" in value or ";" in value:
        raise ValueError("complex expected value")
    if lower.startswith(("enabled:", "disabled:")) or any(token in value for token in ("{", "}", "[", "]")):
        raise ValueError("structured expected value")
    if lower in ("enabled", "enable", "true", "yes", "on"):
        return 1, winreg.REG_DWORD
    if lower in ("disabled", "disable", "false", "no", "off"):
        return 0, winreg.REG_DWORD
    if lower in REGISTRY_VALUE_LABEL_MAP:
        return REGISTRY_VALUE_LABEL_MAP[lower], winreg.REG_DWORD
    if value.isdigit():
        return int(value), winreg.REG_DWORD
    return value, winreg.REG_SZ


def _normalize_audit_autofix_value(value: str):
    normalized = " ".join(str(value or "").strip().lower().split())
    mapping = {
        "success": ("enable", "disable", "Success"),
        "failure": ("disable", "enable", "Failure"),
        "success and failure": ("enable", "enable", "Success and Failure"),
        "success/failure": ("enable", "enable", "Success and Failure"),
        "success, failure": ("enable", "enable", "Success and Failure"),
        "no auditing": ("disable", "disable", "No Auditing"),
        "no audit": ("disable", "disable", "No Auditing"),
        "none": ("disable", "disable", "No Auditing"),
    }
    if normalized not in mapping:
        raise ValueError("unsupported audit policy value")
    return mapping[normalized]


def _read_audit_subcategory(subcategory: str) -> str:
    import subprocess

    proc = subprocess.run(
        ["auditpol.exe", "/get", f"/subcategory:{subcategory}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    for line in text.splitlines():
        if subcategory.lower() in line.lower():
            parts = line.rsplit("  ", 1)
            if len(parts) == 2:
                return parts[-1].strip()
    return text.strip()[:300]


def _apply_audit_policy_autofix(check: dict) -> dict:
    import subprocess

    subcategory = str(check.get("audit_subcategory") or "").strip()
    if not subcategory:
        raise ValueError("missing audit subcategory")
    success, failure, normalized = _normalize_audit_autofix_value(check.get("audit_value") or check.get("expected_value") or "")
    old_value = _read_audit_subcategory(subcategory)
    proc = subprocess.run(
        [
            "auditpol.exe",
            "/set",
            f"/subcategory:{subcategory}",
            f"/success:{success}",
            f"/failure:{failure}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "auditpol failed").strip())
    return {
        "old_value": old_value,
        "new_value": normalized,
        "audit_subcategory": subcategory,
    }


def _normalize_service_startup_value(value: str) -> str:
    normalized = " ".join(str(value or "").strip().lower().split())
    mapping = {
        "automatic": "Automatic",
        "auto": "Automatic",
        "manual": "Manual",
        "demand": "Manual",
        "disabled": "Disabled",
        "disable": "Disabled",
    }
    if normalized not in mapping:
        raise ValueError("unsupported service startup type")
    return mapping[normalized]


def _normalize_firewall_state_value(value: str) -> str:
    normalized = " ".join(str(value or "").strip().lower().split())
    mapping = {
        "on": "On",
        "enabled": "On",
        "enable": "On",
        "true": "On",
        "1": "On",
        "off": "Off",
        "disabled": "Off",
        "disable": "Off",
        "false": "Off",
        "0": "Off",
    }
    if normalized not in mapping:
        raise ValueError("unsupported firewall state")
    return mapping[normalized]


def _ps_single_quote(value: str) -> str:
    return "'" + str(value or "").replace("'", "''") + "'"


def _apply_service_startup_autofix(check: dict) -> dict:
    import subprocess

    service_name = str(check.get("service_name") or check.get("check_name") or "").strip()
    if not service_name:
        raise ValueError("missing service name")
    startup_type = _normalize_service_startup_value(check.get("startup_type") or check.get("expected_value") or "")
    quoted_service = _ps_single_quote(service_name)
    read_cmd = f"(Get-Service -Name {quoted_service} -ErrorAction Stop).StartType"
    read_proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", read_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if read_proc.returncode != 0:
        raise RuntimeError((read_proc.stderr or read_proc.stdout or "service not found").strip())
    old_value = (read_proc.stdout or "").strip()
    set_cmd = f"Set-Service -Name {quoted_service} -StartupType {startup_type} -ErrorAction Stop"
    set_proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", set_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if set_proc.returncode != 0:
        raise RuntimeError((set_proc.stderr or set_proc.stdout or "Set-Service failed").strip())
    return {
        "old_value": old_value,
        "new_value": startup_type,
        "service_name": service_name,
    }


def _apply_firewall_profile_autofix(check: dict) -> dict:
    import subprocess

    profile = str(check.get("firewall_profile") or "").strip().lower()
    profile_map = {
        "domain": "Domain",
        "private": "Private",
        "public": "Public",
    }
    if profile not in profile_map:
        raise ValueError("unsupported firewall profile")
    state = _normalize_firewall_state_value(check.get("firewall_state") or check.get("expected_value") or "")
    ps_profile = profile_map[profile]
    ps_enabled = "True" if state == "On" else "False"
    quoted_profile = _ps_single_quote(ps_profile)
    read_cmd = f"(Get-NetFirewallProfile -Profile {quoted_profile} -ErrorAction Stop).Enabled"
    read_proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", read_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if read_proc.returncode != 0:
        raise RuntimeError((read_proc.stderr or read_proc.stdout or "Get-NetFirewallProfile failed").strip())
    old_raw = (read_proc.stdout or "").strip().lower()
    old_value = "On" if old_raw == "true" else "Off" if old_raw == "false" else (read_proc.stdout or "").strip()
    set_cmd = f"Set-NetFirewallProfile -Profile {quoted_profile} -Enabled {ps_enabled} -ErrorAction Stop"
    set_proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", set_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if set_proc.returncode != 0:
        raise RuntimeError((set_proc.stderr or set_proc.stdout or "Set-NetFirewallProfile failed").strip())
    return {
        "old_value": old_value,
        "new_value": state,
        "firewall_profile": profile,
    }


def _read_text_best_effort(path: str) -> str:
    for encoding in ("utf-16", "utf-8-sig", "utf-8", "mbcs"):
        try:
            with open(path, "r", encoding=encoding, errors="replace") as handle:
                return handle.read()
        except Exception:
            continue
    with open(path, "r", errors="replace") as handle:
        return handle.read()


def _run_secedit_export(cfg_path: str) -> None:
    import subprocess

    proc = subprocess.run(
        ["secedit.exe", "/export", "/cfg", cfg_path, "/quiet"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "secedit export failed").strip())


def _run_secedit_configure(cfg_path: str, db_path: str, area: str = "") -> None:
    import subprocess

    command = ["secedit.exe", "/configure", "/db", db_path, "/cfg", cfg_path]
    if area:
        command.extend(["/areas", area])
    command.append("/quiet")
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "secedit configure failed").strip())


def _get_inf_value(text: str, section: str, key: str) -> str:
    current_section = ""
    target_section = section.strip().lower()
    target_key = key.strip().lower()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            continue
        if current_section == target_section and "=" in line:
            left, right = line.split("=", 1)
            if left.strip().lower() == target_key:
                return right.strip()
    return ""


def _set_inf_value(text: str, section: str, key: str, value: str) -> str:
    lines = text.splitlines()
    target_section = section.strip().lower()
    target_key = key.strip().lower()
    out = []
    in_section = False
    section_found = False
    key_written = False

    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_section and not key_written:
                out.append(f"{key} = {value}")
                key_written = True
            in_section = stripped[1:-1].strip().lower() == target_section
            section_found = section_found or in_section
            out.append(raw_line)
            continue
        if in_section and "=" in stripped and not stripped.startswith(";"):
            left, _right = stripped.split("=", 1)
            if left.strip().lower() == target_key:
                out.append(f"{key} = {value}")
                key_written = True
                continue
        out.append(raw_line)

    if section_found and in_section and not key_written:
        out.append(f"{key} = {value}")
    if not section_found:
        if out and out[-1].strip():
            out.append("")
        out.extend([f"[{section}]", f"{key} = {value}"])
    return "\r\n".join(out) + "\r\n"


def _minimal_secedit_inf(section: str, key: str, value: str) -> str:
    return "\r\n".join([
        "[Unicode]",
        "Unicode=yes",
        "",
        "[Version]",
        'signature="$CHICAGO$"',
        "Revision=1",
        "",
        f"[{section}]",
        f"{key} = {value}",
        "",
    ])


def _secedit_area_for_section(section: str) -> str:
    normalized = str(section or "").strip().lower()
    if normalized == "privilege rights":
        return "USER_RIGHTS"
    if normalized == "system access":
        return "SECURITYPOLICY"
    raise ValueError(f"unsupported secedit section: {section}")


def _normalize_inf_account_set(value: str) -> set[str]:
    return {
        item.strip().lower()
        for item in str(value or "").split(",")
        if item.strip()
    }


def _secedit_apply(section: str, key: str, value: str) -> dict:
    import tempfile
    import uuid

    if not key:
        raise ValueError("missing secedit key")
    temp_dir = tempfile.gettempdir()
    tag = uuid.uuid4().hex
    export_cfg = os.path.join(temp_dir, f"mse-export-{tag}.inf")
    apply_cfg = os.path.join(temp_dir, f"mse-apply-{tag}.inf")
    db_path = os.path.join(temp_dir, f"mse-{tag}.sdb")
    try:
        _run_secedit_export(export_cfg)
        original = _read_text_best_effort(export_cfg)
        old_value = _get_inf_value(original, section, key)
        updated = _minimal_secedit_inf(section, key, value)
        with open(apply_cfg, "w", encoding="utf-16") as handle:
            handle.write(updated)
        _run_secedit_configure(apply_cfg, db_path, _secedit_area_for_section(section))

        verify_cfg = os.path.join(temp_dir, f"mse-verify-{tag}.inf")
        _run_secedit_export(verify_cfg)
        verified = _get_inf_value(_read_text_best_effort(verify_cfg), section, key)
        if section.strip().lower() == "privilege rights":
            applied = _normalize_inf_account_set(verified)
            expected = _normalize_inf_account_set(value)
            if applied != expected:
                raise RuntimeError(
                    f"secedit verification failed for {key}: expected {value or '<empty>'}, "
                    f"got {verified or '<empty>'}"
                )
        elif str(verified).strip() != str(value).strip():
            raise RuntimeError(
                f"secedit verification failed for {key}: expected {value}, "
                f"got {verified or '<empty>'}"
            )
        return {"old_value": old_value, "new_value": value}
    finally:
        for path in (
            export_cfg,
            apply_cfg,
            locals().get("verify_cfg"),
            db_path,
            f"{db_path}.log",
        ):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass


def _normalize_security_policy_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("missing security policy value")
    if not re.fullmatch(r"-?\d+", text):
        raise ValueError("security policy value must be numeric")
    return text


NET_ACCOUNTS_POLICY_ARGS = {
    "MinimumPasswordLength": "/minpwlen",
    "MaximumPasswordAge": "/maxpwage",
    "MinimumPasswordAge": "/minpwage",
    "PasswordHistorySize": "/uniquepw",
    "LockoutDuration": "/lockoutduration",
    "LockoutBadCount": "/lockoutthreshold",
    "ResetLockoutCount": "/lockoutwindow",
}

NET_ACCOUNTS_OUTPUT_LABELS = {
    "MinimumPasswordLength": "Minimum password length",
    "MaximumPasswordAge": "Maximum password age",
    "MinimumPasswordAge": "Minimum password age",
    "PasswordHistorySize": "Length of password history maintained",
    "LockoutDuration": "Lockout duration",
    "LockoutBadCount": "Lockout threshold",
    "ResetLockoutCount": "Lockout observation window",
}


def _read_net_accounts() -> str:
    import subprocess

    proc = subprocess.run(
        ["net.exe", "accounts"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "net accounts failed").strip())
    return proc.stdout or ""


def _extract_net_accounts_value(output: str, key: str) -> str:
    label = NET_ACCOUNTS_OUTPUT_LABELS.get(key)
    if not label:
        return ""
    label_lower = label.lower()
    for line in str(output or "").splitlines():
        if label_lower not in line.lower() or ":" not in line:
            continue
        value = line.split(":", 1)[1].strip()
        if key in ("LockoutDuration", "ResetLockoutCount"):
            match = re.search(r"-?\d+", value)
            return match.group(0) if match else value
        if key == "LockoutBadCount" and value.lower() == "never":
            return "0"
        if key == "PasswordHistorySize" and value.lower() == "none":
            return "0"
        match = re.search(r"-?\d+", value)
        return match.group(0) if match else value
    return ""


def _apply_net_accounts_policy(key: str, value: str) -> dict:
    import subprocess

    arg_name = NET_ACCOUNTS_POLICY_ARGS.get(key)
    if not arg_name:
        raise ValueError("unsupported net accounts policy")
    current_accounts = _read_net_accounts()
    old_value = _extract_net_accounts_value(current_accounts, key)
    if key in ("LockoutDuration", "ResetLockoutCount"):
        current_threshold = _extract_net_accounts_value(current_accounts, "LockoutBadCount")
        if current_threshold in ("", "0"):
            raise ValueError("Account lockout threshold is Never/0; apply Account lockout threshold before duration/window")
    proc = subprocess.run(
        ["net.exe", "accounts", f"{arg_name}:{value}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "net accounts configure failed").strip())
    verify_value = _extract_net_accounts_value(_read_net_accounts(), key)
    if verify_value and verify_value != str(value):
        raise RuntimeError(f"net accounts did not apply {key}: expected {value}, got {verify_value}")
    return {"old_value": old_value, "new_value": value, "security_policy_tool": "net accounts"}


def _apply_security_policy_autofix(check: dict) -> dict:
    key = str(check.get("security_policy_key") or "").strip()
    value = _normalize_security_policy_value(check.get("security_policy_value") or check.get("expected_value") or "")
    if key in NET_ACCOUNTS_POLICY_ARGS:
        result = _apply_net_accounts_policy(key, value)
    else:
        result = _secedit_apply("System Access", key, value)
    result["security_policy_key"] = key
    return result


def _normalize_user_right_accounts(accounts) -> str:
    if accounts is None:
        return ""
    if isinstance(accounts, list):
        values = [str(item).strip() for item in accounts if str(item).strip()]
    else:
        raw = str(accounts or "").strip()
        values = [part.strip() for part in re.split(r"\s*(?:,|;|\|)\s*", raw) if part.strip()]
    for value in values:
        if not (value.startswith("*S-") or "\\" in value or value.isidentifier() or " " in value):
            raise ValueError(f"unsupported user-right account: {value}")
    return ",".join(values)


def _apply_user_rights_autofix(check: dict) -> dict:
    privilege = str(check.get("privilege_name") or "").strip()
    accounts = _normalize_user_right_accounts(check.get("privilege_accounts"))
    result = _secedit_apply("Privilege Rights", privilege, accounts)
    result["privilege_name"] = privilege
    result["privilege_accounts"] = accounts
    return result


def _autofix_check_order(check: dict) -> tuple[int, str]:
    if check.get("fix_mode") == "rollback" and check.get("fix_type") == "security_policy":
        key = check.get("security_policy_key") or ""
        if key == "LockoutDuration":
            return (0, str(check.get("check_id") or ""))
        if key == "ResetLockoutCount":
            return (1, str(check.get("check_id") or ""))
        if key == "LockoutBadCount":
            return (2, str(check.get("check_id") or ""))
    if check.get("fix_type") == "security_policy":
        key = check.get("security_policy_key") or ""
        if key == "LockoutBadCount":
            return (0, str(check.get("check_id") or ""))
        if key == "ResetLockoutCount":
            return (1, str(check.get("check_id") or ""))
        if key == "LockoutDuration":
            return (2, str(check.get("check_id") or ""))
    return (5, str(check.get("check_id") or ""))


def _parse_registry_old_values(old_value: str) -> dict[str, str]:
    values = {}
    for raw_part in str(old_value or "").split(" | "):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key.strip().lower()] = value.strip()
    return values


def _apply_registry_rollback(check: dict) -> dict:
    import winreg

    old_values = _parse_registry_old_values(check.get("old_value") or "")
    if not old_values:
        raise ValueError("missing registry old value")
    restored = []
    entries = check.get("registry_entries") if isinstance(check.get("registry_entries"), list) else None
    if not entries:
        entries = _split_autofix_registry_entries(check.get("registry_path") or "")
    for entry in entries:
        hive, hive_name, sub_path = _normalize_autofix_hive(entry["path"])
        full_name = f"{hive_name}\\{sub_path}!{entry['value_name']}"
        old_raw = old_values.get(full_name.lower())
        if old_raw is None:
            raise ValueError(f"missing rollback value for {full_name}")
        key = winreg.CreateKeyEx(hive, sub_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            if old_raw == "<missing>":
                try:
                    winreg.DeleteValue(key, entry["value_name"])
                except FileNotFoundError:
                    pass
                restored.append(f"{full_name}=<deleted>")
            else:
                value, value_type = _convert_autofix_value(old_raw)
                winreg.SetValueEx(key, entry["value_name"], 0, value_type, value)
                restored.append(f"{full_name}={old_raw}")
        finally:
            winreg.CloseKey(key)
    return {
        "old_value": check.get("new_value") or "",
        "new_value": " | ".join(restored),
    }


def _registry_entries_for_apply(check: dict) -> list[dict]:
    entries = check.get("registry_entries")
    if isinstance(entries, list) and entries:
        normalized = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("invalid registry entry")
            path = str(entry.get("path") or "").strip()
            value_name = str(entry.get("value_name") or "").strip()
            value = str(entry.get("value") if entry.get("value") is not None else "").strip()
            if not path or not value_name or value == "":
                raise ValueError("registry entry missing path, value name, or value")
            normalized.append({"path": path, "value_name": value_name, "value": value})
        return normalized
    value = str(check.get("expected_value") or "").strip()
    return [
        {**entry, "value": value}
        for entry in _split_autofix_registry_entries(check.get("registry_path") or "")
    ]


def _apply_registry_autofix(check: dict) -> dict:
    import winreg

    old_values = []
    new_values = []
    registry_path_parts = []
    for entry in _registry_entries_for_apply(check):
        new_value, value_type = _convert_autofix_value(entry.get("value") or "")
        hive, hive_name, sub_path = _normalize_autofix_hive(entry["path"])
        full_name = f"{hive_name}\\{sub_path}!{entry['value_name']}"
        registry_path_parts.append(full_name)
        key = winreg.CreateKeyEx(hive, sub_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            try:
                old_value, _old_type = winreg.QueryValueEx(key, entry["value_name"])
                old_values.append(f"{full_name}={old_value}")
            except FileNotFoundError:
                old_values.append(f"{full_name}=<missing>")
            winreg.SetValueEx(key, entry["value_name"], 0, value_type, new_value)
            new_values.append(f"{full_name}={new_value}")
        finally:
            winreg.CloseKey(key)
    return {
        "old_value": " | ".join(old_values),
        "new_value": " | ".join(new_values),
        "registry_path": "; ".join(registry_path_parts),
        "registry_entries": _registry_entries_for_apply(check),
    }


def run_autofix(job: dict):
    results = []
    checks = sorted(job.get("checks") or [], key=_autofix_check_order)
    for check in checks:
        check_id = check.get("check_id") or check.get("check_name") or "unknown"
        result = {
            "check_id": check_id,
            "check_name": check.get("check_name") or check_id,
            "status": "error",
            "registry_path": check.get("registry_path") or "",
            "fix_type": check.get("fix_type") or "registry",
            "old_value": "",
            "new_value": "",
            "error": "",
        }
        try:
            if check.get("fix_mode") == "rollback" and result["fix_type"] in ("registry", "registry_multi", "defender_registry"):
                rollback_result = _apply_registry_rollback(check)
                result.update(rollback_result)
                result["status"] = "done"
                results.append(result)
                continue

            if result["fix_type"] == "audit_policy":
                audit_result = _apply_audit_policy_autofix(check)
                result.update(audit_result)
                result["status"] = "done"
                results.append(result)
                continue
            if result["fix_type"] == "service_startup":
                service_result = _apply_service_startup_autofix(check)
                result.update(service_result)
                result["status"] = "done"
                results.append(result)
                continue
            if result["fix_type"] == "firewall_profile":
                firewall_result = _apply_firewall_profile_autofix(check)
                result.update(firewall_result)
                result["status"] = "done"
                results.append(result)
                continue
            if result["fix_type"] == "security_policy":
                policy_result = _apply_security_policy_autofix(check)
                result.update(policy_result)
                result["status"] = "done"
                results.append(result)
                continue
            if result["fix_type"] == "user_rights":
                rights_result = _apply_user_rights_autofix(check)
                result.update(rights_result)
                result["status"] = "done"
                results.append(result)
                continue

            registry_result = _apply_registry_autofix(check)
            result.update(registry_result)
            result["status"] = "done"
        except Exception as exc:
            result["error"] = str(exc)
        results.append(result)
    return {
        "autofix_results": results,
        "autofix_total": len(results),
        "autofix_success": sum(1 for item in results if item.get("status") == "done"),
        "autofix_failed": sum(1 for item in results if item.get("status") != "done"),
    }


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    cfg     = load_config()
    os_meta = detect_os_metadata()
    URL     = cfg["backend_url"].rstrip("/")
    HDR     = {
        "X-Agent-Token": cfg["agent_token"],
        "X-Agent-Hostname": socket.gethostname(),
        "X-Agent-Version": get_agent_runtime_version(),
        "X-Agent-Detected-Role": detect_role(),
        "X-Agent-IP-Addresses": ",".join(get_ipv4_addresses()),
        "X-Agent-OS-Name": os_meta.get("os_name", ""),
        "X-Agent-OS-Version": os_meta.get("os_version", ""),
        "X-Agent-OS-Build": os_meta.get("os_build", ""),
        "X-Agent-OS-Release": os_meta.get("os_release", ""),
        "X-Agent-OS-Family": os_meta.get("os_family", ""),
    }
    POLL    = int(cfg.get("poll_interval", 10))
    DATA    = cfg["data_path"]
    TIMEOUT = int(cfg.get("request_timeout", 300))

    print(f"[Agent] backend -> {URL}")
    print(f"[Agent] data    -> {DATA}")
    print(f"[Agent] poll    -> {POLL}s")
    print("[Agent] พร้อมรับงาน...")

    while True:
        try:
            poll_headers = {
                **HDR,
                "X-Agent-Detected-Role": detect_role(),
                "X-Agent-IP-Addresses": ",".join(get_ipv4_addresses()),
            }
            resp = requests.get(
                f"{URL}/agent/jobs/pending",
                headers=poll_headers,
                timeout=TIMEOUT,
            )

            if resp.status_code == 401:
                print("[Agent] Token ผิด กรุณาตรวจสอบ agent_config.json")
                time.sleep(POLL)
                continue

            jobs = resp.json().get("jobs", [])
            if jobs:
                try:
                    ensure_scanner_package(cfg, poll_headers, TIMEOUT)
                except Exception as e:
                    print(f"[Agent] scanner package update warning: {e}")

            for job in jobs:
                jid  = job["job_id"]
                ver  = job.get("version", "?")
                role = job.get("role", "-")
                job_type = job.get("job_type", "scan")
                print(f"[Agent] รับ job {jid}  version={ver}  role={role}")

                try:
                    if job_type in ("autofix", "rollback"):
                        score = 0
                        details = run_autofix(job)
                    else:
                        score, details = run_scan(job, DATA)
                    payload = {
                        "job_id":  jid,
                        "score":   score,
                        "details": details,
                        "error":   "",
                    }
                    print(f"[Agent] สแกนเสร็จ  score={score}  items={len(details)}")
                except Exception as e:
                    payload = {
                        "job_id":  jid,
                        "score":   0,
                        "details": {},
                        "error":   str(e),
                    }
                    print(f"[Agent] scan error: {e}")

                requests.post(
                    f"{URL}/agent/jobs/{jid}/result",
                    headers=poll_headers,
                    json=payload,
                    timeout=TIMEOUT,
                )

        except KeyboardInterrupt:
            print("[Agent] หยุดทำงาน")
            break
        except requests.exceptions.ConnectionError:
            print(f"[Agent] เชื่อมต่อ backend ไม่ได้ ลองใหม่ใน {POLL}s")
        except Exception as e:
            print(f"[Agent] error: {e}")

        try:
            time.sleep(POLL)
        except KeyboardInterrupt:
            print("[Agent] หยุดทำงาน")
            break


if __name__ == "__main__":
    main()
