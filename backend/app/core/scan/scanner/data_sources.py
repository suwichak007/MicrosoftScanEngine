import json
import os


def collect_environment_debug(scanner):
    try:
        scanner.debug.append(f"cwd={os.getcwd()}")
    except Exception as e:
        scanner.debug.append(f"cwd_error={e}")
    try:
        scanner.debug.append(f"whoami={os.getlogin()}")
    except Exception as e:
        scanner.debug.append(f"whoami_error={e}")
    try:
        scanner.debug.append(f"is_admin={scanner.is_admin()}")
    except Exception as e:
        scanner.debug.append(f"is_admin_error={e}")

    scanner.debug.append(f"python_exe={scanner.python_exe}")
    scanner.debug.append(f"secedit_path_exists={os.path.exists(scanner.SECEDIT)}")
    scanner.debug.append(f"auditpol_path_exists={os.path.exists(scanner.AUDITPOL)}")
    scanner.debug.append(f"powershell_path_exists={os.path.exists(scanner.POWERSHELL)}")


def export_security_policy(scanner):
    try:
        if os.path.exists(scanner.secedit_file):
            os.remove(scanner.secedit_file)
    except Exception:
        pass

    try:
        proc = scanner.executor.run_subprocess(
            [scanner.SECEDIT, "/export", "/cfg", scanner.secedit_file],
            capture_output=True,
            text=True,
            shell=False,
        )
        scanner.debug.append(f"SECEDIT rc={proc.returncode}")
        scanner.debug.append(f"SECEDIT stdout={proc.stdout[:300]}")
        scanner.debug.append(f"SECEDIT stderr={proc.stderr[:300]}")
        scanner.debug.append(f"SECEDIT file={scanner.secedit_file}")
        scanner.debug.append(f"SECEDIT file_exists={os.path.exists(scanner.secedit_file)}")
    except Exception as e:
        scanner.debug.append(f"SECEDIT exception={e}")
        return ""

    if not os.path.exists(scanner.secedit_file):
        return ""

    for enc in ("utf-16", "utf-8-sig", "cp1252", "latin-1"):
        try:
            with open(scanner.secedit_file, "r", encoding=enc, errors="replace") as f:
                data = f.read()
            scanner.debug.append(f"SECEDIT read_ok encoding={enc} len={len(data)}")
            scanner.debug.append(f"SECEDIT head={data[:500]}")
            return data
        except Exception as e:
            scanner.debug.append(f"SECEDIT read_fail encoding={enc} err={e}")
    return ""


def parse_security_data(scanner, security_data):
    parsed = {}
    for line in security_data.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        parsed[k.strip()] = v.strip()

    scanner.debug.append(f"SECEDIT parsed_count={len(parsed)}")
    scanner.debug.append(f"SECEDIT parsed_keys_sample={list(parsed.keys())[:20]}")
    scanner.debug.append(f"SECEDIT has_MinimumPasswordLength={'MinimumPasswordLength' in parsed}")
    scanner.debug.append(f"SECEDIT has_PasswordComplexity={'PasswordComplexity' in parsed}")
    scanner.debug.append(f"SECEDIT has_LockoutBadCount={'LockoutBadCount' in parsed}")
    scanner.debug.append(f"SECEDIT has_SeNetworkLogonRight={'SeNetworkLogonRight' in parsed}")
    return parsed


def export_audit_policy(scanner):
    try:
        proc = scanner.executor.run_subprocess(
            [scanner.AUDITPOL, "/get", "/category:*"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        scanner.debug.append(f"AUDIT rc={proc.returncode}")
        scanner.debug.append(f"AUDIT stdout={proc.stdout[:1000]}")
        scanner.debug.append(f"AUDIT stderr={proc.stderr[:300]}")
        return proc.stdout if proc.returncode == 0 else ""
    except Exception as e:
        scanner.debug.append(f"AUDIT exception={e}")
        return ""


def parse_audit_data(scanner, audit_text):
    import re

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

    scanner.debug.append(f"AUDIT parsed_count={len(mapping)}")
    scanner.debug.append(f"AUDIT parsed_keys_sample={list(mapping.keys())[:20]}")
    scanner.debug.append(f"AUDIT has_Logon={'Logon' in mapping}")
    scanner.debug.append(f"AUDIT value_Logon={mapping.get('Logon')}")
    return mapping


def load_mp_preference(scanner):
    try:
        cmd = "Get-MpPreference | ConvertTo-Json -Depth 4"
        proc = scanner.executor.run_subprocess(
            [scanner.POWERSHELL, "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        scanner.debug.append(f"MPPREF rc={proc.returncode}")
        scanner.debug.append(f"MPPREF stdout={proc.stdout[:600]}")
        scanner.debug.append(f"MPPREF stderr={proc.stderr[:300]}")
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        data = json.loads(proc.stdout)
        if isinstance(data, list):
            data = data[0] if data else {}
        scanner.debug.append(f"MPPREF keys_sample={list(data.keys())[:20]}")
        return data if isinstance(data, dict) else {}
    except Exception as e:
        scanner.debug.append(f"MPPREF exception={e}")
        return {}
