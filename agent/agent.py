# agent.py
import json
import os
import sys
import time
import io
import socket
import requests

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    INTERNAL = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INTERNAL = BASE_DIR

sys.path.insert(0, INTERNAL)

CONFIG_PATH = os.path.join(BASE_DIR, "agent_config.json")

VALID_ROLES = {"Member Server", "Domain Controller"}
AGENT_VERSION = "1.0.0"


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
            "backend_url":      "http://BACKEND_IP:8001",
            "agent_token":      "ใส่ token ที่ได้จาก POST /agent/register",
            "poll_interval":    10,
            "request_timeout":  300,
            "data_path":        os.path.join(BASE_DIR, "data"),
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
        print(f"[Agent] สร้าง config ที่ {CONFIG_PATH}")
        print("[Agent] กรุณาแก้ไข config แล้วรันใหม่")
        sys.exit(1)

    with open(CONFIG_PATH, encoding="utf-8-sig") as f:
        return json.load(f)


def run_scan(job: dict, data_path: str):
    from scanner.security_scanner import SecurityScanner
    from scanner.baseline_config import load_checks

    version = job.get("version", "")

    # detect role
    detected_role = detect_role()
    raw_role      = str(job.get("role", detected_role)).strip()
    role          = raw_role if raw_role in VALID_ROLES else detected_role

    print(f"[Agent] detected={detected_role}  job_role={job.get('role', '-')}  final={role}")

    # โหลด checks จาก JSON
    checks = load_checks(version, role=role)
    print(f"[Agent] baseline={version}  role={role}  checks={len(checks)}")

    s = SecurityScanner(role=role)
    return s.run_baseline_scan(checks)


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    cfg     = load_config()
    os_meta = detect_os_metadata()
    URL     = cfg["backend_url"].rstrip("/")
    HDR     = {
        "X-Agent-Token": cfg["agent_token"],
        "X-Agent-Hostname": socket.gethostname(),
        "X-Agent-Version": AGENT_VERSION,
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

            for job in jobs:
                jid  = job["job_id"]
                ver  = job.get("version", "?")
                role = job.get("role", "-")
                print(f"[Agent] รับ job {jid}  version={ver}  role={role}")

                try:
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
