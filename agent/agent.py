# agent.py
import json
import os
import sys
import time
import io
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
    from scanner.baseline_config import load_configs, auto_detect_baseline

    version  = job.get("version", "")
    filename = os.path.basename(job.get("baseline_path", ""))

    # ── detect role จากเครื่อง, job override ได้ ─────────────────
    detected_role = detect_role()
    raw_role      = str(job.get("role", detected_role)).strip()
    role          = raw_role if raw_role in VALID_ROLES else detected_role

    print(f"[Agent] detected={detected_role}  job_role={job.get('role', '-')}  final={role}")

    # ── หา baseline config ────────────────────────────────────────
    configs = load_configs(data_path)

    if version and version in configs:
        baseline_cfg = configs[version]
    elif filename:
        matched = next(
            (c for c in configs.values() if c.filename == filename), None
        )
        if matched:
            baseline_cfg = matched
        else:
            fpath        = os.path.join(data_path, filename)
            baseline_cfg = auto_detect_baseline(fpath)
    else:
        baseline_cfg = next(iter(configs.values()))

    s = SecurityScanner(
        data_path       = data_path,
        baseline_config = baseline_cfg,
        role            = role,
    )
    s.target_file = os.path.join(data_path, baseline_cfg.filename)

    print(f"[Agent] baseline={baseline_cfg.version_id}  role={role}")
    return s.run_baseline_scan()


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    cfg     = load_config()
    URL     = cfg["backend_url"].rstrip("/")
    HDR     = {"X-Agent-Token": cfg["agent_token"]}
    POLL    = int(cfg.get("poll_interval", 10))
    DATA    = cfg["data_path"]
    TIMEOUT = int(cfg.get("request_timeout", 300))

    print(f"[Agent] backend -> {URL}")
    print(f"[Agent] data    -> {DATA}")
    print(f"[Agent] poll    -> {POLL}s")
    print("[Agent] พร้อมรับงาน...")

    while True:
        try:
            resp = requests.get(
                f"{URL}/agent/jobs/pending",
                headers=HDR,
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
                    headers=HDR,
                    json=payload,
                    timeout=TIMEOUT,
                )

        except requests.exceptions.ConnectionError:
            print(f"[Agent] เชื่อมต่อ backend ไม่ได้ ลองใหม่ใน {POLL}s")
        except Exception as e:
            print(f"[Agent] error: {e}")

        time.sleep(POLL)


if __name__ == "__main__":
    main()