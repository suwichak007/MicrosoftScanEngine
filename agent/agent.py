# agent.py
import json
import os
import sys
import time
import io
import requests

# ── path handling (ปกติ vs exe) ───────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    INTERNAL = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INTERNAL = BASE_DIR

sys.path.insert(0, INTERNAL)

CONFIG_PATH = os.path.join(BASE_DIR, "agent_config.json")


# ── config ────────────────────────────────────────────────────────
def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        default = {
            "backend_url":   "http://BACKEND_IP:8000",
            "agent_token":   "ใส่ token ที่ได้จาก POST /agent/register",
            "poll_interval": 10,
            "data_path":     os.path.join(BASE_DIR, "data"),
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
        print(f"[Agent] สร้าง config ที่ {CONFIG_PATH}")
        print("[Agent] กรุณาแก้ไข config แล้วรันใหม่")
        sys.exit(1)

    with open(CONFIG_PATH, encoding="utf-8-sig") as f:  
        return json.load(f)


# ── scan ──────────────────────────────────────────────────────────
BASELINE_FILE_MAP = {
    "Windows 11 v24H2": "MS Security Baseline Windows 11 v24H2.xlsx",
    "Windows 11 v25H2": "MS Security Baseline Windows 11 v25H2.xlsx",
}


def run_scan(job: dict, data_path: str):
    from scanner.security_scanner import SecurityScanner

    s = SecurityScanner(data_path=data_path)

    if "baseline_path" in job:
        # backend ส่ง path มาตรงๆ (กรณี path ตรงกัน)
        filename = os.path.basename(job["baseline_path"])
        s.target_file = os.path.join(data_path, filename)
    else:
        version  = job.get("version", "Windows 11 v24H2")
        filename = BASELINE_FILE_MAP.get(version, BASELINE_FILE_MAP["Windows 11 v24H2"])
        s.target_file = os.path.join(data_path, filename)

    return s.run_baseline_scan()


# ── main loop ─────────────────────────────────────────────────────
def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    cfg  = load_config()
    URL  = cfg["backend_url"].rstrip("/")
    HDR  = {"X-Agent-Token": cfg["agent_token"]}
    POLL = int(cfg.get("poll_interval", 10))
    DATA = cfg["data_path"]
    TIMEOUT = int(cfg.get("request_timeout", 300))  # ← เพิ่ม

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
                jid = job["job_id"]
                ver = job.get("version", "?")
                print(f"[Agent] รับ job {jid}  version={ver}")

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