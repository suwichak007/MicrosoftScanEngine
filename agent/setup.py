"""
ScanAgentSetup.py
ดับเบิลคลิกเดียว — ติดตั้ง MicrosoftScanAgent อัตโนมัติ
agent.exe, nssm.exe และ data/ ถูก bundle ไว้ใน setup.exe แล้ว
"""
import ctypes
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.parse

# ── config (เปลี่ยนตรงนี้ก่อน build) ────────────────────────────
AGENT_DIR    = r"C:\MicrosoftScanEngine"
SERVICE_NAME = "MicrosoftScanAgent"
# ─────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate():
    args = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = args
    else:
        target = sys.executable
        params = f'"{__file__}" {args}'.strip()
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", target, params, None, 1
    )
    sys.exit(0)


def log(msg: str):
    print(msg)


def get_bundled(path: str) -> str:
    """คืน path ของไฟล์/โฟลเดอร์ที่ bundle ไว้ใน exe"""
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, path)


def parse_args():
    parser = argparse.ArgumentParser(description="Install MicrosoftScanAgent")
    parser.add_argument("--backend-url", required=True, help="Backend URL, e.g. http://SERVER:8000")
    parser.add_argument("--install-token", required=True, help="Shared install token from backend")
    return parser.parse_args()


def register_agent(backend_url: str, install_token: str) -> tuple[str, str]:
    hostname = socket.gethostname()
    query = urllib.parse.urlencode({
        "hostname": hostname,
        "install_token": install_token,
    })
    url = f"{backend_url.rstrip('/')}/agent/register?{query}"
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    return data["agent_id"], data["token"]


def _service_state() -> str:
    proc = subprocess.run(
        ["sc", "query", SERVICE_NAME],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        return "NOT_FOUND"
    for line in proc.stdout.splitlines():
        if "STATE" in line:
            return line.strip()
    return "UNKNOWN"


def stop_existing_service(timeout: int = 30):
    state = _service_state()
    if state == "NOT_FOUND":
        return

    log("      stopping existing service...")
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)

    deadline = time.time() + timeout
    while time.time() < deadline:
        state = _service_state()
        if state == "NOT_FOUND" or "STOPPED" in state:
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"Service {SERVICE_NAME} did not stop within {timeout}s")

    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True)
    time.sleep(2)


def install_service(nssm: str, exe: str):
    cmds = [
        [nssm, "install",  SERVICE_NAME, exe],
        [nssm, "set", SERVICE_NAME, "AppDirectory",   AGENT_DIR],
        [nssm, "set", SERVICE_NAME, "AppStdout",      os.path.join(AGENT_DIR, "agent.log")],
        [nssm, "set", SERVICE_NAME, "AppStderr",      os.path.join(AGENT_DIR, "agent_err.log")],
        [nssm, "set", SERVICE_NAME, "AppRotateFiles", "1"],
        [nssm, "set", SERVICE_NAME, "AppRotateBytes", "10485760"],
        [nssm, "set", SERVICE_NAME, "Start",          "SERVICE_AUTO_START"],
        [nssm, "start", SERVICE_NAME],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)


def main():
    args = parse_args()
    backend_url = args.backend_url.rstrip("/")

    # ── 0. ตรวจสิทธิ์ ──────────────────────────────────────────
    if not is_admin():
        log("[Setup] ขอสิทธิ์ Administrator...")
        elevate()
        return

    print("=" * 50)
    print("  MicrosoftScanAgent Setup")
    print("=" * 50)

    # ── 1. สร้างโฟลเดอร์ ───────────────────────────────────────
    log("[1/5] สร้างโฟลเดอร์...")
    os.makedirs(AGENT_DIR, exist_ok=True)
    os.makedirs(os.path.join(AGENT_DIR, "data"), exist_ok=True)
    os.makedirs(os.path.join(AGENT_DIR, "packages"), exist_ok=True)

    # ── 2. Register ────────────────────────────────────────────
    log("[2/5] ลงทะเบียนกับ backend...")
    try:
        agent_id, token = register_agent(backend_url, args.install_token)
        log(f"      agent_id = {agent_id}")
    except Exception as e:
        log(f"[ERROR] ลงทะเบียนไม่ได้: {e}")
        input("กด Enter เพื่อปิด...")
        sys.exit(1)

    # ── 3. สร้าง config ────────────────────────────────────────
    log("[3/5] สร้าง agent_config.json...")
    config = {
        "backend_url":   backend_url,
        "agent_token":   token,
        "poll_interval": 10,
        "data_path":     os.path.join(AGENT_DIR, "data"),
        "package_path":  os.path.join(AGENT_DIR, "packages"),
        "scanner_auto_update": True,
    }
    with open(os.path.join(AGENT_DIR, "agent_config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # ── 4. copy ไฟล์จาก bundle ────────────────────────────────
    log("[4/5] ติดตั้งไฟล์...")
    stop_existing_service()

    # copy exe และ nssm
    for filename in ["MicrosoftScanAgent.exe", "nssm.exe"]:
        src = get_bundled(filename)
        dst = os.path.join(AGENT_DIR, filename)
        log(f"      {filename}")
        shutil.copy2(src, dst)

    # copy ทั้งโฟลเดอร์ data/ (ไม่ hard code ชื่อไฟล์)
    src_data = get_bundled("data")
    dst_data = os.path.join(AGENT_DIR, "data")
    log(f"      data/ ({len(os.listdir(src_data))} ไฟล์)")
    for filename in os.listdir(src_data):
        shutil.copy2(
            os.path.join(src_data, filename),
            os.path.join(dst_data, filename)
        )

    # ── 5. ติดตั้ง service ─────────────────────────────────────
    log("[5/5] ติดตั้ง Windows Service...")
    nssm = os.path.join(AGENT_DIR, "nssm.exe")
    exe  = os.path.join(AGENT_DIR, "MicrosoftScanAgent.exe")
    install_service(nssm, exe)

    print()
    print("=" * 50)
    print("  ติดตั้งเสร็จเรียบร้อย!")
    print(f"  Agent ID : {agent_id}")
    print(f"  Log      : {AGENT_DIR}\\agent.log")
    print("=" * 50)
    input("กด Enter เพื่อปิด...")


if __name__ == "__main__":
    main()
