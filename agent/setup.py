"""
ScanAgentSetup.py
ดับเบิลคลิกเดียว — ติดตั้ง MicrosoftScanAgent อัตโนมัติ
agent.exe, nssm.exe และ data/ ถูก bundle ไว้ใน setup.exe แล้ว
"""
import ctypes
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request

# ── config (เปลี่ยนตรงนี้ก่อน build) ────────────────────────────
BACKEND_URL  = "http://192.168.105.11:8000"
AGENT_DIR    = r"C:\MicrosoftScanEngine"
SERVICE_NAME = "MicrosoftScanAgent"
# ─────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate():
    script = sys.executable if getattr(sys, "frozen", False) else __file__
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}"', None, 1
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


def register_agent() -> tuple[str, str]:
    hostname = socket.gethostname()
    url = f"{BACKEND_URL}/agent/register?hostname={hostname}"
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    return data["agent_id"], data["token"]


def stop_existing_service():
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True)


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

    # ── 2. Register ────────────────────────────────────────────
    log("[2/5] ลงทะเบียนกับ backend...")
    try:
        agent_id, token = register_agent()
        log(f"      agent_id = {agent_id}")
    except Exception as e:
        log(f"[ERROR] ลงทะเบียนไม่ได้: {e}")
        input("กด Enter เพื่อปิด...")
        sys.exit(1)

    # ── 3. สร้าง config ────────────────────────────────────────
    log("[3/5] สร้าง agent_config.json...")
    config = {
        "backend_url":   BACKEND_URL,
        "agent_token":   token,
        "poll_interval": 10,
        "data_path":     os.path.join(AGENT_DIR, "data"),
    }
    with open(os.path.join(AGENT_DIR, "agent_config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # ── 4. copy ไฟล์จาก bundle ────────────────────────────────
    log("[4/5] ติดตั้งไฟล์...")

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
    stop_existing_service()
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