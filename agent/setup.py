import argparse
import ctypes
import json
import os
from queue import Empty, Queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:
    tk = None
    messagebox = None
    ttk = None

try:
    import customtkinter as ctk
except Exception:
    ctk = None


AGENT_DIR = r"C:\MicrosoftScanEngine"
SERVICE_NAME = "MicrosoftScanAgent"
DEFAULT_BACKEND_URL = "http://192.168.105.11:8000"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run_hidden(command: list[str]) -> subprocess.CompletedProcess:
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        startupinfo.wShowWindow = 0
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
        startupinfo=startupinfo,
    )


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def log(message: str):
    print(message)


def bundled_path(relative_path: str) -> str:
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


def parse_args():
    parser = argparse.ArgumentParser(description="Install MicrosoftScanAgent")
    parser.add_argument("--backend-url", default="", help="Backend URL, e.g. http://SERVER:8000")
    parser.add_argument("--gui", action="store_true", help="Open the graphical installer")
    parser.add_argument("--auto-start", action="store_true", help="Start GUI installation automatically")
    return parser.parse_args()


def elevate(extra_args: list[str] | None = None):
    if extra_args is None:
        extra_args = sys.argv[1:]

    params = " ".join(f'"{arg}"' for arg in extra_args)
    if getattr(sys, "frozen", False):
        target = sys.executable
    else:
        target = sys.executable
        params = f'"{__file__}" {params}'.strip()

    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)
    sys.exit(0)


def register_agent(backend_url: str) -> tuple[str, str]:
    hostname = socket.gethostname()
    query = urllib.parse.urlencode({"hostname": hostname})
    url = f"{backend_url.rstrip('/')}/agent/register?{query}"
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.loads(response.read())
    return data["agent_id"], data["token"]


def service_state() -> str:
    proc = run_hidden(["sc", "query", SERVICE_NAME])
    if proc.returncode != 0:
        return "NOT_FOUND"
    for line in proc.stdout.splitlines():
        if "STATE" in line:
            return line.strip()
    return "UNKNOWN"


def stop_existing_service(timeout: int = 30):
    state = service_state()
    if state == "NOT_FOUND":
        return

    run_hidden(["sc", "stop", SERVICE_NAME])
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = service_state()
        if state == "NOT_FOUND" or "STOPPED" in state:
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"Service {SERVICE_NAME} did not stop within {timeout}s")

    run_hidden(["sc", "delete", SERVICE_NAME])
    time.sleep(2)


def install_service(nssm_path: str, agent_exe: str):
    commands = [
        [nssm_path, "install", SERVICE_NAME, agent_exe],
        [nssm_path, "set", SERVICE_NAME, "AppDirectory", AGENT_DIR],
        [nssm_path, "set", SERVICE_NAME, "AppStdout", os.path.join(AGENT_DIR, "agent.log")],
        [nssm_path, "set", SERVICE_NAME, "AppStderr", os.path.join(AGENT_DIR, "agent_err.log")],
        [nssm_path, "set", SERVICE_NAME, "AppRotateFiles", "1"],
        [nssm_path, "set", SERVICE_NAME, "AppRotateBytes", "10485760"],
        [nssm_path, "set", SERVICE_NAME, "Start", "SERVICE_AUTO_START"],
        [nssm_path, "start", SERVICE_NAME],
    ]
    for command in commands:
        run_hidden(command)


def install_agent(backend_url: str, progress=log) -> tuple[str, str]:
    backend_url = backend_url.rstrip("/")
    if not backend_url:
        raise ValueError("Backend URL is required")

    progress("=" * 50)
    progress("  MicrosoftScanAgent Setup")
    progress("=" * 50)

    progress("[1/5] Create folders...")
    os.makedirs(AGENT_DIR, exist_ok=True)
    os.makedirs(os.path.join(AGENT_DIR, "data"), exist_ok=True)
    os.makedirs(os.path.join(AGENT_DIR, "packages"), exist_ok=True)

    progress("[2/5] Register with backend...")
    agent_id, token = register_agent(backend_url)
    progress(f"      agent_id = {agent_id}")

    progress("[3/5] Create agent_config.json...")
    config = {
        "backend_url": backend_url,
        "agent_token": token,
        "poll_interval": 10,
        "data_path": os.path.join(AGENT_DIR, "data"),
        "package_path": os.path.join(AGENT_DIR, "packages"),
        "scanner_auto_update": True,
    }
    with open(os.path.join(AGENT_DIR, "agent_config.json"), "w", encoding="utf-8") as config_file:
        json.dump(config, config_file, indent=2, ensure_ascii=False)

    progress("[4/5] Install files...")
    stop_existing_service()

    for filename in ["MicrosoftScanAgent.exe", "nssm.exe"]:
        source = bundled_path(filename)
        destination = os.path.join(AGENT_DIR, filename)
        progress(f"      {filename}")
        shutil.copy2(source, destination)
        if os.path.getsize(source) != os.path.getsize(destination):
            raise RuntimeError(f"Installed file verification failed: {destination}")

    source_data = bundled_path("data")
    destination_data = os.path.join(AGENT_DIR, "data")
    files = os.listdir(source_data) if os.path.isdir(source_data) else []
    progress(f"      data/ ({len(files)} files)")
    for filename in files:
        shutil.copy2(os.path.join(source_data, filename), os.path.join(destination_data, filename))

    progress("[5/5] Install Windows Service...")
    nssm_path = os.path.join(AGENT_DIR, "nssm.exe")
    agent_exe = os.path.join(AGENT_DIR, "MicrosoftScanAgent.exe")
    progress(f"      service exe = {agent_exe}")
    install_service(nssm_path, agent_exe)

    log_path = os.path.join(AGENT_DIR, "agent.log")
    progress("")
    progress("=" * 50)
    progress("  Install complete!")
    progress(f"  Agent ID : {agent_id}")
    progress(f"  Log      : {log_path}")
    progress("=" * 50)
    return agent_id, log_path


def run_gui(initial_backend_url: str = "", auto_start: bool = False):
    if tk is None:
        raise RuntimeError("tkinter is not available in this build")

    root = tk.Tk()
    root.title("MicrosoftScanAgent Setup")
    root.geometry("860x620")
    root.minsize(800, 580)
    root.configure(bg="#f5f0e8")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(
        "Accent.Horizontal.TProgressbar",
        troughcolor="#ede7d9",
        background="#c8813a",
        bordercolor="#ede7d9",
        lightcolor="#c8813a",
        darkcolor="#c8813a",
    )

    events = Queue()
    backend_var = tk.StringVar(value=(initial_backend_url or DEFAULT_BACKEND_URL).rstrip("/"))
    status_var = tk.StringVar(value="Ready")
    step_var = tk.StringVar(value="Not started")
    progress_var = tk.IntVar(value=0)

    colors = {
        "shell": "#f5f0e8",
        "paper": "#faf7f2",
        "panel": "#2b2318",
        "panel_soft": "#3a3024",
        "card": "#faf7f2",
        "border": "#e6deca",
        "text": "#2b2318",
        "muted": "#5a4f3f",
        "faint": "#9a8f7e",
        "accent": "#c8813a",
        "accent_dark": "#a96a2b",
        "accent_pale": "#f2e4d0",
        "success": "#5a8a5e",
        "danger": "#b5483a",
        "log": "#1f1a14",
        "log_text": "#f5f0e8",
    }

    shell = tk.Frame(root, bg=colors["shell"])
    shell.pack(fill="both", expand=True)

    side = tk.Frame(shell, bg=colors["panel"], width=252)
    side.pack(side="left", fill="y")
    side.pack_propagate(False)

    logo_row = tk.Frame(side, bg=colors["panel"], padx=22, pady=24)
    logo_row.pack(fill="x")
    logo = tk.Frame(logo_row, bg=colors["accent"], width=46, height=46)
    logo.pack(anchor="w")
    logo.pack_propagate(False)
    tk.Label(logo, text="MS", bg=colors["accent"], fg="white", font=("Segoe UI", 12, "bold")).pack(expand=True)

    tk.Label(
        side,
        text="Microsoft\nScanAgent",
        bg=colors["panel"],
        fg=colors["shell"],
        font=("Georgia", 24, "bold"),
        justify="left",
        padx=22,
    ).pack(anchor="w")
    tk.Label(
        side,
        text="Security baseline scanning\nfor managed Windows hosts.",
        bg=colors["panel"],
        fg="#c4b9a8",
        font=("Segoe UI", 10),
        justify="left",
        padx=22,
        pady=12,
    ).pack(anchor="w")

    feature_box = tk.Frame(side, bg=colors["panel"], padx=22, pady=10)
    feature_box.pack(fill="x")
    for label, feature in [("01", "No install token"), ("02", "Windows service"), ("03", "Scanner auto-update")]:
        row = tk.Frame(feature_box, bg=colors["panel_soft"], padx=10, pady=8)
        row.pack(fill="x", pady=5)
        tk.Label(row, text=label, bg=colors["panel_soft"], fg=colors["accent"], font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(row, text=feature, bg=colors["panel_soft"], fg=colors["shell"], font=("Segoe UI", 9)).pack(side="left", padx=(10, 0))

    tk.Label(
        side,
        text=f"Install path\n{AGENT_DIR}",
        bg=colors["panel"],
        fg="#9a8f7e",
        font=("Segoe UI", 9),
        justify="left",
        padx=22,
        pady=22,
    ).pack(side="bottom", anchor="w")

    main = tk.Frame(shell, bg=colors["shell"], padx=24, pady=22)
    main.pack(side="left", fill="both", expand=True)

    header = tk.Frame(main, bg=colors["shell"])
    header.pack(fill="x")
    tk.Label(
        header,
        text="Agent Setup",
        bg=colors["shell"],
        fg=colors["text"],
        font=("Georgia", 24, "bold"),
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Connect this machine to the scanner backend and install the background service.",
        bg=colors["shell"],
        fg=colors["faint"],
        font=("Segoe UI", 10),
    ).pack(anchor="w", pady=(4, 16))

    card = tk.Frame(main, bg=colors["card"], highlightbackground=colors["border"], highlightthickness=1, padx=18, pady=16)
    card.pack(fill="x")

    top_meta = tk.Frame(card, bg=colors["card"])
    top_meta.pack(fill="x", pady=(0, 12))
    tk.Label(
        top_meta,
        text="Managed endpoint installation",
        bg=colors["card"],
        fg=colors["text"],
        font=("Segoe UI", 11, "bold"),
    ).pack(side="left")
    tk.Label(
        top_meta,
        text="Ready",
        bg=colors["accent_pale"],
        fg=colors["accent"],
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=4,
    ).pack(side="right")

    tk.Label(card, text="Backend URL", bg=colors["card"], fg=colors["text"], font=("Segoe UI", 10, "bold")).pack(anchor="w")
    entry_wrap = tk.Frame(card, bg="#fffdf9", highlightbackground=colors["border"], highlightthickness=1)
    entry_wrap.pack(fill="x", pady=(7, 12))
    backend_entry = tk.Entry(
        entry_wrap,
        textvariable=backend_var,
        font=("Segoe UI", 10),
        bg="#fffdf9",
        fg=colors["text"],
        relief="flat",
        insertbackground=colors["text"],
    )
    backend_entry.pack(fill="x", padx=11, pady=9)

    status_row = tk.Frame(card, bg=colors["card"])
    status_row.pack(fill="x", pady=(0, 8))
    tk.Label(status_row, textvariable=step_var, bg=colors["card"], fg=colors["muted"], font=("Segoe UI", 9, "bold")).pack(side="left")
    tk.Label(status_row, textvariable=status_var, bg=colors["card"], fg=colors["muted"], font=("Segoe UI", 9)).pack(side="right")

    progress_bar = ttk.Progressbar(
        card,
        mode="determinate",
        maximum=100,
        variable=progress_var,
        style="Accent.Horizontal.TProgressbar",
    )
    progress_bar.pack(fill="x")

    log_header = tk.Frame(main, bg=colors["shell"])
    log_header.pack(fill="x", pady=(18, 8))
    tk.Label(log_header, text="Install activity", bg=colors["shell"], fg=colors["text"], font=("Segoe UI", 11, "bold")).pack(side="left")
    tk.Label(log_header, text="Windows may request Administrator permission.", bg=colors["shell"], fg=colors["faint"], font=("Segoe UI", 9)).pack(side="right")

    log_frame = tk.Frame(main, bg=colors["log"], highlightbackground="#3a3024", highlightthickness=1)
    log_frame.pack(fill="both", expand=True)
    log_box = tk.Text(
        log_frame,
        height=13,
        font=("Consolas", 9),
        wrap="word",
        bg=colors["log"],
        fg=colors["log_text"],
        insertbackground=colors["log_text"],
        relief="flat",
        padx=12,
        pady=10,
    )
    log_box.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(log_frame, command=log_box.yview)
    scroll.pack(side="right", fill="y")
    log_box.configure(yscrollcommand=scroll.set)
    log_box.configure(state="disabled")

    footer = tk.Frame(main, bg=colors["shell"])
    footer.pack(fill="x", pady=(16, 0))

    def append_log(message: str):
        events.put(("log", message))

    def set_running(running: bool):
        install_button.configure(state="disabled" if running else "normal")
        install_button.configure(bg="#88a89d" if running else colors["accent"])
        backend_entry.configure(state="disabled" if running else "normal")
        root.configure(cursor="watch" if running else "")

    def install_clicked():
        backend_url = backend_var.get().strip().rstrip("/")
        if not backend_url:
            messagebox.showerror("Backend URL required", "Please enter the backend URL.")
            return

        if not is_admin():
            status_var.set("Requesting Administrator permission...")
            step_var.set("Elevation required")
            elevate(["--gui", "--auto-start", "--backend-url", backend_url])
            root.destroy()
            return

        set_running(True)
        status_var.set("Installing...")
        step_var.set("Starting")
        progress_var.set(5)

        def worker():
            try:
                agent_id, log_path = install_agent(backend_url, append_log)
                events.put(("done", agent_id, log_path))
            except Exception as exc:
                events.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    close_button = tk.Button(
        footer,
        text="Close",
        command=root.destroy,
        bg=colors["paper"],
        fg=colors["text"],
        activebackground=colors["accent_pale"],
        activeforeground=colors["text"],
        bd=0,
        highlightbackground=colors["border"],
        highlightthickness=1,
        font=("Segoe UI", 10),
        padx=18,
        pady=9,
        cursor="hand2",
    )
    close_button.pack(side="right")
    install_button = tk.Button(
        footer,
        text="Install Agent",
        command=install_clicked,
        bg=colors["accent"],
        fg="#ffffff",
        activebackground=colors["accent_dark"],
        activeforeground="#ffffff",
        disabledforeground="#f5f7f8",
        bd=0,
        font=("Segoe UI", 10, "bold"),
        padx=22,
        pady=10,
        cursor="hand2",
    )
    install_button.pack(side="right")
    tk.Frame(footer, bg=colors["shell"], width=10).pack(side="right")

    def update_step_from_message(message: str):
        if message.startswith("[1/5]"):
            step_var.set("Step 1 of 5")
            progress_var.set(10)
        elif message.startswith("[2/5]"):
            step_var.set("Step 2 of 5")
            progress_var.set(30)
        elif message.startswith("[3/5]"):
            step_var.set("Step 3 of 5")
            progress_var.set(50)
        elif message.startswith("[4/5]"):
            step_var.set("Step 4 of 5")
            progress_var.set(70)
        elif message.startswith("[5/5]"):
            step_var.set("Step 5 of 5")
            progress_var.set(88)

    def pump_events():
        try:
            while True:
                event = events.get_nowait()
                if event[0] == "log":
                    update_step_from_message(event[1])
                    log_box.configure(state="normal")
                    log_box.insert("end", event[1] + "\n")
                    log_box.see("end")
                    log_box.configure(state="disabled")
                    status_var.set(event[1])
                elif event[0] == "done":
                    _kind, agent_id, log_path = event
                    status_var.set(f"Installed: {agent_id}")
                    step_var.set("Complete")
                    progress_var.set(100)
                    set_running(False)
                    messagebox.showinfo("Install complete", f"Agent ID: {agent_id}\nLog: {log_path}")
                elif event[0] == "error":
                    status_var.set("Install failed")
                    step_var.set("Failed")
                    set_running(False)
                    messagebox.showerror("Install failed", event[1])
        except Empty:
            pass
        root.after(100, pump_events)

    root.after(100, pump_events)
    if auto_start:
        root.after(300, install_clicked)
    root.mainloop()


def run_modern_gui(initial_backend_url: str = "", auto_start: bool = False):
    if tk is None or ctk is None:
        raise RuntimeError("The graphical installer dependencies are not available in this build")

    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")

    colors = {
        "shell": "#f5f0e8",
        "paper": "#faf7f2",
        "card": "#fffdf9",
        "ink": "#2b2318",
        "ink_soft": "#3a3024",
        "muted": "#5a4f3f",
        "faint": "#9a8f7e",
        "border": "#e6deca",
        "amber": "#c8813a",
        "amber_dark": "#a96a2b",
        "amber_pale": "#f2e4d0",
        "green": "#5a8a5e",
        "red": "#b5483a",
        "log": "#1f1a14",
    }

    root = ctk.CTk(fg_color=colors["shell"])
    root.title("MicrosoftScanAgent Setup")
    root.geometry("920x650")
    root.minsize(860, 610)

    events = Queue()
    backend_var = tk.StringVar(master=root, value=(initial_backend_url or DEFAULT_BACKEND_URL).rstrip("/"))
    status_var = tk.StringVar(master=root, value="Ready")
    step_var = tk.StringVar(master=root, value="Ready to install")

    shell = ctk.CTkFrame(root, fg_color=colors["shell"], corner_radius=0)
    shell.pack(fill="both", expand=True)
    shell.grid_columnconfigure(1, weight=1)
    shell.grid_rowconfigure(0, weight=1)

    side = ctk.CTkFrame(shell, fg_color=colors["ink"], corner_radius=0, width=270)
    side.grid(row=0, column=0, sticky="nsew")
    side.grid_propagate(False)

    logo = ctk.CTkFrame(side, fg_color=colors["amber"], corner_radius=16, width=54, height=54)
    logo.grid(row=0, column=0, padx=28, pady=(32, 22), sticky="w")
    logo.grid_propagate(False)
    ctk.CTkLabel(logo, text="MS", text_color="#ffffff", font=("Segoe UI", 14, "bold")).place(relx=0.5, rely=0.5, anchor="center")

    ctk.CTkLabel(
        side,
        text="Microsoft\nScanAgent",
        text_color=colors["shell"],
        font=("Georgia", 29, "bold"),
        justify="left",
    ).grid(row=1, column=0, padx=28, sticky="w")
    ctk.CTkLabel(
        side,
        text="Enroll this Windows host into\nthe security baseline scanner.",
        text_color="#c4b9a8",
        font=("Segoe UI", 11),
        justify="left",
    ).grid(row=2, column=0, padx=28, pady=(12, 28), sticky="w")

    step_stack = ctk.CTkFrame(side, fg_color="transparent")
    step_stack.grid(row=3, column=0, padx=20, sticky="ew")
    for number, title, hint in [
        ("01", "Connect", "Use backend URL"),
        ("02", "Register", "Create agent identity"),
        ("03", "Install", "Run as service"),
    ]:
        item = ctk.CTkFrame(step_stack, fg_color=colors["ink_soft"], corner_radius=14)
        item.pack(fill="x", pady=6)
        ctk.CTkLabel(
            item,
            text=number,
            width=38,
            height=34,
            corner_radius=12,
            fg_color=colors["amber"],
            text_color="#ffffff",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(12, 10), pady=10)
        text_box = ctk.CTkFrame(item, fg_color="transparent")
        text_box.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(text_box, text=title, text_color=colors["shell"], font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ctk.CTkLabel(text_box, text=hint, text_color="#c4b9a8", font=("Segoe UI", 9)).pack(anchor="w")

    side.grid_rowconfigure(4, weight=1)
    ctk.CTkLabel(
        side,
        text=f"Install path\n{AGENT_DIR}",
        text_color=colors["faint"],
        font=("Segoe UI", 9),
        justify="left",
    ).grid(row=5, column=0, padx=28, pady=30, sticky="sw")

    main = ctk.CTkFrame(shell, fg_color=colors["shell"], corner_radius=0)
    main.grid(row=0, column=1, sticky="nsew", padx=30, pady=28)
    main.grid_columnconfigure(0, weight=1)
    main.grid_rowconfigure(3, weight=1)

    header = ctk.CTkFrame(main, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew")
    ctk.CTkLabel(header, text="Agent Setup", text_color=colors["ink"], font=("Georgia", 32, "bold")).pack(anchor="w")
    ctk.CTkLabel(
        header,
        text="A cleaner one-click installer for managed security scanning.",
        text_color=colors["faint"],
        font=("Segoe UI", 11),
    ).pack(anchor="w", pady=(4, 18))

    connect_card = ctk.CTkFrame(
        main,
        fg_color=colors["card"],
        corner_radius=22,
        border_width=1,
        border_color=colors["border"],
    )
    connect_card.grid(row=1, column=0, sticky="ew", pady=(0, 16))
    connect_card.grid_columnconfigure(0, weight=1)

    card_head = ctk.CTkFrame(connect_card, fg_color="transparent")
    card_head.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 10))
    ctk.CTkLabel(card_head, text="Backend connection", text_color=colors["ink"], font=("Segoe UI", 14, "bold")).pack(side="left")
    ctk.CTkLabel(
        card_head,
        text="NO TOKEN REQUIRED",
        text_color=colors["amber"],
        fg_color=colors["amber_pale"],
        corner_radius=999,
        font=("Segoe UI", 9, "bold"),
        width=128,
        height=26,
    ).pack(side="right")

    ctk.CTkLabel(connect_card, text="Backend URL", text_color=colors["muted"], font=("Segoe UI", 10, "bold")).grid(
        row=1, column=0, padx=22, sticky="w"
    )
    backend_entry = ctk.CTkEntry(
        connect_card,
        textvariable=backend_var,
        height=46,
        corner_radius=14,
        border_width=1,
        border_color=colors["border"],
        fg_color="#ffffff",
        text_color=colors["ink"],
        placeholder_text="http://server:8000",
        font=("Segoe UI", 11),
    )
    backend_entry.grid(row=2, column=0, sticky="ew", padx=22, pady=(8, 20))

    progress_card = ctk.CTkFrame(
        main,
        fg_color=colors["card"],
        corner_radius=22,
        border_width=1,
        border_color=colors["border"],
    )
    progress_card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
    progress_card.grid_columnconfigure(0, weight=1)

    status_row = ctk.CTkFrame(progress_card, fg_color="transparent")
    status_row.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 12))
    ctk.CTkLabel(status_row, textvariable=step_var, text_color=colors["ink"], font=("Segoe UI", 12, "bold")).pack(side="left")
    ctk.CTkLabel(status_row, textvariable=status_var, text_color=colors["muted"], font=("Segoe UI", 10)).pack(side="right")

    progress_bar = ctk.CTkProgressBar(
        progress_card,
        height=12,
        corner_radius=999,
        fg_color=colors["amber_pale"],
        progress_color=colors["amber"],
    )
    progress_bar.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 20))
    progress_bar.set(0)

    log_card = ctk.CTkFrame(main, fg_color=colors["log"], corner_radius=22)
    log_card.grid(row=3, column=0, sticky="nsew")
    log_card.grid_columnconfigure(0, weight=1)
    log_card.grid_rowconfigure(1, weight=1)

    log_head = ctk.CTkFrame(log_card, fg_color="transparent")
    log_head.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 8))
    ctk.CTkLabel(log_head, text="Activity log", text_color=colors["shell"], font=("Segoe UI", 12, "bold")).pack(side="left")
    ctk.CTkLabel(log_head, text="Windows may show a UAC prompt", text_color="#c4b9a8", font=("Segoe UI", 9)).pack(side="right")

    log_box = ctk.CTkTextbox(
        log_card,
        corner_radius=14,
        border_width=0,
        fg_color="#15110d",
        text_color=colors["shell"],
        font=("Consolas", 9),
        wrap="word",
    )
    log_box.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
    log_box.configure(state="disabled")

    footer = ctk.CTkFrame(main, fg_color="transparent")
    footer.grid(row=4, column=0, sticky="ew", pady=(18, 0))

    def append_log(message: str):
        events.put(("log", message))

    def set_progress(value: int):
        progress_bar.set(max(0, min(value, 100)) / 100)

    def set_running(running: bool):
        install_button.configure(state="disabled" if running else "normal")
        install_button.configure(fg_color="#c4b9a8" if running else colors["amber"])
        backend_entry.configure(state="disabled" if running else "normal")
        root.configure(cursor="watch" if running else "")

    def install_clicked():
        backend_url = backend_var.get().strip().rstrip("/")
        if not backend_url:
            messagebox.showerror("Backend URL required", "Please enter the backend URL.")
            return

        if not is_admin():
            status_var.set("Requesting Administrator permission...")
            step_var.set("Elevation required")
            elevate(["--gui", "--auto-start", "--backend-url", backend_url])
            root.destroy()
            return

        set_running(True)
        status_var.set("Installing...")
        step_var.set("Starting")
        set_progress(5)

        def worker():
            try:
                agent_id, log_path = install_agent(backend_url, append_log)
                events.put(("done", agent_id, log_path))
            except Exception as exc:
                events.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    close_button = ctk.CTkButton(
        footer,
        text="Close",
        command=root.destroy,
        width=112,
        height=44,
        corner_radius=14,
        fg_color=colors["paper"],
        hover_color=colors["amber_pale"],
        border_width=1,
        border_color=colors["border"],
        text_color=colors["ink"],
        font=("Segoe UI", 10),
    )
    close_button.pack(side="right")

    install_button = ctk.CTkButton(
        footer,
        text="Install Agent",
        command=install_clicked,
        width=160,
        height=44,
        corner_radius=14,
        fg_color=colors["amber"],
        hover_color=colors["amber_dark"],
        text_color="#ffffff",
        font=("Segoe UI", 10, "bold"),
    )
    install_button.pack(side="right", padx=(0, 10))

    def update_step_from_message(message: str):
        if message.startswith("[1/5]"):
            step_var.set("Creating folders")
            set_progress(12)
        elif message.startswith("[2/5]"):
            step_var.set("Registering machine")
            set_progress(34)
        elif message.startswith("[3/5]"):
            step_var.set("Writing configuration")
            set_progress(54)
        elif message.startswith("[4/5]"):
            step_var.set("Copying agent files")
            set_progress(74)
        elif message.startswith("[5/5]"):
            step_var.set("Installing service")
            set_progress(90)

    def pump_events():
        try:
            while True:
                event = events.get_nowait()
                if event[0] == "log":
                    update_step_from_message(event[1])
                    log_box.configure(state="normal")
                    log_box.insert("end", event[1] + "\n")
                    log_box.see("end")
                    log_box.configure(state="disabled")
                    status_var.set(event[1])
                elif event[0] == "done":
                    _kind, agent_id, log_path = event
                    status_var.set(f"Installed: {agent_id}")
                    step_var.set("Complete")
                    set_progress(100)
                    set_running(False)
                    messagebox.showinfo("Install complete", f"Agent ID: {agent_id}\nLog: {log_path}")
                elif event[0] == "error":
                    status_var.set("Install failed")
                    step_var.set("Failed")
                    set_running(False)
                    messagebox.showerror("Install failed", event[1])
        except Empty:
            pass
        root.after(100, pump_events)

    root.after(100, pump_events)
    if auto_start:
        root.after(300, install_clicked)
    root.mainloop()


def main():
    args = parse_args()
    backend_url = args.backend_url.rstrip("/")
    use_gui = args.gui or not backend_url

    if use_gui:
        run_modern_gui(backend_url, args.auto_start)
        return

    if not is_admin():
        log("[Setup] requesting Administrator permission...")
        elevate(["--backend-url", backend_url])
        return

    try:
        install_agent(backend_url, log)
    except Exception as exc:
        log(f"[ERROR] Install failed: {exc}")
        input("Press Enter to close...")
        sys.exit(1)

    input("Press Enter to close...")


if __name__ == "__main__":
    main()
