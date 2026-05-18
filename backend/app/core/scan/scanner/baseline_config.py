"""
baseline_config.py  (v2 — auto-detect)

แทนที่ BASELINE_CONFIGS dict แบบ hardcode ด้วย auto_detect_baseline()
ที่อ่าน Excel แล้ว detect sheet/column เองอัตโนมัติ

เพิ่ม OS ใหม่ = วางไฟล์ .xlsx ใน /data เท่านั้น
ไม่ต้องแก้โค้ดใดๆ
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

import openpyxl

# ---------------------------------------------------------------------------
# Constants — hardcode เพียงส่วนเดียวที่จำเป็น
# ---------------------------------------------------------------------------

# sheet name (lowercase) → sheet_type
SHEET_TYPE_MAP: dict[str, str] = {
    "computer":           "computer",
    "user":               "user",
    "security template":  "security_template",
    "advanced audit":     "advanced_audit",
    "advanced auditing":  "advanced_audit",
    "firewall":           "firewall",
    "services":           "services",
    "applocker":          "skip",
    "applocker for dcs":  "skip",
    "information":        "skip",
    "revision history":   "skip",
}

# ลำดับ priority ในการหา target column
TARGET_COLUMN_PRIORITY: list[str] = [
    "Member Server",
    "Domain Controller",
    "Windows 11 25H2",
    "Windows 11 24H2",
    "Windows 11",
    "Policy Value",
    "Windows 11 23H2",
    "Windows 10",
    "Windows Server 2022",
    "Windows Server 2019",
]

# column name candidates สำหรับแต่ละ field
REG_INFO_CANDIDATES:    list[str] = ["Registry Information", "Reg Info", "Registry"]
POLICY_NAME_CANDIDATES: list[str] = ["Policy Setting Name", "Name", "Policy Name"]
POLICY_PATH_CANDIDATES: list[str] = ["Policy Path", "Path"]
SERVICE_NAME_CANDIDATES: list[str] = ["Name", "Service Name"]
SERVICE_TYPE_CANDIDATES: list[str] = ["Type", "Service Type"]

# regex สำหรับดึง version string จากชื่อไฟล์
# รองรับ: "MS Security Baseline Windows 11 v24H2.xlsx"
#          "MS Security Baseline Windows Server 2025 v2602.xlsx"
_FILENAME_RE = re.compile(
    r"MS[_ ]Security[_ ]Baseline[_ ](.+?)(?:\s*v[\d.]+)?\s*\.xlsx$",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"v([\dH.]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes (เหมือนเดิม — scanner ใช้ได้โดยไม่ต้องแก้)
# ---------------------------------------------------------------------------

@dataclass
class SheetConfig:
    sheet_type:      str
    target_columns:  list[str]
    policy_name_col: str = "Policy Setting Name"
    policy_path_col: str = "Policy Path"
    reg_info_col:    str = "Registry Information"
    service_name_col: str = "Name"
    service_type_col: str = "Type"


@dataclass
class BaselineConfig:
    version_id:   str
    display_name: str
    filename:     str
    os_family:    str
    sheets:       dict[str, SheetConfig]
    skip_sheets:  set[str] = field(default_factory=lambda: {"Information", "Revision History"})


# ---------------------------------------------------------------------------
# Auto-detect core
# ---------------------------------------------------------------------------

def _detect_os_family(filename: str) -> str:
    """ดู os_family จากชื่อไฟล์"""
    lower = filename.lower()
    if "server" in lower:
        return "windows_server"
    return "windows_client"


def _derive_version_id(filename: str) -> str:
    """
    แปลงชื่อไฟล์ → version_id
    "MS Security Baseline Windows Server 2025 v2602.xlsx"
    → "Windows Server 2025 v2602"
    """
    # ตัด prefix "MS Security Baseline " และ extension
    name = os.path.splitext(filename)[0]
    prefixes = [
        "MS_Security_Baseline_",
        "MS Security Baseline ",
        "MSSecurityBaseline",
    ]
    for p in prefixes:
        if name.startswith(p):
            name = name[len(p):]
            break
    # normalize underscore → space
    name = name.replace("_", " ").strip()
    return name


def _first_match(candidates: list[str], headers: list[str]) -> Optional[str]:
    """คืน candidate แรกที่เจอใน headers"""
    for c in candidates:
        if c in headers:
            return c
    return None


def auto_detect_baseline(filepath: str) -> BaselineConfig:
    """
    อ่าน Excel แล้ว detect config อัตโนมัติ

    Parameters
    ----------
    filepath : str
        absolute path ของไฟล์ .xlsx

    Returns
    -------
    BaselineConfig พร้อมใช้งาน
    """
    filename   = os.path.basename(filepath)
    version_id = _derive_version_id(filename)
    os_family  = _detect_os_family(filename)

    wb     = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    sheets: dict[str, SheetConfig] = {}

    for sheet_name in wb.sheetnames:
        sheet_type = SHEET_TYPE_MAP.get(sheet_name.lower(), "skip")
        if sheet_type == "skip":
            continue

        ws   = wb[sheet_name]
        rows = list(ws.iter_rows(max_row=1, values_only=True))
        if not rows or not rows[0]:
            continue
        headers = [str(h).strip() if h is not None else "" for h in rows[0]]

        # หา target columns ตาม priority
        target_cols = [c for c in TARGET_COLUMN_PRIORITY if c in headers]
        if not target_cols:
            # ไม่มี target column → skip sheet นี้
            continue

        sheets[sheet_name] = SheetConfig(
            sheet_type      = sheet_type,
            target_columns  = target_cols,
            policy_name_col = _first_match(POLICY_NAME_CANDIDATES, headers) or "Policy Setting Name",
            policy_path_col = _first_match(POLICY_PATH_CANDIDATES, headers) or "Policy Path",
            reg_info_col    = _first_match(REG_INFO_CANDIDATES,    headers) or "Registry Information",
            service_name_col= _first_match(SERVICE_NAME_CANDIDATES, headers) or "Name",
            service_type_col= _first_match(SERVICE_TYPE_CANDIDATES, headers) or "Type",
        )

    wb.close()

    return BaselineConfig(
        version_id   = version_id,
        display_name = f"{version_id} (MS Security Baseline)",
        filename     = filename,
        os_family    = os_family,
        sheets       = sheets,
        skip_sheets  = {
            s for s in wb.sheetnames
            if SHEET_TYPE_MAP.get(s.lower(), "skip") == "skip"
        },
    )


# ---------------------------------------------------------------------------
# Registry  (cache per data_path)
# ---------------------------------------------------------------------------

def scan_data_directory(data_path: str) -> dict[str, BaselineConfig]:
    """
    Scan folder หา .xlsx ทั้งหมดแล้ว detect config

    Returns
    -------
    dict[version_id, BaselineConfig]
    """
    configs: dict[str, BaselineConfig] = {}

    if not os.path.isdir(data_path):
        return configs

    for fname in os.listdir(data_path):
        if not fname.lower().endswith(".xlsx"):
            continue
        # ข้ามไฟล์ที่ไม่ใช่ baseline (เช่น scan_summary.log)
        if "security baseline" not in fname.lower() and "securitybaseline" not in fname.lower():
            continue
        fpath = os.path.join(data_path, fname)
        try:
            cfg = auto_detect_baseline(fpath)
            configs[cfg.version_id] = cfg
        except Exception as e:
            # ถ้าไฟล์ใดอ่านไม่ได้ให้ข้ามแทนที่จะ crash ทั้งหมด
            print(f"[baseline_config] skip {fname}: {e}")

    return configs


# ---------------------------------------------------------------------------
# Public API  (เหมือนเดิม — main.py ไม่ต้องแก้มาก)
# ---------------------------------------------------------------------------

# lazy cache — โหลดครั้งแรกที่ใช้
_config_cache: dict[str, BaselineConfig] = {}
_cache_data_path: str = ""


def load_configs(data_path: str, force_reload: bool = False) -> dict[str, BaselineConfig]:
    """โหลด (และ cache) configs จาก data_path"""
    global _config_cache, _cache_data_path
    if force_reload or _cache_data_path != data_path or not _config_cache:
        _config_cache    = scan_data_directory(data_path)
        _cache_data_path = data_path
    return _config_cache


def get_config(version_id: str, data_path: str = "") -> BaselineConfig:
    """ดึง config ตาม version_id"""
    configs = load_configs(data_path) if data_path else _config_cache
    cfg = configs.get(version_id)
    if cfg is None:
        raise ValueError(
            f"ไม่รองรับ version '{version_id}' "
            f"รองรับเฉพาะ: {list(configs.keys())}"
        )
    return cfg


def list_versions(data_path: str = "") -> list[dict]:
    """คืน list ข้อมูล version ทั้งหมด"""
    configs = load_configs(data_path) if data_path else _config_cache
    return [
        {
            "version_id":   cfg.version_id,
            "display_name": cfg.display_name,
            "filename":     cfg.filename,
            "os_family":    cfg.os_family,
        }
        for cfg in configs.values()
    ]


def resolve_target_col(sheet_cfg: SheetConfig, columns: list) -> Optional[str]:
    """หา target column ตามลำดับ priority"""
    for candidate in sheet_cfg.target_columns:
        if candidate in columns:
            return candidate
    return None