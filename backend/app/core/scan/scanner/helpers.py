import re

from .mappings import SPECIAL_VALUE_MAP


def normalize_value(value):
    val = str(value).strip().lower()
    if val in ["1", "enabled", "on", "yes", "true"]:
        return "1"
    if val in ["0", "disabled", "off", "no", "false"]:
        return "0"
    if val.lstrip("-").isdigit():
        return val
    mapped = SPECIAL_VALUE_MAP.get(val)
    if mapped is not None:
        return mapped
    return val


def norm_yn(val):
    v = str(val).strip().lower()
    if v in ("yes", "enable", "enabled", "on", "1", "true"):
        return "yes"
    if v in ("no", "disable", "disabled", "off", "0", "false", "n/a"):
        return "no"
    return v


def resolve_sids(sid_string, sid_map):
    if sid_string is None:
        return "None"
    raw = str(sid_string).strip()
    if raw == "":
        return ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    resolved = [sid_map.get(p, p) for p in parts]
    return "; ".join(resolved)


def update_section_stats(section_stats, full_key, result):
    m = re.match(r"^\[([^\]]+)\]", str(full_key))
    section = m.group(1) if m else "Unknown"

    if section not in section_stats:
        section_stats[section] = {
            "Total": 0,
            "Pass": 0,
            "Fail": 0,
            "Manual": 0,
            "Other": 0,
        }

    section_stats[section]["Total"] += 1
    text = str(result)
    if text == "Pass":
        section_stats[section]["Pass"] += 1
    elif text.startswith("Fail"):
        section_stats[section]["Fail"] += 1
    elif "Manual" in text:
        section_stats[section]["Manual"] += 1
    else:
        section_stats[section]["Other"] += 1


def resolve_target_col(sheet_name, columns):
    if sheet_name in ("Computer", "User"):
        for candidate in ("Windows 11 25H2", "Windows 11 24H2", "Policy Value"):
            if candidate in columns:
                return candidate
        return None
    return "Windows 11" if "Windows 11" in columns else None
