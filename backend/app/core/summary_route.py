"""
summary_router.py
FastAPI router สำหรับ /api/summary และ /api/summary/stream (SSE)
ใช้ llama-cpp-python โหลด LLaMA 3 8B Q4_K_M แบบ local
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.security import get_current_user
from app.models.user import User
from fastapi import Depends

# ─── Model path ───────────────────────────────────────────────────────────────
MODEL_PATH = r"C:\MicrosoftScanEngine\meta-llama-3-8b-instruct.Q4_K_M.gguf"

# ─── Lazy-load LLM (โหลดครั้งเดียว, thread-safe) ─────────────────────────────
_llm      = None
_llm_lock = threading.Lock()


def _get_llm():
    """โหลด LLaMA model แบบ singleton — thread-safe"""
    global _llm
    if _llm is not None:
        return _llm
    with _llm_lock:
        if _llm is not None:
            return _llm
        try:
            from llama_cpp import Llama  # type: ignore
            _llm = Llama(
                model_path=MODEL_PATH,
                n_ctx=4096,
                n_threads=4,
                n_gpu_layers=0,
                verbose=False,
            )
        except Exception as e:
            raise RuntimeError(f"ไม่สามารถโหลด LLaMA model ได้: {e}") from e
    return _llm


# ─── Schemas ──────────────────────────────────────────────────────────────────
class FailItem(BaseModel):
    name:     str
    section:  str
    severity: str
    target:   str = ""
    actual:   str = ""


class SummaryRequest(BaseModel):
    score:          int
    target_name:    str
    version:        str
    pass_count:     int
    total_count:    int
    fail_items:     list[FailItem]
    # ── ตัวเลข severity จริงทั้งหมด (ไม่ขึ้นกับจำนวน fail_items ที่ส่งมา) ──
    critical_count: int = 0
    high_count:     int = 0
    medium_count:   int = 0
    low_count:      int = 0


class SummaryResponse(BaseModel):
    overview:       str
    detected:       list[dict[str, Any]]
    recommendation: str


# ─── Router ───────────────────────────────────────────────────────────────────
router = APIRouter()


def _build_prompt(req: SummaryRequest) -> str:
    """สร้าง prompt สำหรับ LLaMA 3 Instruct format"""
    critical_highs = [
        f"- [{i.severity.upper()}] {i.name} (section: {i.section})"
        + (f" | current: {i.actual}" if i.actual else "")
        + (f" | required: {i.target}" if i.target else "")
        for i in req.fail_items
        if i.severity in ("critical", "high")
    ][:15]

    mediums_lows = [
        f"- [{i.severity.upper()}] {i.name} (section: {i.section})"
        for i in req.fail_items
        if i.severity in ("medium", "low")
    ][:10]

    fail_summary = "\n".join(critical_highs + mediums_lows) or "- ไม่มีรายการ"

    # ── ใช้ค่า counts ที่ส่งมาจาก frontend โดยตรง ──────────────────────────
    # fallback: นับจาก fail_items ถ้าไม่ได้ส่ง counts มา
    if req.critical_count or req.high_count or req.medium_count or req.low_count:
        counts = {
            "critical": req.critical_count,
            "high":     req.high_count,
            "medium":   req.medium_count,
            "low":      req.low_count,
        }
    else:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in req.fail_items:
            counts[item.severity] = counts.get(item.severity, 0) + 1

    total_fail = counts["critical"] + counts["high"] + counts["medium"] + counts["low"]

    system_msg = (
        "You are a senior cybersecurity analyst specializing in Windows security hardening. "
        "Analyze the scan results and respond ONLY in valid JSON with no text outside the JSON object. "
        "The JSON must have exactly three keys: overview, detected, recommendation. "
        "Write ALL text content in Thai language. Be concise but informative."
    )

    user_msg = (
        f"Scan results for Windows machine:\n"
        f"- Target: {req.target_name}\n"
        f"- Version: {req.version}\n"
        f"- Security Score: {req.score}%\n"
        f"- Pass: {req.pass_count}/{req.total_count}\n"
        f"- Total failed: {total_fail} items\n"
        f"- Failed breakdown: Critical={counts['critical']}, High={counts['high']}, "
        f"Medium={counts['medium']}, Low={counts['low']}\n"
        f"\n"
        f"Failed policies (top items shown):\n"
        f"{fail_summary}\n"
        f"\n"
        # ── Instructions แยกออกมาจาก JSON template ──────────────────────────
        f"Instructions for your response:\n"
        f"- overview: เขียน 150-200 คำ ครอบคลุม "
        f"(1) คะแนน {req.score}% และระดับความเสี่ยงโดยรวม "
        f"(2) จำนวน critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} ที่ fail และหมวดที่มีปัญหามากสุด "
        f"เช่น Network Security, Credential, Audit Policy, Account Security "
        f"(3) ความเสี่ยงรูปธรรมที่ผู้โจมตีอาจใช้ประโยชน์ได้ "
        f"(4) ผลกระทบต่อองค์กรถ้าปล่อยทิ้งไว้\n"
        f"- detected: แสดง 5 รายการที่ critical ที่สุดจาก fail_items ด้านบน "
        f"พร้อมอธิบาย why เป็น 1 ประโยคในภาษาไทย\n"
        f"- recommendation: เขียน 100-150 คำ แนะนำการแก้ไข 4-5 ข้อเรียงตาม priority "
        f"ระบุ tool เช่น secpol.msc, gpedit.msc, registry path โดยเริ่มจาก critical ก่อน\n"
        f"\n"
        # ── JSON template ใช้ placeholder สั้นๆ เท่านั้น ────────────────────
        "Return ONLY this JSON structure (all text values in Thai, no trailing commas):\n"
        "{{\n"
        '  "overview": "(วิเคราะห์ภาษาไทย 150-200 คำ)",\n'
        '  "detected": [\n'
        '    {{\n'
        '      "name": "ชื่อ policy",\n'
        '      "section": "ชื่อ section",\n'
        '      "severity": "critical|high|medium|low",\n'
        '      "actual": "ค่าปัจจุบัน",\n'
        '      "target": "ค่าที่ต้องการ",\n'
        '      "why": "อธิบายความเสี่ยง 1 ประโยค"\n'
        '    }}\n'
        '  ],\n'
        '  "recommendation": "(แนะนำการแก้ไข 100-150 คำ อยากได้ประมาณว่าควรเริ่มที่อะไรไม่ต้องลงรายละเอียดมาก)"\n'
        "}}\n"
        "\n"
        "IMPORTANT: Do NOT copy the placeholder text above into your response. "
        "Generate actual Thai content based on the scan data provided. "
        "Respond ONLY with valid JSON."
    )

    prompt = (
        "<|start_header_id|>system<|end_header_id|>\n\n"
        f"{system_msg}"
        "<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\n\n"
        f"{user_msg}"
        "<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n\n"
        "{\n"  # prime token — บังคับให้ LLM เริ่ม JSON ทันที
    )
    return prompt


def _sanitize(s: str) -> str:
    """ทำความสะอาด string ก่อน parse"""
    s = re.sub(r',\s*([}\]])', r'\1', s)                    # trailing commas
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', s)     # control chars (ไม่รวม \n \r \t)
    return s.strip()


def _try_parse(s: str) -> dict | None:
    """ลอง json.loads — คืน dict หรือ None"""
    try:
        return json.loads(_sanitize(s))
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_block(raw: str) -> str | None:
    """เดิน { } เพื่อหา outermost JSON object (รองรับ nested)"""
    depth = 0
    start = None
    for i, ch in enumerate(raw):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                return raw[start:i + 1]
    return None


def _truncation_recovery(raw: str, fail_items: list) -> dict:
    """ถ้า JSON ถูกตัดกลางคัน (max_tokens หมด) ให้ดึงเฉพาะส่วนที่ parse ได้"""
    overview       = ''
    recommendation = ''
    detected       = []

    m = re.search(r'"overview"\s*:\s*"((?:[^"\\]|\\.)*)"', raw, re.DOTALL)
    if m:
        try:    overview = json.loads(f'"{m.group(1)}"')
        except: overview = m.group(1)

    m = re.search(r'"recommendation"\s*:\s*"((?:[^"\\]|\\.)*)"', raw, re.DOTALL)
    if m:
        try:    recommendation = json.loads(f'"{m.group(1)}"')
        except: recommendation = m.group(1)

    for item_match in re.finditer(r'\{[^{}]*"name"\s*:[^{}]*\}', raw, re.DOTALL):
        try:
            item = json.loads(_sanitize(item_match.group(0)))
            if 'name' in item:
                detected.append(item)
        except Exception:
            pass

    if not detected and fail_items:
        detected = [
            {"name": i.name, "section": i.section, "severity": i.severity,
             "actual": i.actual, "target": i.target, "why": ""}
            for i in fail_items[:5]
        ]

    return {
        "overview":       overview or "(วิเคราะห์ไม่สมบูรณ์ — JSON ถูกตัดกลางคัน)",
        "detected":       detected,
        "recommendation": recommendation or "(ไม่ได้รับคำแนะนำ — กรุณาลองใหม่)",
    }


def _parse_llm_output(raw: str, fail_items: list | None = None) -> dict:
    """
    Multi-strategy parser — แกร่งต่อ LLM output ที่ไม่สมบูรณ์
      1. parse ตรงหลัง sanitize
      2. ตัด markdown fences แล้ว parse
      3. extract outermost { } แล้ว parse
      3b. ลอง close bracket ที่หายแล้ว parse
      4. truncation recovery — ดึง field ทีละอัน
    """
    # เนื่องจาก prompt เติม "{\n" เป็น prime token ต้องเติม { กลับก่อน parse
    if not raw.strip().startswith('{'):
        raw = '{\n' + raw

    # 1. parse ตรง
    r = _try_parse(raw)
    if r and "overview" in r:
        return r

    # 2. ตัด markdown fences + prefix text
    stripped = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r'\s*```$', '', stripped)
    r = _try_parse(stripped)
    if r and "overview" in r:
        return r

    # 3. extract outermost { }
    block = _extract_block(raw)
    if block:
        r = _try_parse(block)
        if r and "overview" in r:
            return r

        # 3b. เติม bracket ที่หาย
        open_b  = block.count('[') - block.count(']')
        open_c  = block.count('{') - block.count('}')
        closed  = block + (']' * max(0, open_b)) + ('}' * max(0, open_c))
        r = _try_parse(closed)
        if r and "overview" in r:
            return r

    # 4. truncation recovery
    return _truncation_recovery(raw, fail_items or [])


def _make_sse(event: str, data: Any) -> str:
    """สร้าง SSE message string"""
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


# ─── SSE Streaming endpoint ───────────────────────────────────────────────────

@router.post("/api/summary/stream")
async def generate_summary_stream(req: SummaryRequest):
    """
    SSE endpoint — ส่ง progress events ระหว่าง LLM กำลัง generate
    Events:
      phase   — { phase: "loading_model" | "generating" | "parsing" | "done" | "error", message: str }
      token   — { count: int, elapsed: float }   (ส่งทุก 3 วินาที)
      result  — { overview, detected, recommendation }  (เมื่อเสร็จ)
      error   — { detail: str }
    """
    if req.total_count == 0:
        async def _err():
            yield _make_sse("error", {"detail": "ไม่มีข้อมูลผลการสแกน"})
        return StreamingResponse(_err(), media_type="text/event-stream")

    import asyncio
    from fastapi.concurrency import run_in_threadpool

    prompt = _build_prompt(req)

    # queue สำหรับส่ง events จาก thread → async generator
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _put(event: str, data: Any):
        """thread-safe put ลง queue"""
        loop.call_soon_threadsafe(queue.put_nowait, (event, data))

    def _infer():
        start_time = time.time()

        # Phase 1: โหลด model
        _put("phase", {"phase": "loading_model", "message": "กำลังโหลด LLaMA model..."})
        print("[LLM] Loading model...", flush=True)
        try:
            llm = _get_llm()
        except RuntimeError as e:
            print(f"[LLM] ERROR loading model: {e}", flush=True)
            _put("error", {"detail": str(e)})
            _put("__done__", {})
            return

        print("[LLM] Model ready — starting inference", flush=True)
        _put("phase", {"phase": "generating", "message": "LLM กำลังวิเคราะห์ข้อมูล..."})

        # ─── Timer thread — ส่ง progress ทุก 3s ระหว่าง LLM blocking ────────
        _timer_stop = threading.Event()
        _tick       = [0]

        def _timer_worker():
            while not _timer_stop.wait(3.0):
                _tick[0] += 3
                print(f"[LLM] Still running... {_tick[0]}s elapsed", flush=True)
                _put("token", {
                    "count":          _tick[0],
                    "elapsed":        _tick[0],
                    "tokens_per_sec": "~",
                })

        timer_thread = threading.Thread(target=_timer_worker, daemon=True)
        timer_thread.start()

        raw_text = ""
        try:
            output = llm(
                prompt,
                max_tokens=3500,
                temperature=0.3,
                top_p=0.9,
                repeat_penalty=1.1,
                stop=["<|eot_id|>", "<|end_of_text|>"],
                stream=False,
            )
            raw_text = output["choices"][0]["text"]
            elapsed  = round(time.time() - start_time, 1)
            tok_used = output.get("usage", {}).get("completion_tokens", len(raw_text.split()))
            print(f"[LLM] Done — {tok_used} tokens in {elapsed}s", flush=True)

        except Exception as e:
            _timer_stop.set()
            print(f"[LLM] ERROR during inference: {e}", flush=True)
            _put("error", {"detail": f"LLM inference error: {e}"})
            _put("__done__", {})
            return
        finally:
            _timer_stop.set()

        elapsed  = round(time.time() - start_time, 1)
        tok_used = len(raw_text.split())
        _put("token", {
            "count":          tok_used,
            "elapsed":        elapsed,
            "tokens_per_sec": round(tok_used / elapsed, 1) if elapsed > 0 else 0,
        })

        # Phase 3: Parse JSON
        print(f"[LLM] Parsing output ({len(raw_text)} chars)...", flush=True)
        _put("phase", {"phase": "parsing", "message": "กำลัง parse JSON..."})

        result = _parse_llm_output(raw_text, fail_items=list(req.fail_items))

        # Validate & fallback
        overview       = result.get("overview", "")
        detected       = result.get("detected", [])
        recommendation = result.get("recommendation", "")

        if not detected and req.fail_items:
            detected = [
                {
                    "name":     item.name,
                    "section":  item.section,
                    "severity": item.severity,
                    "actual":   item.actual,
                    "target":   item.target,
                    "why":      "",
                }
                for item in req.fail_items[:5]
            ]

        elapsed_total = round(time.time() - start_time, 1)
        _put("phase", {
            "phase":   "done",
            "message": f"เสร็จสิ้น — {tok_used} tokens ใน {elapsed_total}s "
                       f"({round(tok_used / elapsed_total, 1) if elapsed_total else 0} tok/s)",
        })
        _put("result", {
            "overview":       overview,
            "detected":       detected,
            "recommendation": recommendation,
        })
        _put("__done__", {})

    async def _event_generator() -> AsyncIterator[str]:
        infer_task = asyncio.create_task(run_in_threadpool(_infer))

        while True:
            try:
                event, data = await asyncio.wait_for(queue.get(), timeout=120.0)
            except asyncio.TimeoutError:
                yield _make_sse("error", {"detail": "LLM timeout (120s)"})
                break

            if event == "__done__":
                break

            yield _make_sse(event, data)

        await infer_task

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Original non-streaming endpoint (ยังไว้ fallback) ───────────────────────

@router.post("/api/summary", response_model=SummaryResponse)
async def generate_summary(req: SummaryRequest):
    """
    รับผลสแกน → ส่งให้ LLaMA 3 วิเคราะห์ → คืน structured summary (blocking)
    """
    if req.total_count == 0:
        raise HTTPException(status_code=400, detail="ไม่มีข้อมูลผลการสแกน")

    try:
        from fastapi.concurrency import run_in_threadpool

        prompt = _build_prompt(req)

        def _infer():
            llm = _get_llm()
            output = llm(
                prompt,
                max_tokens=3500,
                temperature=0.3,
                top_p=0.9,
                repeat_penalty=1.1,
                stop=["<|eot_id|>", "<|end_of_text|>"],
            )
            return output["choices"][0]["text"]

        raw_text = await run_in_threadpool(_infer)
        result   = _parse_llm_output(raw_text, fail_items=list(req.fail_items))

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"เกิดข้อผิดพลาด: {e}")

    overview       = result.get("overview", "")
    detected       = result.get("detected", [])
    recommendation = result.get("recommendation", "")

    if not detected and req.fail_items:
        detected = [
            {
                "name":     item.name,
                "section":  item.section,
                "severity": item.severity,
                "actual":   item.actual,
                "target":   item.target,
                "why":      "",
            }
            for item in req.fail_items[:5]
        ]

    return SummaryResponse(
        overview=overview,
        detected=detected,
        recommendation=recommendation,
    )