"""
summary_router.py
FastAPI router สำหรับ /api/summary และ /api/summary/stream (SSE)
ใช้ Groq API (ค่าเริ่มต้น: llama-3.1-8b-instant)
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.security import get_current_user
from app.models.user import User
from fastapi import Depends


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


def _build_messages(req: SummaryRequest) -> list[dict]:
    """สร้าง messages array สำหรับ Groq Chat Completion"""
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
        f"- Failed breakdown (USE THESE EXACT NUMBERS — do NOT change them):\n"
        f"    Critical = {counts['critical']}\n"
        f"    High     = {counts['high']}\n"
        f"    Medium   = {counts['medium']}\n"
        f"    Low      = {counts['low']}\n"
        f"    Total    = {total_fail}\n"
        f"\n"
        f"Failed policies (representative sample — top critical/high shown):\n"
        f"{fail_summary}\n"
        f"\n"
        f"=== INSTRUCTIONS ===\n"
        f"Write ALL output in Thai. Return ONLY a single valid JSON object. No markdown, no explanation outside JSON.\n"
        f"\n"
        f"\"overview\" (150-200 Thai words) MUST include ALL of the following:\n"
        f"  1. คะแนน {req.score}% และประเมินระดับความเสี่ยงโดยรวม (สูง/กลาง/ต่ำ)\n"
        f"  2. ระบุตัวเลขที่แน่นอน: Critical={counts['critical']} High={counts['high']} Medium={counts['medium']} Low={counts['low']} รายการที่ fail\n"
        f"  3. หมวดที่มีปัญหามากที่สุด (วิเคราะห์จาก fail_items ที่ให้ไว้)\n"
        f"  4. ความเสี่ยงที่ผู้โจมตีอาจใช้ประโยชน์ได้จริงจากช่องโหว่เหล่านี้\n"
        f"  5. ผลกระทบต่อองค์กรหากไม่แก้ไข\n"
        f"\n"
        f"\"detected\" — เลือก 5 รายการที่อันตรายที่สุดจาก fail_items ด้านบน:\n"
        f"  - ต้องมี severity ตรงกับข้อมูลจริง (critical/high/medium/low)\n"
        f"  - \"why\" อธิบายความเสี่ยงเป็นภาษาไทย 1 ประโยคที่เป็นรูปธรรม\n"
        f"\n"
        f"\"recommendation\" (100-150 Thai words):\n"
        f"  - เขียนในรูปแบบย่อหน้าต่อเนื่อง ไม่ใช้ข้อหรือ bullet\n"
        f"  - วิเคราะห์ภาพรวมของสถานะความปลอดภัยระบบ และแนะนำทิศทางการแก้ไขโดยรวม\n"
        f"  - เน้นว่าควรเริ่มจากจุดไหนก่อนและทำไม โดยไม่ต้องลงรายละเอียดทีละ policy\n"
        f"  - ระบุ tool กลางๆ ที่ใช้จัดการได้ เช่น secpol.msc, gpedit.msc\n"
        f"\n"
        f"Return ONLY this JSON (no trailing commas, no text outside):\n"
        f"{{\n"
        f'  "overview": "...",\n'
        f'  "detected": [\n'
        f'    {{\n'
        f'      "name": "...",\n'
        f'      "section": "...",\n'
        f'      "severity": "critical|high|medium|low",\n'
        f'      "actual": "...",\n'
        f'      "target": "...",\n'
        f'      "why": "..."\n'
        f'    }}\n'
        f'  ],\n'
        f'  "recommendation": "..."\n'
        f"}}"
    )

    return [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": user_msg},
    ]


# ─── JSON Parsing helpers (เหมือนเดิม) ───────────────────────────────────────

def _sanitize(s: str) -> str:
    s = re.sub(r',\s*([}\]])', r'\1', s)
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', s)
    return s.strip()


def _try_parse(s: str) -> dict | None:
    try:
        return json.loads(_sanitize(s))
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_block(raw: str) -> str | None:
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
    r = _try_parse(raw)
    if r and "overview" in r:
        return r

    stripped = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r'\s*```$', '', stripped)
    r = _try_parse(stripped)
    if r and "overview" in r:
        return r

    block = _extract_block(raw)
    if block:
        r = _try_parse(block)
        if r and "overview" in r:
            return r

        open_b  = block.count('[') - block.count(']')
        open_c  = block.count('{') - block.count('}')
        closed  = block + (']' * max(0, open_b)) + ('}' * max(0, open_c))
        r = _try_parse(closed)
        if r and "overview" in r:
            return r

    return _truncation_recovery(raw, fail_items or [])


def _make_sse(event: str, data: Any) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


def _get_groq_client():
    try:
        from groq import Groq
    except ImportError:
        raise RuntimeError("กรุณาติดตั้ง groq: pip install groq")

    api_key = os.environ.get("GROQ_API_KEY", "")
    model   = os.environ.get("GROQ_MODEL") or "llama-3.1-8b-instant"

    if not api_key:
        raise RuntimeError("ไม่พบ GROQ_API_KEY — กรุณาตั้งค่า environment variable")

    return Groq(api_key=api_key), model

# ─── SSE Streaming endpoint ───────────────────────────────────────────────────

@router.post("/api/summary/stream")
async def generate_summary_stream(
    req: SummaryRequest,
    current_user: User = Depends(get_current_user),
):
    """
    SSE endpoint — ส่ง progress events ระหว่าง Groq กำลัง generate
    Events:
      phase   — { phase: "connecting"|"generating"|"parsing"|"done"|"error", message: str }
      token   — { count: int, elapsed: float, tokens_per_sec: float|str }
      result  — { overview, detected, recommendation }
      error   — { detail: str }
    """
    if req.total_count == 0:
        async def _err():
            yield _make_sse("error", {"detail": "ไม่มีข้อมูลผลการสแกน"})
        return StreamingResponse(_err(), media_type="text/event-stream")

    import asyncio
    from fastapi.concurrency import run_in_threadpool

    messages = _build_messages(req)
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _put(event: str, data: Any):
        loop.call_soon_threadsafe(queue.put_nowait, (event, data))

    def _infer():
        start_time = time.time()

        _put("phase", {"phase": "connecting", "message": "กำลังเชื่อมต่อ Groq API..."})

        try:
            client, model = _get_groq_client()
        except RuntimeError as e:
            _put("error", {"detail": str(e)})
            _put("__done__", {})
            return

        _put("phase", {"phase": "generating", "message": "Groq กำลังวิเคราะห์ข้อมูล..."})

        raw_text     = ""
        token_count  = 0

        try:
            # ใช้ streaming ของ Groq เพื่อให้ SSE ตอบสนองได้ระหว่าง generate
            stream = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=3000,
                temperature=0.3,
                top_p=0.9,
                stream=True,
            )

            last_progress_time = time.time()

            for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                raw_text    += delta
                token_count += len(delta.split())

                # ส่ง progress ทุก 2 วินาที
                now = time.time()
                if now - last_progress_time >= 2.0:
                    elapsed = round(now - start_time, 1)
                    _put("token", {
                        "count":          token_count,
                        "elapsed":        elapsed,
                        "tokens_per_sec": round(token_count / elapsed, 1) if elapsed > 0 else "~",
                    })
                    last_progress_time = now

        except Exception as e:
            _put("error", {"detail": f"Groq API error: {e}"})
            _put("__done__", {})
            return

        elapsed  = round(time.time() - start_time, 1)
        tok_used = token_count or len(raw_text.split())

        _put("token", {
            "count":          tok_used,
            "elapsed":        elapsed,
            "tokens_per_sec": round(tok_used / elapsed, 1) if elapsed > 0 else 0,
        })

        # Phase: Parse
        _put("phase", {"phase": "parsing", "message": "กำลัง parse JSON..."})

        result = _parse_llm_output(raw_text, fail_items=list(req.fail_items))

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
                event, data = await asyncio.wait_for(queue.get(), timeout=60.0)
            except asyncio.TimeoutError:
                yield _make_sse("error", {"detail": "Groq API timeout (60s)"})
                break

            if event == "__done__":
                break

            yield _make_sse(event, data)

        await infer_task

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Non-streaming endpoint (fallback) ───────────────────────────────────────

@router.post("/api/summary", response_model=SummaryResponse)
async def generate_summary(
    req: SummaryRequest,
    current_user: User = Depends(get_current_user),
):
    """
    รับผลสแกน → ส่งให้ Groq วิเคราะห์ → คืน structured summary (blocking)
    """
    if req.total_count == 0:
        raise HTTPException(status_code=400, detail="ไม่มีข้อมูลผลการสแกน")

    try:
        from fastapi.concurrency import run_in_threadpool

        messages = _build_messages(req)

        def _infer():
            client, model = _get_groq_client()
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=3000,
                temperature=0.3,
                top_p=0.9,
                stream=False,
            )
            return response.choices[0].message.content

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
