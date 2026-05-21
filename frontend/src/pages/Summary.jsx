import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import ExportButton from './ExportButton';
import './Summary.css';
import { authHeaders, clearAuth } from '../auth';

// ─── Severity helpers ─────────────────────────────────────────────────────────
const CRITICAL_KEYWORDS = ['remote desktop','lsa protection','credential','ntlm','kerberos','bitlocker'];
const HIGH_KEYWORDS = [
  'network access','network security','user rights','privilege','logon',
  'encryption','tls','ssl','rdp','rpc','anonymous','guest','sam',
  'domain member','impersonate','user account control','restrict','audit',
  'signing','inactivity','force shutdown',
];
const MEDIUM_KEYWORDS = [
  'autoplay','autorun','internet explorer','smartscreen','activex',
  'printer','bluetooth','wifi','hotspot','ink workspace','xbox',
  'cortana','spotlight','toast','netbios','icmp','multicast',
];

function getSeverity(key) {
  const lower = key.toLowerCase();
  if (lower.includes('remote desktop'))    return 'critical';
  if (lower.includes('bitlocker'))         return 'critical';
  if (lower.includes('lsa protection'))    return 'critical';
  if (lower.includes('credential'))        return 'critical';
  if (lower.includes('account lockout'))   return 'high';
  if (lower.includes('logon'))             return 'high';
  if (lower.startsWith('[advanced audit]')) return 'medium';
  if (lower.startsWith('[services]'))       return 'low';
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k)))     return 'high';
  if (MEDIUM_KEYWORDS.some(k => lower.includes(k)))   return 'medium';
  return 'low';
}

const SEV_CONFIG = {
  critical: { label: 'Critical', color: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)', bd: 'var(--sev-critical-bd)' },
  high:     { label: 'High',     color: 'var(--sev-high)',     bg: 'var(--sev-high-bg)',     bd: 'var(--sev-high-bd)' },
  medium:   { label: 'Medium',   color: 'var(--sev-medium)',   bg: 'var(--sev-medium-bg)',   bd: 'var(--sev-medium-bd)' },
  low:      { label: 'Low',      color: 'var(--sev-low)',      bg: 'var(--sev-low-bg)',      bd: 'var(--sev-low-bd)' },
};

// ─── LLM Phase config ─────────────────────────────────────────────────────────
const PHASE_INFO = {
  loading_model: { icon: '⚙️', label: 'โหลด Model',          color: 'var(--ink-lt)' },
  generating:    { icon: '🧠', label: 'LLM กำลังวิเคราะห์',  color: 'var(--amber)' },
  parsing:       { icon: '🔧', label: 'แปลงผลลัพธ์',          color: 'var(--sev-medium)' },
  done:          { icon: '✅', label: 'เสร็จสิ้น',             color: 'var(--green)' },
  error:         { icon: '❌', label: 'เกิดข้อผิดพลาด',        color: 'var(--red)' },
};

// ─── Layout ───────────────────────────────────────────────────────────────────
function Layout({ children, navigate }) {
  return (
    <div className="root">
      <aside className="sidebar">
        <div className="sideTop">
          <div className="logo">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="5"  stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="1.5" fill="#c8813a" />
            </svg>
            <span className="logoText">SecureScan</span>
          </div>
          <nav className="sideNav">
            <button className="sideLink" onClick={() => navigate('/home')}>
              <span className="sideLinkDot" />Home
            </button>
            <button className="sideLink" onClick={() => navigate('/history')}>
              <span className="sideLinkDot" />History
            </button>
            <button className="sideLink" onClick={() => navigate('/guide')}>
              <span className="sideLinkDot" />Guide
            </button>
          </nav>
        </div>
        <button className="logoutBtn" onClick={() => { clearAuth(); navigate('/login'); }}>
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M5 2H2v10h3M9 10l3-3-3-3M12 7H5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Log out
        </button>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

// ─── Topbar ───────────────────────────────────────────────────────────────────
function Topbar() {
  return (
    <header className="topbar">
      <p className="topbarDate">
        {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
      </p>
      <div className="topbarActions">
        <button className="notifBtn">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M8 1a5 5 0 0 1 5 5v3l1 2H2l1-2V6a5 5 0 0 1 5-5zM6.5 13a1.5 1.5 0 0 0 3 0" strokeLinecap="round" />
          </svg>
          <span className="notifDot" />
        </button>
        <div className="avatar">จ</div>
      </div>
    </header>
  );
}

// ─── Score Ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score }) {
  const color = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--amber)' : 'var(--red)';
  const circumference = 2 * Math.PI * 42;
  return (
    <div className="scoreRingWrap">
      <svg viewBox="0 0 100 100" className="scoreRingSvg">
        <circle cx="50" cy="50" r="42" className="scoreTrack" />
        <circle
          cx="50" cy="50" r="42"
          className="scoreArc"
          strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
          transform="rotate(-90 50 50)"
          style={{ stroke: color }}
        />
      </svg>
      <div className="scoreRingText" style={{ color }}>{score}%</div>
    </div>
  );
}

// ─── Typewriter ───────────────────────────────────────────────────────────────
function TypewriterText({ text, speed = 12 }) {
  const [displayed, setDisplayed] = useState('');
  const idx = useRef(0);

  useEffect(() => {
    setDisplayed('');
    idx.current = 0;
    if (!text) return;
    const iv = setInterval(() => {
      idx.current += 1;
      setDisplayed(text.slice(0, idx.current));
      if (idx.current >= text.length) clearInterval(iv);
    }, speed);
    return () => clearInterval(iv);
  }, [text, speed]);

  return <span>{displayed}<span className="cursor">|</span></span>;
}

// ─── LLM Progress Bar ─────────────────────────────────────────────────────────
function LlmProgressBar({ phase, tokenCount, tokensPerSec, elapsed, message }) {
  const info = PHASE_INFO[phase] || PHASE_INFO.generating;

  const barPct = phase === 'done'         ? 100
               : phase === 'parsing'      ? 95
               : phase === 'loading_model'? 5
               : Math.min(90, Math.round((tokenCount / 600) * 85) + 10);

  return (
    <div className="llmProgress">
      <div className="llmPhaseRow">
        <span className="llmPhaseIcon">{info.icon}</span>
        <span className="llmPhaseLabel" style={{ color: info.color }}>{info.label}</span>
        {phase === 'generating' && <span className="llmPulse" />}
      </div>

      <div className="llmBar">
        <div
          className="llmBarFill"
          style={{ width: `${barPct}%`, background: info.color }}
        />
      </div>

      <div className="llmStatsRow">
        {phase === 'generating' && (
          <>
            <span className="llmStat">
              <span className="llmStatLabel">เวลา</span>
              <span className="llmStatVal" style={{ color: 'var(--amber)' }}>{elapsed}s</span>
            </span>
            {tokensPerSec !== '~' && tokensPerSec > 0 && (
              <span className="llmStat">
                <span className="llmStatLabel">tok/s</span>
                <span className="llmStatVal" style={{ color: 'var(--sev-medium)' }}>{tokensPerSec}</span>
              </span>
            )}
            {tokenCount > 0 && tokensPerSec !== '~' && (
              <span className="llmStat">
                <span className="llmStatLabel">tokens</span>
                <span className="llmStatVal">{tokenCount}</span>
              </span>
            )}
          </>
        )}
        {message && <span className="llmMessage">{message}</span>}
      </div>

      <div className="llmDevLog">
        {phase === 'generating' && elapsed > 0
          ? `› LLM running... ${elapsed}s elapsed${tokensPerSec !== '~' ? ` | ${tokenCount} tokens @ ${tokensPerSec} tok/s` : ' | computing...'}`
          : `› ${message || phase}`}
      </div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────
export default function Summary() {
  const navigate = useNavigate();
  const location = useLocation();
  const apiHost  = window.location.hostname;

  const scanData = location.state?.scanData
    || (() => {
        const s = sessionStorage.getItem('scanResult');
        return s ? JSON.parse(s) : null;
      })();

  const [llmData,      setLlmData]      = useState(null);
  const [llmPhase,     setLlmPhase]     = useState('loading_model');
  const [tokenCount,   setTokenCount]   = useState(0);
  const [tokensPerSec, setTokensPerSec] = useState(0);
  const [elapsed,      setElapsed]      = useState(0);
  const [phaseMsg,     setPhaseMsg]     = useState('');
  const [loading,      setLoading]      = useState(false);
  const [llmError,     setLlmError]     = useState('');
  const [exported,     setExported]     = useState(false);

  // ─── Parse fail items ─────────────────────────────────────────────────────
  const failItems = useMemo(() => {
    if (!scanData?.details) return [];
    return Object.entries(scanData.details)
      .filter(([, v]) => String(v).startsWith('Fail'))
      .map(([key, value]) => {
        const secMatch = key.match(/^\[([^\]]+)\]/);
        const section  = secMatch ? secMatch[1] : 'General';
        const name     = key.replace(/^\[[^\]]+\]\s*/, '');
        const severity = getSeverity(key);
        const raw      = String(value);
        const tgt = (raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/) || [])[1]?.trim() || '';
        const act = (raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/) || [])[1]?.trim().replace(/\)\s*$/, '') || '';
        return { key, name, section, severity, target: tgt, actual: act };
      })
      .sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return order[a.severity] - order[b.severity];
      });
  }, [scanData]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    failItems.forEach(i => c[i.severity]++);
    return c;
  }, [failItems]);

  const passCount  = useMemo(() =>
    Object.values(scanData?.details || {}).filter(v => String(v) === 'Pass').length,
  [scanData]);
  const totalCount = Object.keys(scanData?.details || {}).length;

  // ─── SSE streaming ────────────────────────────────────────────────────────
  useEffect(() => {
    if (!scanData) return;

    setLoading(true);
    setLlmError('');
    setLlmPhase('loading_model');
    setTokenCount(0);
    setPhaseMsg('กำลังเชื่อมต่อ...');

    const top30 = failItems.slice(0, 30).map(i => ({
      name: i.name, section: i.section, severity: i.severity,
      target: i.target, actual: i.actual,
    }));

    const body = JSON.stringify({
      score:          scanData.score,
      target_name:    scanData.targetName || scanData.hostname,
      version:        scanData.version,
      pass_count:     passCount,
      total_count:    totalCount,
      fail_items:     top30,
      critical_count: counts.critical,
      high_count:     counts.high,
      medium_count:   counts.medium,
      low_count:      counts.low,
    });

    let aborted = false;
    const controller = new AbortController();

    (async () => {
      try {
        const res = await fetch(`http://${apiHost}:8000/api/summary/stream`, {
          method: 'POST',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          body,
          signal: controller.signal,
        });

        if (res.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }

        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: 'Server error' }));
          setLlmError(err.detail || 'Server error');
          setLoading(false);
          return;
        }

        const reader  = res.body.getReader();
        const decoder = new TextDecoder();
        let   buffer  = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done || aborted) break;

          buffer += decoder.decode(value, { stream: true });
          const messages = buffer.split('\n\n');
          buffer = messages.pop() || '';

          for (const msg of messages) {
            if (!msg.trim()) continue;
            const eventMatch = msg.match(/^event:\s*(.+)$/m);
            const dataMatch  = msg.match(/^data:\s*(.+)$/m);
            if (!eventMatch || !dataMatch) continue;

            const event = eventMatch[1].trim();
            let data;
            try { data = JSON.parse(dataMatch[1]); } catch { continue; }

            if (event === 'phase') {
              setLlmPhase(data.phase);
              setPhaseMsg(data.message || '');
              if (data.phase === 'done') setLoading(false);
            } else if (event === 'token') {
              setTokenCount(data.count);
              setTokensPerSec(data.tokens_per_sec);
              setElapsed(data.elapsed);
              if (data.tokens_per_sec === '~') {
                setPhaseMsg(`LLM กำลังคิด... ผ่านมาแล้ว ${data.elapsed}s`);
              }
            } else if (event === 'result') {
              setLlmData(data);
            } else if (event === 'error') {
              setLlmError(data.detail || 'Unknown error');
              setLoading(false);
            }
          }
        }
      } catch (err) {
        if (!aborted) {
          setLlmError(String(err));
          setLoading(false);
        }
      }
    })();

    return () => { aborted = true; controller.abort(); };
  }, [scanData]);

  // ─── Export ───────────────────────────────────────────────────────────────

  // ─── Guard ────────────────────────────────────────────────────────────────
  if (!scanData) {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="sumEmpty">
          <div className="sumEmptyIcon">📋</div>
          <div className="sumEmptyText">ไม่พบข้อมูลการสแกน</div>
          <button className="sumEmptyBtn" onClick={() => navigate('/home')}>กลับหน้าหลัก</button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <Topbar />

      {/* ── Header ── */}
      <div className="sumHeader">
        <h1 className="sumTitle">Report</h1>
        <ExportButton scanId={scanData?.scan_id} />
      </div>

      {/* ── Score Bar ── */}
      <div className="sumScoreBar">
        <ScoreRing score={scanData.score} />
        <div className="sumScoreMeta">
          <div className="sumTarget">{scanData.targetName || scanData.hostname}</div>
          <div className="sumVersion">{scanData.version}</div>
          <div className="sumBadgeRow">
            <span className="badge pass">✔ {passCount} Pass</span>
            <span className="badge fail">✖ {totalCount - passCount} Fail</span>
          </div>
          <div className="sumSevRow">
            {Object.entries(SEV_CONFIG).map(([sev, cfg]) => (
              <span
                key={sev}
                className="sevPill"
                style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.bd}` }}
              >
                {cfg.label}: {counts[sev]}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main Card ── */}
      <div className="sumCard">

        {/* LLM Progress */}
        {loading && (
          <div className="sumSection">
            <LlmProgressBar
              phase={llmPhase}
              tokenCount={tokenCount}
              tokensPerSec={tokensPerSec}
              elapsed={elapsed}
              message={phaseMsg}
            />
          </div>
        )}

        {/* Error */}
        {llmError && !loading && (
          <div className="sumSection">
            <div className="llmError">⚠️ {llmError}</div>
          </div>
        )}

        {/* Section 1 — Summary */}
        <section className="sumSection">
          <div className="sumSectionHeader">
            <span className="sumSectionIcon">🛡️</span>
            <h2 className="sumSectionTitle">Summary</h2>
          </div>
          <div className="sumTextBox">
            {llmData?.overview
              ? <TypewriterText text={llmData.overview} speed={10} />
              : <span className="sumPlaceholder">รอ LLM วิเคราะห์...</span>}
          </div>
        </section>

        <div className="sumDivider" />

        {/* Section 2 — Detected */}
        <section className="sumSection">
          <div className="sumSectionHeader">
            <span className="sumSectionIcon">🔍</span>
            <h2 className="sumSectionTitle">Detected Summary</h2>
          </div>

          {llmData?.detected && (
            <div className="detectedGrid">
              {llmData.detected.map((item, i) => {
                const sev = SEV_CONFIG[item.severity] || SEV_CONFIG.low;
                return (
                  <div
                    key={i}
                    className="detectedCard"
                    style={{ borderLeft: `3px solid ${sev.color}` }}
                  >
                    <div className="dcTop">
                      <span className="dcSev" style={{ color: sev.color, background: sev.bg, border: `1px solid ${sev.bd}` }}>
                        {sev.label}
                      </span>
                      <span className="dcSection">[{item.section}]</span>
                    </div>
                    <div className="dcName">{item.name}</div>
                    {item.why && <div className="dcWhy">{item.why}</div>}
                    <div className="dcVals">
                      {item.actual && <span className="dcActual">ค่าปัจจุบัน: {item.actual}</span>}
                      {item.target && <span className="dcTarget">ค่าที่ต้องการ: {item.target}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <div className="sumDivider" />

        {/* Section 3 — Recommendation */}
        <section className="sumSection">
          <div className="sumSectionHeader">
            <span className="sumSectionIcon">💡</span>
            <h2 className="sumSectionTitle">Recommendation</h2>
          </div>
          <div className="sumTextBox">
            {llmData?.recommendation
              ? <TypewriterText text={llmData.recommendation} speed={8} />
              : <span className="sumPlaceholder">รอผลการวิเคราะห์...</span>}
          </div>
        </section>

      </div>

      {/* ── Footer ── */}
      <div className="sumFooter">
        <button className="sumBackBtn" onClick={() => navigate(-1)}>← Back to Result</button>
      </div>
    </Layout>
  );
}
