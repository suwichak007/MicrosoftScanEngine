import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import './Summary.css';

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
  if (lower.includes('remote desktop'))   return 'critical';
  if (lower.includes('bitlocker'))        return 'critical';
  if (lower.includes('lsa protection'))   return 'critical';
  if (lower.includes('credential'))       return 'critical';
  if (lower.includes('account lockout'))  return 'high';
  if (lower.includes('logon'))            return 'high';
  if (lower.startsWith('[advanced audit]')) return 'medium';
  if (lower.startsWith('[services]'))       return 'low';
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k)))     return 'high';
  if (MEDIUM_KEYWORDS.some(k => lower.includes(k)))   return 'medium';
  return 'low';
}

const SEV_CONFIG = {
  critical: { label: 'Critical', color: '#ff4d4d', bg: 'rgba(255,77,77,0.15)' },
  high:     { label: 'High',     color: '#ff9900', bg: 'rgba(255,153,0,0.15)' },
  medium:   { label: 'Medium',   color: '#f5d000', bg: 'rgba(245,208,0,0.15)' },
  low:      { label: 'Low',      color: '#2ea3ff', bg: 'rgba(46,163,255,0.15)' },
};

// ─── Layout ───────────────────────────────────────────────────────────────────
function Layout({ children, navigate }) {
  return (
    <div className="sumPage">
      <header className="topBar">
        <div className="brand">Scanner</div>
        <div className="topBarRight">
          <div className="bellWrapper">
            <span className="bellIcon">🔔</span>
            <span className="notificationDot" />
          </div>
          <div className="profileCircle">👤</div>
        </div>
      </header>
      <div className="homeLayout">
        <aside className="sideBar">
          <div className="menuGroup">
            <button className="menuItem" onClick={() => navigate('/home')}>Home</button>
            <button className="menuItem" onClick={() => navigate('/history')}>History</button>
            <button className="menuItem" onClick={() => navigate('/guide')}>Guide</button>
          </div>
          <button className="logoutButton" onClick={() => navigate('/')}>
            <span className="logoutIcon">↪</span><span>Log Out</span>
          </button>
        </aside>
        <main className="sumMain">{children}</main>
      </div>
    </div>
  );
}

// ─── Typewriter text ──────────────────────────────────────────────────────────
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

// ─── Score ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score }) {
  const color = score >= 70 ? '#20d320' : score >= 40 ? '#f5d000' : '#ff4d4d';
  return (
    <div className="scoreRingWrap">
      <svg viewBox="0 0 100 100" className="scoreRingSvg">
        <circle cx="50" cy="50" r="42" className="scoreTrack" />
        <circle cx="50" cy="50" r="42" className="scoreArc"
          strokeDasharray={`${score * 2.638} 263.8`}
          transform="rotate(-90 50 50)"
          style={{ stroke: color }}
        />
      </svg>
      <div className="scoreRingText" style={{ color }}>{score}%</div>
    </div>
  );
}

// ─── LLM Progress Indicator (แสดงระหว่าง LLM กำลังคิด) ──────────────────────
const PHASE_INFO = {
  loading_model: { icon: '⚙️',  label: 'โหลด Model',      color: '#888' },
  generating:    { icon: '🧠',  label: 'LLM กำลังวิเคราะห์', color: '#2ea3ff' },
  parsing:       { icon: '🔧',  label: 'แปลงผลลัพธ์',      color: '#f5d000' },
  done:          { icon: '✅',  label: 'เสร็จสิ้น',         color: '#20d320' },
  error:         { icon: '❌',  label: 'เกิดข้อผิดพลาด',    color: '#ff4d4d' },
};

function LlmProgressBar({ phase, tokenCount, tokensPerSec, elapsed, message }) {
  const info = PHASE_INFO[phase] || PHASE_INFO.generating;

  // Progress bar % ประมาณจาก token count (target ~600 tokens)
  const barPct = phase === 'done'
    ? 100
    : phase === 'parsing'
    ? 95
    : phase === 'loading_model'
    ? 5
    : Math.min(90, Math.round((tokenCount / 600) * 85) + 10);

  return (
    <div className="llmProgress">
      {/* Phase badge */}
      <div className="llmPhaseRow">
        <span className="llmPhaseIcon">{info.icon}</span>
        <span className="llmPhaseLabel" style={{ color: info.color }}>{info.label}</span>
        {phase === 'generating' && (
          <span className="llmPulse" />
        )}
      </div>

      {/* Progress bar */}
      <div className="llmBar">
        <div
          className="llmBarFill"
          style={{
            width: `${barPct}%`,
            background: info.color,
            transition: 'width 0.4s ease',
          }}
        />
      </div>

      {/* Stats row */}
      <div className="llmStatsRow">
        {phase === 'generating' && (
          <>
            <span className="llmStat">
              <span className="llmStatLabel">เวลา</span>
              <span className="llmStatVal" style={{ color: '#2ea3ff' }}>{elapsed}s</span>
            </span>
            {tokensPerSec !== '~' && tokensPerSec > 0 && (
              <span className="llmStat">
                <span className="llmStatLabel">tok/s</span>
                <span className="llmStatVal" style={{ color: '#f5d000' }}>{tokensPerSec}</span>
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

      {/* Dev log — terminal-style, เห็นชัดสำหรับ dev */}
      <div className="llmDevLog">
        {phase === 'generating' && elapsed > 0
          ? `› LLM running... ${elapsed}s elapsed${tokensPerSec !== '~' ? ` | ${tokenCount} tokens @ ${tokensPerSec} tok/s` : ' | computing...'}`
          : `› ${message || phase}`
        }
      </div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────
export default function Summary() {
  const navigate = useNavigate();
  const location = useLocation();
  const apiHost  = window.location.hostname;

  const scanData = location.state?.scanData || null;

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
        const tgt      = (raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/) || [])[1]?.trim() || '';
        const act      = (raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/) || [])[1]?.trim().replace(/\)\s*$/, '') || '';
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

  // ─── SSE streaming call ───────────────────────────────────────────────────
  useEffect(() => {
    if (!scanData) return;

    setLoading(true);
    setLlmError('');
    setLlmPhase('loading_model');
    setTokenCount(0);
    setPhaseMsg('กำลังเชื่อมต่อ...');

    const top30 = failItems.slice(0, 30).map(i => ({
      name:     i.name,
      section:  i.section,
      severity: i.severity,
      target:   i.target,
      actual:   i.actual,
    }));

    const body = JSON.stringify({
      score:       scanData.score,
      target_name: scanData.targetName || scanData.hostname,
      version:     scanData.version,
      pass_count:  passCount,
      total_count: totalCount,
      fail_items:  top30,
    });

    // SSE ผ่าน fetch (ต้องใช้ fetch ไม่ใช่ EventSource เพราะต้องส่ง POST + body)
    let aborted = false;
    const controller = new AbortController();

    (async () => {
      try {
        const res = await fetch(`http://${apiHost}:8000/api/summary/stream`, {
          method: 'POST',
          headers: {
            'Content-Type':  'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
          },
          body,
          signal: controller.signal,
        });

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

          // Parse SSE messages จาก buffer
          const messages = buffer.split('\n\n');
          buffer = messages.pop() || ''; // เก็บ incomplete message ไว้

          for (const msg of messages) {
            if (!msg.trim()) continue;

            // หา event type และ data
            const eventMatch = msg.match(/^event:\s*(.+)$/m);
            const dataMatch  = msg.match(/^data:\s*(.+)$/m);
            if (!eventMatch || !dataMatch) continue;

            const event = eventMatch[1].trim();
            let   data;
            try { data = JSON.parse(dataMatch[1]); } catch { continue; }

            // ─── Handle events ───────────────────────────────────────────
            if (event === 'phase') {
              setLlmPhase(data.phase);
              setPhaseMsg(data.message || '');
              if (data.phase === 'done') {
                setLoading(false);
              }
            }

            else if (event === 'token') {
              setTokenCount(data.count);
              setTokensPerSec(data.tokens_per_sec);
              setElapsed(data.elapsed);
              // เมื่อได้ token event แสดงว่า LLM ยัง alive — อัปเดต phase message
              if (data.tokens_per_sec === '~') {
                setPhaseMsg(`LLM กำลังคิด... ผ่านมาแล้ว ${data.elapsed}s`);
              }
            }

            else if (event === 'result') {
              setLlmData(data);
            }

            else if (event === 'error') {
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

    return () => {
      aborted = true;
      controller.abort();
    };
  }, [scanData]);

  // ─── Export ───────────────────────────────────────────────────────────────
  const handleExport = () => {
    if (!llmData) return;
    const lines = [
      `Security Summary Report`,
      `Target : ${scanData?.targetName || scanData?.hostname}`,
      `Version: ${scanData?.version}`,
      `Score  : ${scanData?.score}%`,
      `Date   : ${new Date().toLocaleString()}`,
      '',
      '=== OVERVIEW ===',
      llmData.overview,
      '',
      '=== DETECTED FINDINGS ===',
      ...(llmData.detected || []).map(d =>
        `[${d.severity?.toUpperCase()}] ${d.name} | Current: ${d.actual || 'N/A'} | Required: ${d.target || 'N/A'}`
      ),
      '',
      '=== RECOMMENDATION ===',
      llmData.recommendation,
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `security-summary-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setExported(true);
    setTimeout(() => setExported(false), 2000);
  };

  // ─── Guard ────────────────────────────────────────────────────────────────
  if (!scanData) {
    return (
      <Layout navigate={navigate}>
        <div className="sumEmpty">
          <div className="sumEmptyIcon">📋</div>
          <div className="sumEmptyText">ไม่พบข้อมูลการสแกน</div>
          <button className="sumBackBtn" onClick={() => navigate('/home')}>กลับหน้าหลัก</button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <div className="sumHeader">
        <h1 className="sumTitle">Report</h1>
        <button
          className={`exportBtn ${exported ? 'exported' : ''}`}
          onClick={handleExport}
          disabled={!llmData}
        >
          {exported ? '✓ Exported' : 'Export'}
        </button>
      </div>

      {/* ── Score bar ── */}
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
              <span key={sev} className="sevPill"
                style={{ color: cfg.color, border: `1px solid ${cfg.color}`, background: cfg.bg }}>
                {cfg.label}: {counts[sev]}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main card ── */}
      <div className="sumCard">

        {/* ── Progress indicator — แสดงตลอดระหว่าง loading ── */}
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

        {/* ── Error ── */}
        {llmError && !loading && (
          <div className="sumSection">
            <div className="llmError">⚠️ {llmError}</div>
          </div>
        )}

        {/* ── SECTION 1: Summary overview ── */}
        <section className="sumSection">
          <div className="sumSectionHeader">
            <span className="sumSectionIcon">🛡️</span>
            <h2 className="sumSectionTitle">Summary</h2>
          </div>
          <div className="sumTextBox">
            {llmData?.overview && (
              <TypewriterText text={llmData.overview} speed={10} />
            )}
            {loading && !llmData && (
              <span className="sumPlaceholder">รอ LLM วิเคราะห์...</span>
            )}
          </div>
        </section>

        <div className="sumDivider" />

        {/* ── SECTION 2: Detected Summary ── */}
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
                  <div key={i} className="detectedCard"
                    style={{ borderLeft: `3px solid ${sev.color}` }}>
                    <div className="dcTop">
                      <span className="dcSev" style={{ color: sev.color, background: sev.bg }}>{sev.label}</span>
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

        {/* ── SECTION 3: Recommendation ── */}
        <section className="sumSection">
          <div className="sumSectionHeader">
            <span className="sumSectionIcon">💡</span>
            <h2 className="sumSectionTitle">Recommendation</h2>
          </div>
          <div className="sumTextBox">
            {llmData?.recommendation && (
              <TypewriterText text={llmData.recommendation} speed={8} />
            )}
            {loading && !llmData && (
              <span className="sumPlaceholder">รอผลการวิเคราะห์...</span>
            )}
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