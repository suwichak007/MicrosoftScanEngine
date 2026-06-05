import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import ExportButton from './ExportButton';
import './Summary.css';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

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
            {localStorage.getItem('role') === 'admin' && (
              <>
                <button className="sideLink" onClick={() => navigate('/admin/agents')}>
                  <span className="sideLinkDot" />Agents
                </button>
                <button className="sideLink" onClick={() => navigate('/admin/users')}>
                  <span className="sideLinkDot" />Users
                </button>
              </>
            )}
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
        <ProfileMenu />
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
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function normalizeStatus(value) {
  const text = String(value || '').trim().toLowerCase();
  if (text.startsWith('pass')) return 'pass';
  if (text.startsWith('fail')) return 'fail';
  if (text.includes('manual')) return 'manual';
  return 'unknown';
}

function normalizeSeverity(value, fallbackKey = '') {
  const severity = String(value || '').trim().toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(severity)) return severity;
  return getSeverity(fallbackKey);
}

function parseTargetActual(rawValue) {
  const raw = String(rawValue || '');
  const target = (raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/) || [])[1]?.trim() || '';
  const actual = (raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/) || [])[1]?.trim().replace(/\)\s*$/, '') || '';
  return { target, actual };
}

function normalizeReportItems(scanData) {
  if (Array.isArray(scanData?.findings) && scanData.findings.length > 0) {
    return scanData.findings.map((item, index) => {
      const name = item.check_name || item.source_key || item.check_id || `Check ${index + 1}`;
      const section = item.category || 'General';
      return {
        key: item.source_key || item.check_id || `${section}-${name}-${index}`,
        name,
        section,
        severity: normalizeSeverity(item.severity, `${section} ${name} ${item.source_key || ''}`),
        status: normalizeStatus(item.status),
        target: item.expected_value || '',
        actual: item.current_value || '',
        remediation: item.remediation || '',
        policyPath: item.policy_path || item.registry_path || '',
      };
    });
  }

  return Object.entries(scanData?.details || {}).map(([key, value]) => {
    const sectionMatch = key.match(/^\[([^\]]+)\]/);
    const section = sectionMatch ? sectionMatch[1] : 'General';
    const name = key.replace(/^\[[^\]]+\]\s*/, '');
    const { target, actual } = parseTargetActual(value);
    return {
      key,
      name,
      section,
      severity: normalizeSeverity('', key),
      status: normalizeStatus(value),
      target,
      actual,
      remediation: '',
      policyPath: '',
    };
  });
}

function buildRecommendations(failItems, counts, categoryBreakdown) {
  const recommendations = [];
  const haystack = failItems
    .map((item) => `${item.section} ${item.name} ${item.key}`.toLowerCase())
    .join(' ');

  if (counts.critical + counts.high > 0) {
    recommendations.push({
      title: 'แก้รายการความเสี่ยงสูงก่อน',
      detail: `เริ่มจาก ${counts.critical + counts.high} รายการ Critical/High ก่อน แล้วค่อยไล่เก็บรายการทั่วไป`,
    });
  }
  if (/account|password|lockout/.test(haystack)) {
    recommendations.push({
      title: 'ทบทวน Account Policy',
      detail: 'พบรายการเกี่ยวกับ password, lockout หรือ account control ที่ยังไม่ตรง baseline',
    });
  }
  if (/audit/.test(haystack)) {
    recommendations.push({
      title: 'ตรวจ Audit Policy',
      detail: 'ช่องว่างด้าน audit อาจทำให้ตรวจสอบเหตุการณ์ย้อนหลังได้ไม่ครบ ควรเทียบค่ากับ baseline',
    });
  }
  if (/rdp|remote desktop|ntlm|smb|network/.test(haystack)) {
    recommendations.push({
      title: 'ลดความเสี่ยงด้าน Network Exposure',
      detail: 'ควรจัดลำดับ RDP, SMB, NTLM และ network access control เป็นกลุ่มที่ต้องตรวจเพิ่ม',
    });
  }
  if (/defender|firewall/.test(haystack)) {
    recommendations.push({
      title: 'ปรับ Endpoint Protection ให้แข็งแรงขึ้น',
      detail: 'พบรายการ Defender หรือ Firewall ที่ควรทบทวนเพื่อเพิ่มระดับการป้องกันของเครื่อง',
    });
  }
  if (recommendations.length === 0 && failItems.length > 0) {
    recommendations.push({
      title: 'เริ่มจากหมวดที่ตกมากที่สุด',
      detail: `เริ่มแก้จาก ${categoryBreakdown[0]?.section || 'หมวดหลักที่มีปัญหา'} ก่อน เพื่อลดปัญหาซ้ำ ๆ ในกลุ่มเดียวกัน`,
    });
  }
  if (failItems.length === 0) {
    recommendations.push({
      title: 'รักษาสถานะปัจจุบัน',
      detail: 'ไม่พบรายการที่ fail ใน report นี้ ควร monitor ต่อและสแกนซ้ำหลังมีการเปลี่ยน baseline',
    });
  }
  return recommendations.slice(0, 5);
}

function buildReportSummary(scanData) {
  const items = normalizeReportItems(scanData);
  const failItems = items
    .filter((item) => item.status === 'fail')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || a.section.localeCompare(b.section));
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  failItems.forEach((item) => { severityCounts[item.severity] += 1; });

  const categoryMap = new Map();
  failItems.forEach((item) => {
    const current = categoryMap.get(item.section) || { section: item.section, count: 0, critical: 0, high: 0 };
    current.count += 1;
    if (item.severity === 'critical') current.critical += 1;
    if (item.severity === 'high') current.high += 1;
    categoryMap.set(item.section, current);
  });
  const categoryBreakdown = Array.from(categoryMap.values())
    .sort((a, b) => (b.count - a.count) || (b.critical - a.critical) || a.section.localeCompare(b.section))
    .slice(0, 8);

  return {
    items,
    failItems,
    passCount: items.filter((item) => item.status === 'pass').length,
    manualCount: items.filter((item) => item.status === 'manual').length,
    failCount: failItems.length,
    totalCount: items.length,
    severityCounts,
    categoryBreakdown,
    topCategory: categoryBreakdown[0]?.section || 'None',
    topControls: failItems.slice(0, 10),
    recommendations: buildRecommendations(failItems, severityCounts, categoryBreakdown),
    context: {
      target: scanData?.targetName || scanData?.target_name || scanData?.hostname || 'Unknown target',
      hostname: scanData?.hostname || scanData?.targetName || '-',
      version: scanData?.version || '-',
      scanId: scanData?.scan_id || '-',
      score: Number(scanData?.score || 0),
    },
  };
}

export default function Summary() {
  const navigate = useNavigate();
  const location = useLocation();

  const scanData = useMemo(() => {
    if (location.state?.scanData) return location.state.scanData;
    const saved = sessionStorage.getItem('scanResult');
    return saved ? JSON.parse(saved) : null;
  }, [location.state]);

  const [llmData,      setLlmData]      = useState(null);
  const [llmPhase,     setLlmPhase]     = useState('loading_model');
  const [tokenCount,   setTokenCount]   = useState(0);
  const [tokensPerSec, setTokensPerSec] = useState(0);
  const [elapsed,      setElapsed]      = useState(0);
  const [phaseMsg,     setPhaseMsg]     = useState('');
  const [loading,      setLoading]      = useState(false);
  const [llmError,     setLlmError]     = useState('');
  const report = useMemo(() => buildReportSummary(scanData || {}), [scanData]);

  const failItems = report.failItems;
  const counts = report.severityCounts;
  const passCount = report.passCount;
  const totalCount = report.totalCount;
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
        const res = await fetch(apiUrl('/api/summary/stream'), {
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
  }, [scanData, failItems, passCount, totalCount, counts, navigate]);

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

      <div className="sumHeader">
        <div>
          <h1 className="sumTitle">Security Summary Report</h1>
          <p className="sumSubtitle">สรุปความเสี่ยง หมวดที่ตกบ่อย และสิ่งที่ควรแก้ก่อน</p>
        </div>
        <div className="sumHeaderActions">
          <button className="sumBackBtn" onClick={() => navigate('/history')}>Compare</button>
          <ExportButton scanId={scanData?.scan_id} />
        </div>
      </div>

      <div className="sumScoreBar">
        <ScoreRing score={report.context.score} />
        <div className="sumScoreMeta">
          <div className="sumTarget">{report.context.target}</div>
          <div className="sumVersion">{report.context.version}</div>
          <div className="sumBadgeRow">
            <span className="badge pass">{passCount} Pass</span>
            <span className="badge fail">{report.failCount} Fail</span>
            <span className="badge manual">{report.manualCount} Manual</span>
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

      <div className="sumMetricGrid">
        <div className="sumMetricCard">
          <span className="sumMetricLabel">รายการที่ Fail</span>
          <strong className="sumMetricValue">{report.failCount}</strong>
          <span className="sumMetricHint">of {totalCount || 0} total</span>
        </div>
        <div className="sumMetricCard critical">
          <span className="sumMetricLabel">Critical / High</span>
          <strong className="sumMetricValue">{counts.critical + counts.high}</strong>
          <span className="sumMetricHint">ควรแก้ก่อน</span>
        </div>
        <div className="sumMetricCard">
          <span className="sumMetricLabel">รอตรวจ Manual</span>
          <strong className="sumMetricValue">{report.manualCount}</strong>
          <span className="sumMetricHint">ต้องตรวจยืนยัน</span>
        </div>
        <div className="sumMetricCard">
          <span className="sumMetricLabel">หมวดที่ตกมากสุด</span>
          <strong className="sumMetricValue textValue">{report.topCategory}</strong>
          <span className="sumMetricHint">มี fail มากที่สุด</span>
        </div>
      </div>

      <section className="sumReportGrid">
        <div className="sumPanel fixPanel">
          <div className="sumPanelHead">
            <h2>รายการที่ควรแก้ก่อน</h2>
            <span>Top {report.topControls.length}</span>
          </div>
          <div className="fixList">
            {report.topControls.length === 0 ? (
              <div className="sumSoftEmpty">ไม่พบรายการที่ fail ควร monitor ต่อและสแกนซ้ำหลังมีการเปลี่ยนแปลง</div>
            ) : report.topControls.map((item) => {
              const sev = SEV_CONFIG[item.severity] || SEV_CONFIG.low;
              return (
                <div className="fixItem" key={item.key} style={{ borderLeftColor: sev.color }}>
                  <div className="fixTop">
                    <span className="dcSev" style={{ color: sev.color, background: sev.bg, border: `1px solid ${sev.bd}` }}>{sev.label}</span>
                    <span className="fixSection">{item.section}</span>
                  </div>
                  <strong className="fixName">{item.name}</strong>
                  <div className="fixValues">
                    <span><b>Expected:</b> {item.target || '-'}</span>
                    <span><b>Actual:</b> {item.actual || '-'}</span>
                  </div>
                  {item.policyPath && <div className="fixPath">{item.policyPath}</div>}
                </div>
              );
            })}
          </div>
        </div>

        <aside className="sumSideStack">
          <div className="sumPanel">
            <div className="sumPanelHead">
              <h2>สิ่งที่ควรทำต่อ</h2>
            </div>
            <div className="recommendationList">
              {report.recommendations.map((item) => (
                <div className="recommendationItem" key={item.title}>
                  <strong>{item.title}</strong>
                  <span>{item.detail}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="sumPanel">
            <div className="sumPanelHead">
              <h2>สรุปตามหมวด</h2>
              <span>{report.categoryBreakdown.length} categories</span>
            </div>
            <div className="categoryList">
              {report.categoryBreakdown.length === 0 ? (
                <div className="sumSoftEmpty">ไม่พบหมวดที่มีรายการ fail</div>
              ) : report.categoryBreakdown.map((item) => {
                const width = `${Math.max(8, Math.round((item.count / Math.max(report.failCount, 1)) * 100))}%`;
                return (
                  <div className="categoryRow" key={item.section}>
                    <div className="categoryTop">
                      <strong>{item.section}</strong>
                      <span>{item.count} fail</span>
                    </div>
                    <div className="categoryTrack"><div className="categoryFill" style={{ width }} /></div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="sumPanel">
            <div className="sumPanelHead">
              <h2>ข้อมูลของรายงาน</h2>
            </div>
            <div className="contextGrid compact">
              <div><span>Target</span><strong>{report.context.target}</strong></div>
              <div><span>Hostname</span><strong>{report.context.hostname}</strong></div>
              <div><span>Baseline</span><strong>{report.context.version}</strong></div>
              <div><span>Scan ID</span><strong>{report.context.scanId}</strong></div>
            </div>
          </div>
        </aside>
      </section>

      <div className="sumCard aiCard">
        <section className="sumSection aiSection">
          <div className="sumSectionHeader aiHeader">
            <div>
              <span className="aiEyebrow">AI Context</span>
              <h2 className="sumSectionTitle">คำอธิบายเสริมจาก AI</h2>
            </div>
            <span className="aiStatus">{loading ? 'กำลังวิเคราะห์' : llmData ? 'พร้อมอ่าน' : 'รอผลวิเคราะห์'}</span>
          </div>
          {loading && (
            <LlmProgressBar
              phase={llmPhase}
              tokenCount={tokenCount}
              tokensPerSec={tokensPerSec}
              elapsed={elapsed}
              message={phaseMsg}
            />
          )}
          {llmError && !loading && <div className="llmError">{llmError}</div>}

          <div className="aiInsightGrid">
            <div className="aiPrimaryNote">
              <span className="aiNoteLabel">ภาพรวม</span>
              <div className="aiNoteText">
                {llmData?.overview
                  ? <TypewriterText text={llmData.overview} speed={8} />
                  : <span className="sumPlaceholder">กำลังรอ AI วิเคราะห์ ส่วนสรุปแบบ rule-based ด้านบนพร้อมใช้งานแล้ว</span>}
              </div>
            </div>

            <div className="aiSecondaryNotes">
              <div className="aiNoteCard">
                <span className="aiNoteLabel">ประเด็นที่ควรอ่านประกอบ</span>
                {llmData?.detected?.length ? (
                  <ul className="aiBulletList">
                    {llmData.detected.slice(0, 4).map((item, index) => (
                      <li key={`${item.name}-${index}`}>
                        <strong>{item.name}</strong>
                        <span>{item.why || `${item.section || 'General'} ถูกจัดเป็น ${item.severity || 'risk item'}`}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="sumPlaceholder">AI จะสรุปเหตุผลประกอบเมื่อวิเคราะห์เสร็จ</span>
                )}
              </div>

              <div className="aiNoteCard">
                <span className="aiNoteLabel">คำแนะนำเสริม</span>
                <div className="aiNoteText compactText">
                  {llmData?.recommendation
                    ? <TypewriterText text={llmData.recommendation} speed={6} />
                    : <span className="sumPlaceholder">ใช้ “สิ่งที่ควรทำต่อ” ด้านบนเป็นแนวทางหลักระหว่างรอ AI</span>}
                </div>
              </div>
            </div>
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

