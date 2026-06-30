import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import ExportButton from './ExportButton';
import './Summary.css';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  MetricCard,
  MetricGrid,
  ReportHeader,
  ReportShell,
  ReportTopbar,
} from './ReportUI';
import { formatReportDate } from './reportUtils';

//  Severity helpers 
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

const SEVERITY_CHART_COLORS = {
  critical: '#c2413b',
  high: '#d97706',
  medium: '#2563eb',
  low: '#64748b',
};

const NIST_LABELS = {
  AC: { name: 'Access Control', detail: 'User rights, logon access, remote access, and permission boundaries' },
  AU: { name: 'Audit & Accountability', detail: 'Audit policy, event logging, and traceability settings' },
  CM: { name: 'Configuration Management', detail: 'Security baseline, hardening policy, services, and system configuration' },
  IA: { name: 'Identity & Authentication', detail: 'Password, credential, Kerberos, and authentication settings' },
  SC: { name: 'System & Communications Protection', detail: 'Firewall, SMB, RDP, TLS, and network protection settings' },
  SI: { name: 'System & Information Integrity', detail: 'Defender, malware protection, and endpoint integrity settings' },
};

const CIS_LABELS = {
  3: { name: 'Data Protection', detail: 'Encryption, TLS, and protection of sensitive data paths' },
  4: { name: 'Secure Configuration', detail: 'Secure configuration of enterprise assets and software' },
  5: { name: 'Account Management', detail: 'Account lifecycle, password, lockout, and credential controls' },
  6: { name: 'Access Control Management', detail: 'Access rights, privileged access, and authentication controls' },
  8: { name: 'Audit Log Management', detail: 'Logging, audit policy, and event collection controls' },
  10: { name: 'Malware Defenses', detail: 'Antivirus, Defender, and endpoint protection controls' },
  12: { name: 'Network Infrastructure Management', detail: 'Firewall, remote access, and network exposure controls' },
};

//  LLM Phase config 
const PHASE_INFO = {
  loading_model: { icon: '', label: 'Loading model', color: 'var(--ink-lt)' },
  generating:    { icon: '', label: 'Generating analysis', color: 'var(--amber)' },
  parsing:       { icon: '', label: 'Parsing response', color: 'var(--sev-medium)' },
  done:          { icon: '', label: 'Complete', color: 'var(--green)' },
  error:         { icon: '', label: 'Error', color: 'var(--red)' },
};

//  Layout 
function Layout({ children }) {
  return <ReportShell active="History">{children}</ReportShell>;
}

//  Topbar 
function Topbar() {
  return <ReportTopbar />;
}

//  Score Ring 
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

//  Typewriter 
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

//  LLM Progress Bar 
function LlmProgressBar({ phase, tokenCount, tokensPerSec, elapsed, message }) {
  const info = PHASE_INFO[phase] || PHASE_INFO.generating;

  const barPct = phase === 'done'         ? 100
               : phase === 'parsing'      ? 95
               : phase === 'loading_model' ? 5
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
              <span className="llmStatLabel">elapsed</span>
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
          ? ` LLM running... ${elapsed}s elapsed${tokensPerSec !== '~' ? ` | ${tokenCount} tokens @ ${tokensPerSec} tok/s` : ' | computing...'}`
          : ` ${message || phase}`}
      </div>
    </div>
  );
}

//  Main 
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
        frameworks: item.frameworks || { nist: [], cis: [] },
      };
    });
  }

  return Object.entries(scanData?.details || {})
    .filter(([key]) => !String(key).startsWith('_'))
    .map(([key, value]) => {
    const isObject = value && typeof value === 'object' && !Array.isArray(value);
    const sectionMatch = key.match(/^\[([^\]]+)\]/);
    const section = isObject ? (value.category || value.section || 'General') : (sectionMatch ? sectionMatch[1] : 'General');
    const name = isObject ? (value.check_name || value.name || key) : key.replace(/^\[[^\]]+\]\s*/, '');
    const { target, actual } = isObject ? { target: '', actual: '' } : parseTargetActual(value);
    return {
      key,
      name,
      section,
      severity: normalizeSeverity(isObject ? value.severity : '', `${section} ${name} ${key}`),
      status: normalizeStatus(isObject ? value.status : value),
      target: isObject ? (value.expected_value || value.target || '') : target,
      actual: isObject ? (value.current_value || value.actual || '') : actual,
      remediation: isObject ? (value.remediation || '') : '',
      policyPath: isObject ? (value.policy_path || value.registry_path || '') : '',
      frameworks: isObject ? (value.frameworks || { nist: [], cis: [] }) : { nist: [], cis: [] },
    };
  });
}

function buildFrameworkImpact(failItems) {
  const impact = { nist: new Map(), cis: new Map() };
  failItems.forEach((item) => {
    ['nist', 'cis'].forEach((family) => {
      (item.frameworks?.[family] || []).forEach((code) => {
        const key = String(code);
        const current = impact[family].get(key) || { code: key, failed: 0, critical: 0, high: 0 };
        current.failed += 1;
        if (item.severity === 'critical') current.critical += 1;
        if (item.severity === 'high') current.high += 1;
        impact[family].set(key, current);
      });
    });
  });
  const sortImpact = (rows) => Array.from(rows.values())
    .sort((a, b) => (b.failed - a.failed) || (b.critical - a.critical) || a.code.localeCompare(b.code))
    .slice(0, 6);
  return { nist: sortImpact(impact.nist), cis: sortImpact(impact.cis) };
}

function FrameworkImpactRows({ title, countLabel, rows, labels, totalAssessed }) {
  const denominator = Math.max(Number(totalAssessed || 0), 1);
  return (
    <div className="frameworkGroup">
      <div className="frameworkGroupHead">
        <strong>{title}</strong>
        <span>{rows.length} {countLabel}</span>
      </div>
      {rows.map((item) => {
        const meta = labels[item.code] || { name: item.code, detail: 'Mapped baseline control area' };
        const pct = Math.round((item.failed / denominator) * 100);
        return (
          <div className="frameworkImpactRow" key={`${title}-${item.code}`}>
            <div className="frameworkImpactTop">
              <span className="frameworkCode">{item.code}</span>
              <div className="frameworkText">
                <strong>{meta.name}</strong>
                <span>{meta.detail}</span>
              </div>
              <b>{item.failed} fail · {pct}%</b>
            </div>
            <div className="categoryTrack">
              <div className="categoryFill" style={{ width: `${Math.max(4, Math.min(100, pct))}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function buildRecommendations(failItems, counts, categoryBreakdown) {
  const recommendations = [];
  const haystack = failItems
    .map((item) => `${item.section} ${item.name} ${item.key}`.toLowerCase())
    .join(' ');

  if (counts.critical + counts.high > 0) {
    recommendations.push({
      title: 'Fix high-risk findings first',
      detail: `Start with ${counts.critical + counts.high} Critical/High findings, then continue with medium and low-risk items.`,
    });
  }
  if (/account|password|lockout/.test(haystack)) {
    recommendations.push({
      title: 'Review account policies',
      detail: 'Password, lockout, or account control settings do not match the selected baseline.',
    });
  }
  if (/audit/.test(haystack)) {
    recommendations.push({
      title: 'Review audit policy',
      detail: 'Audit settings affect incident visibility and should be aligned with the baseline.',
    });
  }
  if (/rdp|remote desktop|ntlm|smb|network/.test(haystack)) {
    recommendations.push({
      title: 'Reduce network exposure',
      detail: 'Review RDP, SMB, NTLM, and network access settings for unnecessary exposure.',
    });
  }
  if (/defender|firewall/.test(haystack)) {
    recommendations.push({
      title: 'Strengthen endpoint protection',
      detail: 'Defender or Firewall findings should be fixed to improve host-level protection.',
    });
  }
  if (recommendations.length === 0 && failItems.length > 0) {
    recommendations.push({
      title: 'Start with the most affected category',
      detail: `Prioritize ${categoryBreakdown[0]?.section || 'the category with the most findings'} because it has the highest concentration of failed checks.`,
    });
  }
  if (failItems.length === 0) {
    recommendations.push({
      title: 'Maintain current posture',
      detail: 'No failed checks were found in this report. Continue monitoring and rescan after baseline changes.',
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
    frameworkImpact: buildFrameworkImpact(failItems),
    context: {
      target: scanData?.targetName || scanData?.target_name || scanData?.hostname || 'Unknown target',
      hostname: scanData?.hostname || scanData?.targetName || '-',
      version: scanData?.version || '-',
      scanId: scanData?.scan_id || '-',
      scanDate: scanData?.scan_date || '',
      score: Number(scanData?.score || 0),
      scoreBreakdown: scanData?.score_breakdown || scanData?.details?._score_breakdown || null,
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
  const [aiOpen,       setAiOpen]       = useState(false);
  const [postureChange, setPostureChange] = useState(null);
  const report = useMemo(() => buildReportSummary(scanData || {}), [scanData]);
  const severityChartData = useMemo(() => (
    Object.entries(report.severityCounts)
      .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value, key: name }))
      .filter((item) => item.value > 0)
  ), [report.severityCounts]);
  const categoryChartData = useMemo(() => (
    report.categoryBreakdown.slice(0, 6).map((item) => ({
      name: item.section.length > 22 ? `${item.section.slice(0, 22)}...` : item.section,
      failed: item.count,
    }))
  ), [report.categoryBreakdown]);

  const failItems = report.failItems;
  const counts = report.severityCounts;
  const passCount = report.passCount;
  const totalCount = report.totalCount;

  useEffect(() => {
    const scanId = Number(scanData?.scan_id || 0);
    if (!scanId) return;
    let cancelled = false;
    (async () => {
      try {
        const candidateRes = await fetch(apiUrl(`/api/scan/history/${scanId}/compare-candidates`), { headers: authHeaders() });
        if (!candidateRes.ok) return;
        const candidates = await candidateRes.json();
        if (!Array.isArray(candidates) || !candidates.length) return;
        const base = candidates.find((item) => item.same_baseline) || candidates[0];
        if (!base) return;
        const compareRes = await fetch(
          apiUrl(`/api/scan/history/${scanId}/compare/${base.id}`),
          { headers: authHeaders() },
        );
        if (!compareRes.ok) return;
        const data = await compareRes.json();
        if (!cancelled) setPostureChange(data);
      } catch {
        // Posture change is supplemental and must not block the report.
      }
    })();
    return () => { cancelled = true; };
  }, [scanData?.scan_id]);

  //  SSE streaming 
  useEffect(() => {
    if (!scanData) return;

    setLoading(true);
    setLlmError('');
    setLlmPhase('loading_model');
    setTokenCount(0);
    setPhaseMsg('Preparing AI analysis...');

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
                setPhaseMsg(`AI analysis running... ${data.elapsed}s elapsed`);
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

  //  Export 

  //  Guard 
  if (!scanData) {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="sumEmpty">
          <div className="sumEmptyIcon"></div>
          <div className="sumEmptyText">No scan data available</div>
          <button className="sumEmptyBtn" onClick={() => navigate('/home')}>Back to Home</button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <Topbar />

      <ReportHeader
        eyebrow="Executive security summary"
        title={report.context.target}
        subtitle="Prioritized compliance posture, risk concentration, and recommended remediation actions."
        score={report.context.score}
        context={[
          { label: 'Baseline', value: report.context.version },
          { label: 'Scan ID', value: report.context.scanId },
          { label: 'Scanned', value: report.context.scanDate ? formatReportDate(report.context.scanDate) : 'Current report' },
          {
            label: 'Posture change',
            value: postureChange
              ? `${postureChange.score_delta > 0 ? '+' : ''}${postureChange.score_delta} points vs #${postureChange.base_scan_id}`
              : 'No compatible earlier scan',
          },
        ]}
        actions={(
          <>
            <button
              className="reportAction secondary"
              onClick={() => navigate(scanData?.scan_id ? `/history?compare=${scanData.scan_id}` : '/history')}
            >
              Compare
            </button>
            <ExportButton scanId={scanData?.scan_id} appearance="report" />
            <button
              className="reportAction primary"
              onClick={() => navigate(scanData?.scan_id ? `/scan/${scanData.scan_id}/report` : -1)}
            >
              Findings
            </button>
          </>
        )}
      />

      <MetricGrid>
        <MetricCard label="Assessed checks" value={report.passCount + report.failCount} hint={`${report.passCount} passed`} tone="info" />
        <MetricCard label="Failed checks" value={report.failCount} hint={`of ${totalCount} total`} tone="fail" />
        <MetricCard label="Critical / High" value={counts.critical + counts.high} hint="Risk priority" tone="critical" />
        <MetricCard label="Manual review" value={report.manualCount} hint="Excluded from score" tone="warn" />
        <MetricCard
          label="Posture change"
          value={postureChange ? `${postureChange.score_delta > 0 ? '+' : ''}${postureChange.score_delta}` : '-'}
          hint={postureChange ? `${postureChange.counts.fixed} fixed · ${postureChange.counts.newly_failed} new` : 'No previous scan'}
          tone={postureChange?.score_delta >= 0 ? 'pass' : 'fail'}
        />
      </MetricGrid>

      <div className="sumHeader legacySummaryIntro">
        <div>
          <h1 className="sumTitle">Security Summary Report</h1>
          <p className="sumSubtitle">Decision-ready risk summary, failed categories, and recommended next actions</p>
        </div>
        <div className="sumHeaderActions">
          <button
            className="sumBackBtn"
            onClick={() => navigate(
              scanData?.scan_id ? `/history?compare=${scanData.scan_id}` : '/history',
            )}
          >
            Compare
          </button>
          <ExportButton scanId={scanData?.scan_id} />
        </div>
      </div>

      <div className="sumScoreBar legacySummaryIntro">
        <ScoreRing score={report.context.score} />
        <div className="sumScoreMeta">
          <div className="sumTarget">{report.context.target}</div>
          <div className="sumVersion">{report.context.version}</div>
          <div className="sumVersion">Compliance Score</div>
          {report.context.scoreBreakdown && (
            <div className="sumVersion">
              Assessed pass rate {report.context.scoreBreakdown.passed_assessed_count ?? report.context.scoreBreakdown.passed_weight}/{report.context.scoreBreakdown.total_assessed_count ?? report.context.scoreBreakdown.assessed_weight}
              {report.context.scoreBreakdown.excluded_manual_count ? ` · ${report.context.scoreBreakdown.excluded_manual_count} manual excluded` : ''}
              {report.context.scoreBreakdown.excluded_na_count ? ` · ${report.context.scoreBreakdown.excluded_na_count} N/A excluded` : ''}
            </div>
          )}
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

      <div className="sumMetricGrid legacySummaryIntro">
        <div className="sumMetricCard">
          <span className="sumMetricLabel">Failed Checks</span>
          <strong className="sumMetricValue">{report.failCount}</strong>
          <span className="sumMetricHint">of {totalCount || 0} total</span>
        </div>
        <div className="sumMetricCard critical">
          <span className="sumMetricLabel">Critical / High</span>
          <strong className="sumMetricValue">{counts.critical + counts.high}</strong>
          <span className="sumMetricHint">Fix first</span>
        </div>
        <div className="sumMetricCard">
          <span className="sumMetricLabel">Manual Review</span>
          <strong className="sumMetricValue">{report.manualCount}</strong>
          <span className="sumMetricHint">Requires review</span>
        </div>
        <div className="sumMetricCard">
          <span className="sumMetricLabel">Top Category</span>
          <strong className="sumMetricValue textValue">{report.topCategory}</strong>
          <span className="sumMetricHint">Highest fail count</span>
        </div>
      </div>

      <section className="summaryVisualGrid">
        <div className="summaryVisualPanel">
          <div className="summaryVisualHead">
            <div>
              <h2>Risk severity</h2>
              <p>Failed checks grouped by risk priority</p>
            </div>
            <span>{report.failCount} failed</span>
          </div>
          <div className="summaryChartWrap">
            {severityChartData.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={48}
                    outerRadius={72}
                    paddingAngle={2}
                  >
                    {severityChartData.map((item) => (
                      <Cell key={item.key} fill={SEVERITY_CHART_COLORS[item.key] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="sumSoftEmpty">No failed checks</div>
            )}
          </div>
          <div className="severityLegend">
            {severityChartData.map((item) => (
              <span key={item.key}>
                <i style={{ background: SEVERITY_CHART_COLORS[item.key] }} />
                {item.name} <b>{item.value}</b>
              </span>
            ))}
          </div>
        </div>

        <div className="summaryVisualPanel categoryChartPanel">
          <div className="summaryVisualHead">
            <div>
              <h2>Most affected categories</h2>
              <p>Top categories by failed control count</p>
            </div>
          </div>
          <div className="summaryChartWrap category">
            {categoryChartData.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryChartData} layout="vertical" margin={{ left: 18, right: 14 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={145} tick={{ fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="failed" fill="#2563eb" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="sumSoftEmpty">No failed categories</div>
            )}
          </div>
        </div>
      </section>

      <section className="sumReportGrid">
        <div className="sumPanel fixPanel">
          <div className="sumPanelHead">
            <h2>Fix First</h2>
            <span>Top {report.topControls.length}</span>
          </div>
          <div className="fixList">
            {report.topControls.length === 0 ? (
              <div className="sumSoftEmpty">No failed checks found. Continue monitoring after baseline changes.</div>
            ) : report.topControls.map((item) => {
              const sev = SEV_CONFIG[item.severity] || SEV_CONFIG.low;
              return (
                <button
                  type="button"
                  className="fixItem"
                  key={item.key}
                  style={{ borderLeftColor: sev.color }}
                  onClick={() => navigate(
                    scanData?.scan_id
                      ? `/scan/${scanData.scan_id}/report?check=${encodeURIComponent(item.key)}`
                      : '/result',
                  )}
                >
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
                </button>
              );
            })}
          </div>
        </div>

        <aside className="sumSideStack">
          <div className="sumPanel">
            <div className="sumPanelHead">
              <h2>Recommended Next Actions</h2>
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
              <h2>Category Breakdown</h2>
              <span>{report.categoryBreakdown.length} categories</span>
            </div>
            <div className="categoryList">
              {report.categoryBreakdown.length === 0 ? (
                <div className="sumSoftEmpty">No failed categories found</div>
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
              <h2>Framework Impact</h2>
              <span>Failed check mapping</span>
            </div>
            <div className="frameworkIntro">
              Percent is based on total assessed checks. One failed check can map to more than one area.
            </div>
            <div className="categoryList">
              {report.frameworkImpact.nist.length === 0 && report.frameworkImpact.cis.length === 0 ? (
                <div className="sumSoftEmpty">No mapped failed controls found</div>
              ) : (
                <>
                  <FrameworkImpactRows
                    title="NIST"
                    countLabel="areas"
                    rows={report.frameworkImpact.nist}
                    labels={NIST_LABELS}
                    totalAssessed={report.context.scoreBreakdown?.total_assessed_count || report.passCount + report.failCount}
                  />
                  <FrameworkImpactRows
                    title="CIS"
                    countLabel="safeguards"
                    rows={report.frameworkImpact.cis}
                    labels={CIS_LABELS}
                    totalAssessed={report.context.scoreBreakdown?.total_assessed_count || report.passCount + report.failCount}
                  />
                </>
              )}
            </div>
          </div>

          <div className="sumPanel">
            <div className="sumPanelHead">
              <h2>Report Context</h2>
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
        <button type="button" className="aiCollapseButton" onClick={() => setAiOpen((open) => !open)}>
          <span>
            <small>Supporting analysis</small>
            <strong>AI Analysis</strong>
          </span>
          <span className={`aiCollapseState ${loading ? 'loading' : ''}`}>
            {loading ? 'Analyzing' : llmData ? 'Ready' : 'Unavailable'} · {aiOpen ? 'Hide' : 'Show'}
          </span>
        </button>
        {aiOpen && (
        <section className="sumSection aiSection">
          <div className="sumSectionHeader aiHeader">
            <div>
              <span className="aiEyebrow">AI Context</span>
              <h2 className="sumSectionTitle">AI Analysis</h2>
            </div>
            <span className="aiStatus">{loading ? 'Analyzing' : llmData ? 'Ready' : 'Waiting for analysis'}</span>
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
              <span className="aiNoteLabel">Overview</span>
              <div className="aiNoteText">
                {llmData?.overview
                  ? <TypewriterText text={llmData.overview} speed={8} />
                  : <span className="sumPlaceholder">Waiting for AI analysis. The rule-based summary above is already available.</span>}
              </div>
            </div>

            <div className="aiSecondaryNotes">
              <div className="aiNoteCard">
                <span className="aiNoteLabel">Detected Risks</span>
                {llmData?.detected?.length ? (
                  <ul className="aiBulletList">
                    {llmData.detected.slice(0, 4).map((item, index) => (
                      <li key={`${item.name}-${index}`}>
                        <strong>{item.name}</strong>
                        <span>{item.why || `${item.section || 'General'} includes ${item.severity || 'risk item'}`}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="sumPlaceholder">AI will list supporting risk observations when available.</span>
                )}
              </div>

              <div className="aiNoteCard">
                <span className="aiNoteLabel">Additional Recommendation</span>
                <div className="aiNoteText compactText">
                  {llmData?.recommendation
                    ? <TypewriterText text={llmData.recommendation} speed={6} />
                    : <span className="sumPlaceholder">Use the recommended next actions above while AI analysis is loading.</span>}
                </div>
              </div>
            </div>
          </div>
        </section>
        )}
      </div>

      {/*  Footer  */}
      <div className="sumFooter">
        <button className="sumBackBtn" onClick={() => navigate(-1)}> Back to Result</button>
      </div>
    </Layout>
  );
}




