import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import './Result.css';
import { authHeaders, clearAuth, useIsAdmin } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

// -----------------------------------------------------------------------
// Severity classification
// -----------------------------------------------------------------------
const CRITICAL_KEYWORDS = ['remote desktop','lsa protection','credential','ntlm','kerberos','bitlocker'];
const HIGH_KEYWORDS = [
  'network access', 'network security', 'user rights', 'privilege',
  'logon', 'encryption', 'tls', 'ssl', 'rdp', 'rpc',
  'anonymous', 'guest', 'sam', 'domain member', 'impersonate',
  'user account control', 'restrict', 'audit', 'signing',
  'inactivity', 'force shutdown',
];
const MEDIUM_KEYWORDS = [
  'autoplay', 'autorun', 'internet explorer', 'smartscreen', 'activex',
  'printer', 'bluetooth', 'wifi', 'hotspot', 'ink workspace', 'xbox',
  'cortana', 'spotlight', 'toast', 'netbios', 'icmp', 'multicast',
];

function getSeverity(key) {
  const lower = key.toLowerCase();
  if (lower.includes('remote desktop')) return 'critical';
  if (lower.includes('bitlocker'))      return 'critical';
  if (lower.includes('lsa protection')) return 'critical';
  if (lower.includes('credential'))     return 'critical';
  if (lower.includes('account lockout')) return 'high';
  if (lower.includes('logon'))           return 'high';
  if (lower.startsWith('[advanced audit]')) return 'medium';
  if (lower.startsWith('[services]'))       return 'low';
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k)))     return 'high';
  if (MEDIUM_KEYWORDS.some(k => lower.includes(k)))   return 'medium';
  return 'low';
}

const SOLUTION_MAP = {
  'account lockout': { text: 'Open secpol.msc > Account Policies > Account Lockout Policy and update the setting to match the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy' },
  'password':        { text: 'Open secpol.msc > Account Policies > Password Policy and update the setting to match the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy' },
  'uac':             { text: 'Open secpol.msc > Local Policies > Security Options and review User Account Control settings.', link: 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/' },
  'firewall':        { text: 'Open Windows Defender Firewall (wf.msc) or Group Policy and update firewall settings.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' },
  'audit':           { text: 'Open secpol.msc > Advanced Audit Policy Configuration and align audit settings with the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings' },
  'defender':        { text: 'Review Microsoft Defender settings in Group Policy or Windows Security.', link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows' },
  'ntlm':            { text: 'Open secpol.msc > Local Policies > Security Options and configure LAN Manager authentication level.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' },
  'smb':             { text: 'Review SMBv1 and SMB signing settings in Registry or Group Policy.', link: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' },
  'lsa':             { text: 'Enable LSA Protection in Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa > RunAsPPL = 1.', link: 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' },
  'remote desktop':  { text: 'Review RDP security in Group Policy > Remote Desktop Services.', link: 'https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-desktop-services' },
  'bitlocker':       { text: 'Open BitLocker Drive Encryption and align encryption settings with the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/' },
  'attack surface':  { text: 'Review Attack Surface Reduction rules in Microsoft Defender or Group Policy.', link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference' },
  'smartscreen':     { text: 'Review Windows Defender SmartScreen settings in Group Policy.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/' },
  'autoplay':        { text: 'Open Group Policy > AutoPlay Policies and disable AutoPlay as required.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/turn-off-autoplay' },
  'user rights':     { text: 'Open secpol.msc > Local Policies > User Rights Assignment and update permissions.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment' },
};

function getSolution(key) {
  const lower = key.toLowerCase();
  for (const [keyword, sol] of Object.entries(SOLUTION_MAP)) {
    if (lower.includes(keyword)) return sol;
  }
  return {
    text: 'Review the setting in Group Policy Editor (gpedit.msc) or Local Security Policy (secpol.msc)',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings',
  };
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'var(--sev-critical)',    bg: 'var(--sev-critical-bg)',    bd: 'var(--sev-critical-bd)' },
  high:     { label: 'High',     color: 'var(--sev-high)',        bg: 'var(--sev-high-bg)',        bd: 'var(--sev-high-bd)' },
  medium:   { label: 'Medium',   color: 'var(--sev-medium)',      bg: 'var(--sev-medium-bg)',      bd: 'var(--sev-medium-bd)' },
  low:      { label: 'Low',      color: 'var(--sev-low)',         bg: 'var(--sev-low-bg)',         bd: 'var(--sev-low-bd)' },
};

const SCAN_STEPS = [
  'Preparing target connection...',
  'Loading Security Baseline...',
  'Checking Security Policy...',
  'Checking Audit Policy...',
  'Checking Registry Settings...',
  'Checking Firewall Rules...',
  'Checking Windows Defender...',
  'Checking Services...',
  'Calculating compliance score...',
  'Completed',
];

const SESSION_KEY = 'scanResult';

function normalizeSeverity(value) {
  const sev = String(value || 'low').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(sev) ? sev : 'low';
}

function normalizeText(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function isNotConfigured(value) {
  const text = normalizeText(value);
  return text === 'not configured' || text.includes('not configured');
}

function isDisabledBaseline(value) {
  const text = normalizeText(value).replace(/[\s\]})>]+$/g, '').replace(/[.,;:]+$/g, '');
  return /^(disabled|disable|off|0|false|no|n\/a)(\b|$)/.test(text);
}

function classifyStatus(rawStatus, targetValue = '', actualValue = '', rawResult = '') {
  const raw = normalizeText(rawStatus);
  const target = normalizeText(targetValue);
  const actual = normalizeText(actualValue);
  const result = normalizeText(rawResult);

  if (raw.includes('manual') || result.includes('manual')) return 'manual';

  if (isNotConfigured(actual) || result.includes('not configured')) {
    return isDisabledBaseline(target) ? 'pass' : 'fail';
  }

  if (raw === 'pass' || raw.includes('pass')) return 'pass';

  if (target && actual && target === actual) return 'pass';

  return 'fail';
}

function parseFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.map((item) => {
    const targetValue = item.expected_value || '';
    const actualValue = item.current_value || 'Not Configured';
    
    // Prefer status from backend when available
    const rawStatus = String(item.status || '').toLowerCase();
    let status;
    if (rawStatus === 'pass') {
      status = 'pass';
    } else if (rawStatus.startsWith('fail')) {
      status = 'fail';
    } else if (rawStatus.includes('manual')) {
      status = 'manual';
    } else {
      status = 'fail';
    }

    const solutionKey = `${item.category || ''} ${item.check_name || ''} ${item.source_key || ''}`.trim();
    const fallbackSolution = getSolution(solutionKey);
    return {
      key: item.source_key || item.check_id || item.check_name,
      checkId: item.check_id || '',
      name: item.check_name || item.source_key || 'Unknown check',
      section: item.category || 'General',
      severity: normalizeSeverity(item.severity),
      solution: {
        text: item.remediation || fallbackSolution.text,
        link: fallbackSolution.link,
      },
      target: targetValue,
      actual: actualValue,
      status,
      raw: item.raw_result || '',
      policyPath: item.policy_path || '',
      registryPath: item.registry_path || '',
    };
  });
}
function parseResults(details, findings = null) {
  const enriched = parseFindings(findings);
  if (enriched.length > 0) return enriched;
  if (!details) return [];
  return Object.entries(details)
    .filter(([key]) => !String(key).startsWith('_'))
    .map(([key, value]) => {
      const sectionMatch = key.match(/^\[([^\]]+)\]/);
      const section  = sectionMatch ? sectionMatch[1] : 'General';
      const name     = key.replace(/^\[[^\]]+\]\s*/, '');
      const severity = getSeverity(key);
      const solution = getSolution(key);

      const raw = String(value);
      let target = '', actual = '';

      const targetMatch = raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/);
      if (targetMatch) target = targetMatch[1].trim();

      const actualMatch = raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/);
      if (actualMatch) actual = actualMatch[1].trim().replace(/\)\s*$/, '');

      const status = classifyStatus(raw, target, actual, raw);

      return { key, name, section, severity, solution, target, actual, status, raw };
    });
}

function parseRegistryLocationEntries(registryPath) {
  return String(registryPath || '')
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const bangIndex = entry.indexOf('!');
      if (bangIndex === -1) return { keyPath: entry, valueName: '' };
      return {
        keyPath: entry.slice(0, bangIndex).trim(),
        valueName: entry.slice(bangIndex + 1).trim(),
      };
    });
}

function getPolicyTool(policyPath = '', section = '', name = '') {
  const text = `${policyPath} ${section} ${name}`.toLowerCase();
  if (
    text.includes('password policy') ||
    text.includes('account lockout') ||
    text.includes('user rights') ||
    text.includes('security options') ||
    text.includes('audit policy') ||
    text.includes('local policies')
  ) {
    return 'secpol.msc';
  }
  if (text.includes('firewall')) return 'wf.msc';
  return 'gpedit.msc';
}

function buildSettingLocationGuide(item, context = {}) {
  if (!item || item.status !== 'fail') return { available: false };

  const policyPath = String(item.policyPath || '').trim();
  const registryEntries = parseRegistryLocationEntries(item.registryPath);
  const hasRegistry = registryEntries.length > 0;
  if (!policyPath && !hasRegistry) return { available: false };

  const openTool = policyPath ? getPolicyTool(policyPath, item.section, item.name) : 'regedit.exe';
  const lines = [
    `Target: ${context.hostname || context.targetName || 'Target machine'}`,
    `Check ID: ${item.checkId || item.key || '-'}`,
    `Check Name: ${item.name || '-'}`,
    `Open Tool: ${openTool}`,
  ];

  if (policyPath) lines.push(`Policy Path: ${policyPath}`);
  registryEntries.forEach((entry, index) => {
    const label = registryEntries.length > 1 ? `Registry ${index + 1}` : 'Registry';
    lines.push(`${label} Key: ${entry.keyPath}`);
    if (entry.valueName) lines.push(`${label} Value: ${entry.valueName}`);
  });
  lines.push(`Required Value: ${item.target || '-'}`);
  lines.push(`Current Value: ${item.actual || 'Not Configured'}`);
  lines.push(`Solution: ${item.solution?.text || '-'}`);

  return {
    available: true,
    openTool,
    policyPath,
    registryEntries,
    copyText: lines.join('\n'),
  };
}

// -----------------------------------------------------------------------
// Layout  matches Home sidebar exactly
// -----------------------------------------------------------------------
function Layout({ children, navigate }) {
  const admin = useIsAdmin();

  return (
    <div className="root">
      {/*  Sidebar  */}
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
              <span className="sideLinkDot" />
              Home
            </button>
            <button className="sideLink" onClick={() => navigate('/history')}>
              <span className="sideLinkDot" />
              History
            </button>
            {admin && (
              <>
                <button className="sideLink" onClick={() => navigate('/admin/agents')}>
                  <span className="sideLinkDot" />
                  Agents
                </button>
                <button className="sideLink" onClick={() => navigate('/admin/users')}>
                  <span className="sideLinkDot" />
                  Users
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

      {/*  Main  */}
      <main className="main">{children}</main>
    </div>
  );
}

// -----------------------------------------------------------------------
// Topbar  matches Home topbar
// -----------------------------------------------------------------------
function Topbar() {
  return (
    <header className="topbar">
      <div>
        <p className="topbarDate">
          {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
        </p>
      </div>
      <div className="topbarActions">
        <ProfileMenu />
      </div>
    </header>
  );
}

// -----------------------------------------------------------------------
// ScanProgress
// -----------------------------------------------------------------------
function ScanProgress({ scanParams, onScanComplete, onError }) {
  const navigate   = useNavigate();
  const hasFetched = useRef(false);

  const [progress,  setProgress]  = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const [statusMessage, setStatusMessage] = useState(SCAN_STEPS[0]);
  const pollRef = useRef(null);

  useEffect(() => {
    if (hasFetched.current) return;
    hasFetched.current = true;
    const endpoint = scanParams._mode === 'agent'
      ? apiUrl('/api/scan/agent')
      : scanParams._mode === 'agent-subnet'
      ? apiUrl('/api/scan/agent-subnet')
      : scanParams._mode === 'subnet'
      ? apiUrl('/api/scan/subnet')
      : apiUrl('/api/scan/remote');

    fetch(endpoint, {
      method:  'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(
        scanParams._mode === 'agent'
          ? { agent_id: scanParams.agent_id, version: scanParams.version, role: scanParams.role }
          : scanParams._mode === 'agent-subnet'
          ? { subnet: scanParams.subnet, version: scanParams.version, role: scanParams.role }
          : scanParams._mode === 'subnet'
          ? {
              subnet:        scanParams.subnet,
              username:      scanParams.username,
              password:      scanParams.password,
              version:       scanParams.version,
              role:          scanParams.role,
              use_ssl:       scanParams.use_ssl,
              skip_ca_check: scanParams.skip_ca_check,
              max_parallel:  scanParams.max_parallel,
            }
          : scanParams
      ),
    })
      .then((r) => {
        if (r.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || 'Scan failed'));
        return r.json();
      })
      .then(({ job_id }) => {
        pollRef.current = setInterval(async () => {
          try {
            const res = await fetch(apiUrl(`/api/scan/status/${job_id}`), {
              headers: authHeaders(),
            });

            if (res.status === 401) {
              clearInterval(pollRef.current);
              clearAuth();
              navigate('/login');
              return;
            }

            if (res.status === 404) {
              clearInterval(pollRef.current);
              onError('Job or scan no longer exists');
              return;
            }

            if (!res.ok) throw new Error('Status check failed');
            const data = await res.json();
            const status = data.status;

            if (data.message) {
              setStatusMessage(data.message);
            }

            if (typeof data.progress === 'number') {
              const nextProgress = Math.max(0, Math.min(100, data.progress));
              setProgress(nextProgress);
              if (status === 'done') {
                setStepIndex(SCAN_STEPS.length - 1);
              } else {
                const maxIdx = SCAN_STEPS.length - 2;
                const idx = Math.min(maxIdx, Math.floor((nextProgress / 100) * (SCAN_STEPS.length - 1)));
                setStepIndex(idx);
              }
            } else if (status === 'done') {
              setStepIndex(SCAN_STEPS.length - 1);
            }

            if (status === 'done') {
              clearInterval(pollRef.current);
              setProgress(100);
              setStepIndex(SCAN_STEPS.length - 1);
              setStatusMessage(data.message || SCAN_STEPS[SCAN_STEPS.length - 1]);

              const r = data.result;

              if (scanParams._mode === 'subnet' || scanParams._mode === 'agent-subnet') {
                const subnetResult = {
                  isSubnet:    true,
                  subnet:      r.subnet,
                  total:       r.total,
                  discovered_hosts: r.discovered_hosts,
                  success_count: r.success_count,
                  failed_count:  r.failed_count,
                  results:     r.results || [],
                  version:     scanParams.version,
                  targetName:  scanParams.target_name,
                  scan_id:     r.scan_id,
                };
                sessionStorage.setItem(SESSION_KEY, JSON.stringify(subnetResult));
                onScanComplete(subnetResult);
                return;
              }

              if (!r || !r.details) { onError('Scan result is incomplete'); return; }

              const result = {
                score:      r.score,
                details:    r.details || {},
                findings:   r.findings || [],
                summary:    r.summary || null,
                score_breakdown: r.score_breakdown || r.details?._score_breakdown || null,
                targetName: r.target_name || scanParams.target_name,
                hostname:   scanParams.host,
                version:    r.version || scanParams.version,
                scan_id:    r.scan_id,
              };
              sessionStorage.setItem(SESSION_KEY, JSON.stringify(result));
              setTimeout(() => onScanComplete(result), 600);

            } else if (status === 'error') {
              clearInterval(pollRef.current);
              setStatusMessage(data.message || data.error || 'Scan failed');
              onError(data.error || 'Scan failed');
            }
          } catch (e) {
            clearInterval(pollRef.current);
            onError('Unable to connect to server');
          }
        }, 2000);
      })
      .catch((err) => {
        onError(typeof err === 'string' ? err : 'Unable to start scan');
      });

    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const circumference = 2 * Math.PI * 42; // r=42

  return (
    <div className="scanProgressWrap">
      <div className="scoreCircleWrap">
        <svg viewBox="0 0 100 100" className="scoreCircleSvg">
          <circle cx="50" cy="50" r="42" className="scoreTrack" />
          <circle
            cx="50" cy="50" r="42"
            className="scoreArc"
            strokeDasharray={`${(progress / 100) * circumference} ${circumference}`}
            transform="rotate(-90 50 50)"
            style={{ stroke: 'var(--amber)' }}
          />
        </svg>
        <div className="scoreText">{progress}%</div>
      </div>
      <div className="scanStepMsg">{statusMessage || SCAN_STEPS[stepIndex]}</div>
      <div className="scanBarWrap">
        <div className="scanBar" style={{ width: `${progress}%` }} />
      </div>
      <div className="scanDots">
        {SCAN_STEPS.slice(0, -1).map((_, i) => (
          <div
            key={i}
            className="scanDot"
            style={{ background: i <= stepIndex ? 'var(--amber)' : undefined }}
          />
        ))}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Main Result component
// -----------------------------------------------------------------------
export default function Result() {
  const navigate = useNavigate();
  const location = useLocation();
  const { id: routeScanId } = useParams();

  const scanParamsRef = useRef(null);

  const [phase, setPhase] = useState(() => {
    if (location.state?.scanParams) {
      scanParamsRef.current = location.state.scanParams;
      window.history.replaceState({}, document.title);
      return 'scanning';
    }
    if (location.state?.fromHistory) return 'done';
    
    // Always load history route from backend when opening /scan/:id/report
    if (routeScanId && location.pathname.toLowerCase().endsWith('/report')) {
      return 'loading-history';
    }
    
    if (sessionStorage.getItem(SESSION_KEY)) return 'done';
    return 'redirect';
  });

  const [scanData, setScanData] = useState(() => {
    if (location.state?.fromHistory) return location.state.fromHistory;
    // Do not use sessionStorage for direct history route
    if (routeScanId && location.pathname.toLowerCase().endsWith('/report')) return null;
    const saved = sessionStorage.getItem(SESSION_KEY);
    return saved ? JSON.parse(saved) : null;
  });

  const [errorMsg,      setErrorMsg]      = useState('');
  const [activeTab,     setActiveTab]     = useState('ALL');
  const [searchInput,   setSearchInput]   = useState('');
  const [search,        setSearch]        = useState('');
  const [expanded,      setExpanded]      = useState(null);
  const [sectionFilter, setSectionFilter] = useState('ALL');
  const [statusFilter,  setStatusFilter]  = useState('ALL');
  const [copiedLocation, setCopiedLocation] = useState('');

  useEffect(() => {
    if (phase === 'redirect') navigate('/home', { replace: true });
  }, [phase]);

  useEffect(() => {
    if (!routeScanId || !location.pathname.toLowerCase().endsWith('/report')) return;
    if (location.state?.fromHistory) return;
    setScanData(null);
    setPhase('loading-history');
  }, [routeScanId, location.pathname, location.state]);

  useEffect(() => {
    if (phase !== 'loading-history' || !routeScanId) return;

    fetch(apiUrl(`/api/scan/history/${routeScanId}`), {
      headers: authHeaders(),
    })
      .then((res) => {
        if (res.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!res.ok) return res.json().then((e) => Promise.reject(e.detail || 'Report not found'));
        return res.json();
      })
      .then((data) => {
        const details = data.details || {};
        const subnetResults = Array.isArray(details.results) ? details.results : [];
        if (data.scan_type === 'subnet') {
          setScanData({
            isSubnet: true,
            subnet: details.subnet || data.hostname || data.target_name,
            total: subnetResults.length,
            discovered_hosts: details.discovered_hosts,
            success_count: subnetResults.filter((r) => r.status === 'done').length,
            failed_count: subnetResults.filter((r) => r.status === 'error').length,
            results: subnetResults,
            targetName: data.target_name,
            hostname: data.hostname || '',
            version: data.version || '',
            scan_id: data.id,
          });
          setPhase('done');
          return;
        }

        setScanData({
          score:      data.score,
          details,
          findings:   data.findings || [],
          summary:    data.summary || null,
          score_breakdown: data.score_breakdown || details?._score_breakdown || null,
          targetName: data.target_name,
          hostname:   data.hostname || '',
          version:    data.version || '',
          scan_id:    data.id,
          parent_scan_id: data.parent_scan_id,
        });
        setPhase('done');
      })
      .catch((err) => {
        setErrorMsg(typeof err === 'string' ? err : 'Unable to load report');
        setPhase('error');
      });
  }, [phase, routeScanId, navigate]);

  const tabs = ['ALL', 'critical', 'high', 'medium', 'low'];
  const handleSearch = () => setSearch(searchInput);
  const handleClear  = () => { setSearchInput(''); setSearch(''); };
  const copyTextToClipboard = async (text) => {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  };

  const handleCopyLocation = async (key, text) => {
    try {
      await copyTextToClipboard(text);
      setCopiedLocation(key);
      setTimeout(() => setCopiedLocation(''), 1800);
    } catch (err) {
      setErrorMsg(`Unable to copy location: ${err.message}`);
    }
  };

  const {
    score      = 0,
    details    = {},
    findings   = [],
    hostname   = '',
    targetName = '',
    version    = '',
    score_breakdown: scoreBreakdown = null,
  } = scanData || {};

  const allItems = useMemo(() => parseResults(details, findings), [details, findings]);

  const sections = useMemo(() => {
    const s = new Set(allItems.map((i) => i.section));
    return ['ALL', ...Array.from(s)];
  }, [allItems]);

  const filtered = useMemo(() => allItems.filter((item) => {
    const matchTab     = activeTab === 'ALL' || item.severity === activeTab;
    const matchSection = sectionFilter === 'ALL' || item.section === sectionFilter;
    const matchStatus  = statusFilter === 'ALL' || item.status === statusFilter;
    const matchSearch  = !search
      || item.name.toLowerCase().includes(search.toLowerCase())
      || item.section.toLowerCase().includes(search.toLowerCase());
    return matchTab && matchSection && matchStatus && matchSearch;
  }), [allItems, activeTab, sectionFilter, statusFilter, search]);

  const counts = useMemo(() => {
    const c = { ALL: allItems.length, critical: 0, high: 0, medium: 0, low: 0 };
    allItems.forEach((i) => c[i.severity]++);
    return c;
  }, [allItems]);

  const passCount  = allItems.filter((v) => v.status === 'pass').length;
  const failCount  = allItems.filter((v) => v.status === 'fail').length;
  const totalCount = allItems.length || Object.values(details).length;

  // Score colour using ink/amber/green palette
  const scoreColor = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--amber)' : 'var(--red)';
  const circumference = 2 * Math.PI * 42;

  if (phase === 'redirect') return null;

  if (phase === 'loading-history') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="scanProgressWrap">
          <div className="scanStepMsg">Loading report...</div>
          <div className="scanBarWrap">
            <div className="scanBar" style={{ width: '35%' }} />
          </div>
        </div>
      </Layout>
    );
  }

  if (phase === 'scanning') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Scanning</h1>
          <p className="pageDesc">Running security assessment. Please wait.</p>
        </div>
        <ScanProgress
          scanParams={scanParamsRef.current}
          onScanComplete={(data) => {
            setScanData(data);
            setPhase('done');
            if (data.scan_id) {
              navigate(
                data.isSubnet ? `/scan/${data.scan_id}/subnet` : `/scan/${data.scan_id}/report`,
                { replace: true, state: { fromHistory: data } },
              );
            }
          }}
          onError={(msg)         => { setErrorMsg(msg);  setPhase('error'); }}
        />
      </Layout>
    );
  }

  if (phase === 'error') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Scan Failed</h1>
        </div>
        <div className="idleWrap">
          <div className="idleCard">
            <div className="idleIcon">ï¸</div>
            <h2 className="idleTitle" style={{ color: 'var(--red)' }}>Error</h2>
            <p className="idleDesc">{errorMsg}</p>
            <button className="idleScanBtn" onClick={() => navigate('/home')}>Back to Home</button>
          </div>
        </div>
      </Layout>
    );
  }
  // Subnet result block
  if (phase === 'done' && scanData?.isSubnet) {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Subnet Scan Result</h1>
          <p className="pageDesc">{scanData.subnet}  {scanData.version}</p>
        </div>

        <div className="scoreSummary" style={{ marginBottom: 24 }}>
          <div className="scoreDetail">
            <div className="scoreLabel">{scanData.subnet}</div>
            <div className="scoreVersion">{scanData.version}</div>
            <div className="scoreCounts" style={{ marginTop: 8 }}>
              <span className="countBadge pass"> {scanData.success_count} successful</span>
              <span className="countBadge fail"> {scanData.failed_count} failed</span>
            </div>
          </div>
        </div>

        <div className="resultCard">
          <div className="colHeaders" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
            <div>Host</div>
            <div>Score</div>
            <div>Status</div>
            <div>Detail</div>
          </div>
          <div className="itemList">
            {scanData.results.map((r) => (
              <div key={r.host} className="resultRow">
                <div className="rowSummary" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
                  <div>
                    <div className="itemName">{r.hostname || r.host}</div>
                    <div className="sectionTag">{r.host}</div>
                  </div>
                  <div>
                    <span style={{
                      fontFamily: 'DM Mono, monospace',
                      fontSize: 14,
                      fontWeight: 500,
                      color: r.score >= 70 ? 'var(--green)' : r.score >= 40 ? 'var(--amber)' : 'var(--red)',
                    }}>
                      {r.score}%
                    </span>
                  </div>
                  <div>
                    <span className={`badge ${r.status === 'done' ? 'on' : 'off'}`}>
                      {r.status === 'done' ? 'Done' : 'Error'}
                    </span>
                    {r.error && <div className="sectionTag" style={{ color: 'var(--red)', marginTop: 4 }}>{r.error}</div>}
                  </div>
                  <div>
                    {r.scan_id && (
                      <button
                        className="connBtn"
                        style={{ padding: '4px 12px', fontSize: 12 }}
                        onClick={() => navigate(`/scan/${r.scan_id}/report`)}
                      >
                        View 
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="resultFooter">
            <div />
            <button className="finishButton" onClick={() => navigate('/home')}>
              Finish
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <Topbar />

      <div className="pageHead">
        <h1 className="pageTitle">Scan Result</h1>
        <p className="pageDesc">Security scan result and remediation guidance</p>
      </div>

      {/* Score Summary */}
      <div className="scoreSummary">
        <div className="scoreCircleWrap">
          <svg viewBox="0 0 100 100" className="scoreCircleSvg">
            <circle cx="50" cy="50" r="42" className="scoreTrack" />
            <circle
              cx="50" cy="50" r="42"
              className="scoreArc"
              strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
              transform="rotate(-90 50 50)"
              style={{ stroke: scoreColor }}
            />
          </svg>
          <div className="scoreText" style={{ color: scoreColor }}>{score}%</div>
        </div>

        <div className="scoreDetail">
          <div className="scoreLabel">{targetName || hostname}</div>
          <div className="scoreVersion">{version}</div>
          <div className="scoreVersion">NIST/CIS-informed compliance score</div>
          {scoreBreakdown && (
            <div className="scoreVersion">
              Assessed weight {scoreBreakdown.passed_weight}/{scoreBreakdown.assessed_weight}
              {scoreBreakdown.excluded_manual_count ? ` · ${scoreBreakdown.excluded_manual_count} manual excluded` : ''}
            </div>
          )}
          <div className="scoreCounts">
            <span className="countBadge pass"> {passCount} Pass</span>
            <span className="countBadge fail"> {failCount} Fail</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: 4 }}>
            {tabs.slice(1).map((sev) => (
              <div key={sev} className="severityCount" style={{ color: SEVERITY_CONFIG[sev].color }}>
                <span className="sevDot" style={{ background: SEVERITY_CONFIG[sev].color }} />
                {SEVERITY_CONFIG[sev].label}: {counts[sev]}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Result Card */}
      <div className="resultCard">

        {/* Tab Row */}
        <div className="tabRow">
          {tabs.map((tab) => (
            <button
              key={tab}
              className={`tabBtn ${activeTab === tab ? 'active' : ''}`}
              style={
                activeTab === tab && tab !== 'ALL'
                  ? { borderBottomColor: SEVERITY_CONFIG[tab].color, color: SEVERITY_CONFIG[tab].color }
                  : {}
              }
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              <span className="tabCount">{counts[tab]}</span>
            </button>
          ))}

          <div className="tabRowRight">
            <select
              className="sectionSelect"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Status</option>
              <option value="pass">Pass</option>
              <option value="fail">Fail</option>
              <option value="na">N/A</option>
            </select>

            <select
              className="sectionSelect"
              value={sectionFilter}
              onChange={(e) => setSectionFilter(e.target.value)}
            >
              {sections.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>

            <div className="searchWrap">
              <input
                className="searchInput"
                placeholder="Search"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
              {searchInput && (
                <button className="clearBtn" onClick={handleClear}></button>
              )}
              <button className="searchBtn" onClick={handleSearch}>
                <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="5.5" cy="5.5" r="4.5" />
                  <path d="M9 9l2.5 2.5" strokeLinecap="round" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Column Headers */}
        <div className="colHeaders">
          <div>Your Config</div>
          <div>Baseline</div>
          <div>Solution</div>
        </div>

        {/* Item List */}
        <div className="itemList">
          {filtered.length === 0 && (
            <div className="emptyMsg">No matching items found</div>
          )}
          {filtered.map((item) => {
            const sev    = SEVERITY_CONFIG[item.severity];
            const isOpen = expanded === item.key;
            const locationGuide = buildSettingLocationGuide(item, { hostname, targetName });
            return (
              <div key={item.key} className={`resultRow ${isOpen ? 'open' : ''}`}>
                <div className="rowSummary" onClick={() => setExpanded(isOpen ? null : item.key)}>

                  {/* Col 1  Your Config */}
                  <div>
                    <div className="itemChip yourConf">
                      <span
                        className="sevBadge"
                        style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.bd}` }}
                      >
                        {sev.label}
                      </span>
                      <span className="itemName">{item.name}</span>
                      <span className="sectionTag">[{item.section}]</span>
                    </div>
                    {item.actual && (
                      <div className="actualChip">
                        {item.actual.length > 60 ? item.actual.slice(0, 60) + '' : item.actual}
                      </div>
                    )}
                  </div>

                  {/* Col 2  Baseline */}
                  <div>
                    <div className="itemChip baseline">{item.target || ''}</div>
                  </div>

                  {/* Col 3  Solution */}
                  <div>
                    <div className={`solutionChip ${item.status}`}>
                      {item.status === 'pass' ? 'Compliant'
                     : item.status === 'fail' ? 'Fix Available '
                     : 'N/A'}
                    </div>
                  </div>
                </div>

                {/* Expanded Detail */}
                {isOpen && (
                  <div className="rowDetail">
                    <div className="detailGrid">
                      <div className="detailBlock">
                        <div className="detailLabel">Current Value</div>
                        <div className={`detailValue ${item.status === 'pass' ? 'pass' : item.status === 'fail' ? 'fail' : ''}`}>
                          {item.actual || 'Not Configured'}
                        </div>
                      </div>
                      <div className="detailBlock">
                        <div className="detailLabel">Required Value</div>
                        <div className="detailValue pass">{item.target || ''}</div>
                      </div>
                      <div className="detailBlock full">
                        <div className="detailLabel">Solution</div>
                        <div className="detailValue">{item.solution.text}</div>
                        {item.solution.link && (
                          <a className="msLink" href={item.solution.link} target="_blank" rel="noreferrer">
                             Microsoft Documentation 
                          </a>
                        )}
                      </div>
                      {item.status === 'fail' && locationGuide.available && (
                        <div className="detailBlock full settingLocationPanel">
                          <div className="detailHeaderRow">
                            <div>
                              <div className="detailLabel">Setting Location</div>
                              <div className="settingLocationHint">
                                Windows policy tools usually cannot deep-link to an exact setting. Use this location to navigate or search for the setting.
                              </div>
                            </div>
                            <div className="locationActions">
                              {locationGuide.registryEntries.length > 0 && (
                                <button
                                  type="button"
                                  className="copyLocationBtn"
                                  onClick={() => handleCopyLocation(`${item.key}:registry`, locationGuide.registryEntries.map((entry) => (
                                    entry.valueName ? `${entry.keyPath}!${entry.valueName}` : entry.keyPath
                                  )).join('\n'))}
                                >
                                  {copiedLocation === `${item.key}:registry` ? 'Copied' : 'Copy Registry Path'}
                                </button>
                              )}
                              <button
                                type="button"
                                className="copyLocationBtn primary"
                                onClick={() => handleCopyLocation(`${item.key}:location`, locationGuide.copyText)}
                              >
                                {copiedLocation === `${item.key}:location` ? 'Copied' : 'Copy Location'}
                              </button>
                            </div>
                          </div>

                          <div className="settingLocationGrid">
                            <div className="settingLocationItem">
                              <span>Open Tool</span>
                              <strong>{locationGuide.openTool}</strong>
                            </div>
                            {locationGuide.policyPath && (
                              <div className="settingLocationItem wide">
                                <span>Security Policy Location</span>
                                <strong>{locationGuide.policyPath}</strong>
                              </div>
                            )}
                            {locationGuide.registryEntries.map((entry, index) => (
                              <React.Fragment key={`${entry.keyPath}-${entry.valueName}-${index}`}>
                                <div className="settingLocationItem wide">
                                  <span>{locationGuide.registryEntries.length > 1 ? `Registry Key ${index + 1}` : 'Registry Key'}</span>
                                  <strong>{entry.keyPath}</strong>
                                </div>
                                {entry.valueName && (
                                  <div className="settingLocationItem">
                                    <span>{locationGuide.registryEntries.length > 1 ? `Registry Value ${index + 1}` : 'Registry Value'}</span>
                                    <strong>{entry.valueName}</strong>
                                  </div>
                                )}
                              </React.Fragment>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="resultFooter">
          <button
            className="statButton"
            onClick={() => navigate('/summary', { state: { scanData: { ...scanData, scan_id: scanData?.scan_id } } })}
          >
            Summary
          </button>
          <button
            className="finishButton"
            onClick={() => {
              sessionStorage.removeItem(SESSION_KEY);
              navigate('/home');
            }}
          >
            Finish
          </button>
        </div>
      </div>
    </Layout>
  );
}


