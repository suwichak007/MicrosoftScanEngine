import React, { useState, useMemo, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import './Result.css';

// -----------------------------------------------------------------------
// Severity classification
// -----------------------------------------------------------------------
const CRITICAL_KEYWORDS = [
  'remote desktop',
  'lsa protection',
  'credential',
  'ntlm',
  'kerberos',
  'bitlocker' 
];
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

  // 🎯 Rule-based (แม่นสุด)
  if (lower.includes('remote desktop')) return 'critical';
  if (lower.includes('bitlocker')) return 'critical';
  if (lower.includes('lsa protection')) return 'critical';
  if (lower.includes('credential')) return 'critical';

  if (lower.includes('account lockout')) return 'high';
  if (lower.includes('logon')) return 'high';

  // 🎯 Section-based (ช่วยเสริม)
  if (lower.startsWith('[advanced audit]')) return 'medium';
  if (lower.startsWith('[services]')) return 'low';

  // 🎯 fallback keyword
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k))) return 'high';
  if (MEDIUM_KEYWORDS.some(k => lower.includes(k))) return 'medium';

  return 'low';
}

const SOLUTION_MAP = {
  'account lockout': {
    text: 'ตั้งค่า Account Lockout Policy ผ่าน secpol.msc → Account Policies → Account Lockout Policy',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy',
  },
  'password': {
    text: 'ตั้งค่า Password Policy ผ่าน secpol.msc → Account Policies → Password Policy',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy',
  },
  'uac': {
    text: 'เปิดใช้งาน User Account Control ผ่าน secpol.msc → Local Policies → Security Options',
    link: 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/',
  },
  'firewall': {
    text: 'ตั้งค่า Windows Defender Firewall ผ่าน wf.msc หรือ Group Policy',
    link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/',
  },
  'audit': {
    text: 'ตั้งค่า Advanced Audit Policy ผ่าน secpol.msc → Advanced Audit Policy Configuration',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings',
  },
  'defender': {
    text: 'ตั้งค่า Microsoft Defender ผ่าน Group Policy หรือ Windows Security Settings',
    link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows',
  },
  'ntlm': {
    text: 'กำหนด LAN Manager authentication level ผ่าน secpol.msc → Local Policies → Security Options',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level',
  },
  'smb': {
    text: 'ปิดการใช้งาน SMBv1 และกำหนดค่า SMB Signing ผ่าน Registry หรือ Group Policy',
    link: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3',
  },
  'lsa': {
    text: 'เปิดใช้งาน LSA Protection ผ่าน Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL = 1',
    link: 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection',
  },
  'remote desktop': {
    text: 'กำหนดค่า RDP Security ผ่าน Group Policy → Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services',
    link: 'https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-desktop-services',
  },
  'bitlocker': {
    text: 'เปิดใช้งาน BitLocker ผ่าน Control Panel → System and Security → BitLocker Drive Encryption',
    link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/',
  },
  'attack surface': {
    text: 'กำหนดค่า Attack Surface Reduction Rules ผ่าน Microsoft Defender หรือ Group Policy',
    link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference',
  },
  'smartscreen': {
    text: 'เปิดใช้งาน SmartScreen ผ่าน Group Policy → Windows Defender SmartScreen',
    link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/',
  },
  'autoplay': {
    text: 'ปิด AutoPlay ผ่าน Group Policy → Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/turn-off-autoplay',
  },
  'user rights': {
    text: 'กำหนด User Rights Assignment ผ่าน secpol.msc → Local Policies → User Rights Assignment',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment',
  },
};

function getSolution(key) {
  const lower = key.toLowerCase();
  for (const [keyword, sol] of Object.entries(SOLUTION_MAP)) {
    if (lower.includes(keyword)) return sol;
  }
  return {
    text: 'ตรวจสอบและแก้ไขผ่าน Group Policy Editor (gpedit.msc) หรือ Local Security Policy (secpol.msc)',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings',
  };
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ff4d4d', bg: 'rgba(255,77,77,0.15)' },
  high:     { label: 'High',     color: '#ff9900', bg: 'rgba(255,153,0,0.15)' },
  medium:   { label: 'Medium',   color: '#f5d000', bg: 'rgba(245,208,0,0.15)' },
  low:      { label: 'Low',      color: '#2ea3ff', bg: 'rgba(46,163,255,0.15)' },
};

const SCAN_STEPS = [
  'กำลังเชื่อมต่อกับเครื่องเป้าหมาย...',
  'กำลังโหลด Security Baseline...',
  'กำลังตรวจสอบ Security Policy...',
  'กำลังตรวจสอบ Audit Policy...',
  'กำลังตรวจสอบ Registry Settings...',
  'กำลังตรวจสอบ Firewall Rules...',
  'กำลังตรวจสอบ Windows Defender...',
  'กำลังตรวจสอบ Services...',
  'กำลังคำนวณ Security Score...',
  'เสร็จสิ้น',
];

function parseResults(details) {
  if (!details) return [];
  return Object.entries(details)
    .filter(([, v]) => !String(v).startsWith('Pass'))
    .map(([key, value]) => {
      const sectionMatch = key.match(/^\[([^\]]+)\]/);
      const section  = sectionMatch ? sectionMatch[1] : 'General';
      const name     = key.replace(/^\[[^\]]+\]\s*/, '');
      const severity = getSeverity(key);
      const solution = getSolution(key);

      let target = '', actual = '';
      const targetMatch = String(value).match(/Target:\s*([^,)]+)/);
      const actualMatch = String(value).match(/Actual:\s*(.+)/);
      if (targetMatch) target = targetMatch[1].trim();
      if (actualMatch) actual = actualMatch[1].trim().replace(/\)\s*$/, '');

      const status = String(value).startsWith('Fail')    ? 'fail'
                   : String(value).includes('Manual')    ? 'manual'
                   : String(value).includes('Not Found') ? 'notfound'
                   : 'other';

      return { key, name, section, severity, solution, target, actual, status, raw: value };
    });
}

// -----------------------------------------------------------------------
// Layout — อยู่นอก Result เพื่อป้องกัน re-mount ทุกครั้งที่ state เปลี่ยน
// -----------------------------------------------------------------------
function Layout({ children, navigate }) {
  return (
    <div className="resultPage">
      <header className="topBar">
        <div className="brand">Scanner</div>
        <div className="topBarRight">
          <div className="bellWrapper">
            <span className="bellIcon">🔔</span>
            <span className="notificationDot"></span>
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
            <span className="logoutIcon">↪</span>
            <span>Log Out</span>
          </button>
        </aside>
        <main className="resultMain">{children}</main>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// ScanProgress component
// -----------------------------------------------------------------------
function ScanProgress({ scanParams, onScanComplete, onError }) {
  const apiHost = window.location.hostname;
  const [progress,  setProgress]  = useState(0);
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    let step = 0;
    const interval = setInterval(() => {
      step += 1;
      if (step < SCAN_STEPS.length - 1) {
        setStepIndex(step);
        setProgress(Math.round((step / (SCAN_STEPS.length - 1)) * 85));
      } else {
        clearInterval(interval);
      }
    }, 900);

    fetch(`http://${apiHost}:8000/api/scan/remote`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(scanParams),
    })
      .then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || 'Scan failed'));
        return r.json();
      })
      .then((data) => {
        clearInterval(interval);
        setStepIndex(SCAN_STEPS.length - 1);
        setProgress(100);
        setTimeout(() => {
          onScanComplete({
            score:      data.score,
            details:    data.details || {},
            targetName: data.target_name || scanParams.target_name,
            hostname:   data.hostname   || scanParams.host,
            version:    data.version    || scanParams.version,
          });
        }, 600);
      })
      .catch((err) => {
        clearInterval(interval);
        onError(typeof err === 'string' ? err : 'ไม่สามารถเชื่อมต่อกับ server ได้');
      });

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="scanProgressWrap">
      <div className="scoreCircleWrap">
        <svg viewBox="0 0 100 100" className="scoreCircleSvg">
          <circle cx="50" cy="50" r="42" className="scoreTrack" />
          <circle
            cx="50" cy="50" r="42"
            className="scoreArc"
            strokeDasharray={`${progress * 2.638} 263.8`}
            transform="rotate(-90 50 50)"
            style={{ stroke: '#2ea3ff', transition: 'stroke-dasharray 0.5s ease' }}
          />
        </svg>
        <div className="scoreText">
          <div>{progress}%</div>
          <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>Scanning</div>
        </div>
      </div>
      <div className="scanStepMsg">{SCAN_STEPS[stepIndex]}</div>
      <div className="scanBarWrap">
        <div className="scanBar" style={{ width: `${progress}%` }} />
      </div>
      <div className="scanDots">
        {SCAN_STEPS.slice(0, -1).map((_, i) => (
          <div key={i} className="scanDot"
            style={{ background: i <= stepIndex ? '#2ea3ff' : undefined }} />
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

  const { scanParams } = location.state || {};

  useEffect(() => {
    if (!scanParams) navigate('/home', { replace: true });
  }, []);

  const [phase,         setPhase]         = useState('scanning');
  const [scanData,      setScanData]      = useState(null);
  const [errorMsg,      setErrorMsg]      = useState('');
  const [activeTab,     setActiveTab]     = useState('ALL');
  const [searchInput,   setSearchInput]   = useState('');
  const [search,        setSearch]        = useState('');
  const [expanded,      setExpanded]      = useState(null);
  const [sectionFilter, setSectionFilter] = useState('ALL');

  const tabs = ['ALL', 'critical', 'high', 'medium', 'low'];

  const handleSearch = () => setSearch(searchInput);
  const handleClear  = () => { setSearchInput(''); setSearch(''); };

  const {
    score      = 0,
    details    = {},
    hostname   = '',
    targetName = '',
    version    = '',
  } = scanData || {};

  const allItems = useMemo(() => parseResults(details), [details]);

  const sections = useMemo(() => {
    const s = new Set(allItems.map((i) => i.section));
    return ['ALL', ...Array.from(s)];
  }, [allItems]);

  const filtered = useMemo(() => {
    return allItems.filter((item) => {
      const matchTab     = activeTab === 'ALL' || item.severity === activeTab;
      const matchSection = sectionFilter === 'ALL' || item.section === sectionFilter;
      const matchSearch  = !search
        || item.name.toLowerCase().includes(search.toLowerCase())
        || item.section.toLowerCase().includes(search.toLowerCase());
      return matchTab && matchSection && matchSearch;
    });
  }, [allItems, activeTab, sectionFilter, search]);

  const counts = useMemo(() => {
    const c = { ALL: allItems.length, critical: 0, high: 0, medium: 0, low: 0 };
    allItems.forEach((i) => c[i.severity]++);
    return c;
  }, [allItems]);

  const passCount  = Object.values(details).filter((v) => String(v) === 'Pass').length;
  const totalCount = Object.values(details).length;

  if (!scanParams) return null;

  if (phase === 'scanning') {
    return (
      <Layout navigate={navigate}>
        <ScanProgress
          scanParams={scanParams}
          onScanComplete={(data) => { setScanData(data); setPhase('done'); }}
          onError={(msg)         => { setErrorMsg(msg);  setPhase('error'); }}
        />
      </Layout>
    );
  }

  if (phase === 'error') {
    return (
      <Layout navigate={navigate}>
        <div className="idleWrap">
          <div className="idleCard">
            <div className="idleIcon">⚠️</div>
            <h2 className="idleTitle" style={{ color: '#ff4d4d' }}>Scan Failed</h2>
            <p className="idleDesc"  style={{ color: '#ff4d4d' }}>{errorMsg}</p>
            <button className="idleScanBtn" onClick={() => navigate('/home')}>
              กลับหน้าหลัก
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <h1 className="pageTitle">Result</h1>

      {/* Score Summary */}
      <div className="scoreSummary">
        <div className="scoreCircleWrap">
          <svg viewBox="0 0 100 100" className="scoreCircleSvg">
            <circle cx="50" cy="50" r="42" className="scoreTrack" />
            <circle
              cx="50" cy="50" r="42"
              className="scoreArc"
              strokeDasharray={`${score * 2.638} 263.8`}
              transform="rotate(-90 50 50)"
              style={{ stroke: score >= 70 ? '#20d320' : score >= 40 ? '#f5d000' : '#ff4d4d' }}
            />
          </svg>
          <div className="scoreText">{score}%</div>
        </div>
        <div className="scoreDetail">
          <div className="scoreLabel">{targetName || hostname}</div>
          <div className="scoreVersion">{version}</div>
          <div className="scoreCounts">
            <span className="countBadge pass">✔ {passCount} Pass</span>
            <span className="countBadge fail">✖ {totalCount - passCount} Fail</span>
          </div>
          {tabs.slice(1).map((sev) => (
            <div key={sev} className="severityCount" style={{ color: SEVERITY_CONFIG[sev].color }}>
              <span className="sevDot" style={{ background: SEVERITY_CONFIG[sev].color }} />
              {SEVERITY_CONFIG[sev].label}: {counts[sev]}
            </div>
          ))}
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
              style={activeTab === tab && tab !== 'ALL'
                ? { borderBottomColor: SEVERITY_CONFIG[tab].color, color: SEVERITY_CONFIG[tab].color }
                : {}}
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              <span className="tabCount">{counts[tab]}</span>
            </button>
          ))}

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
              placeholder="Search..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
            {searchInput && (
              <button className="clearBtn" onClick={handleClear}>✕</button>
            )}
            <button className="searchBtn" onClick={handleSearch}>🔍</button>
          </div>
        </div>

        {/* Column Headers */}
        <div className="colHeaders">
          <div className="colYourConf">Your Config</div>
          <div className="colBaseline">BaseLine</div>
          <div className="colSolution">Solution</div>
        </div>

        {/* Item List */}
        <div className="itemList">
          {filtered.length === 0 && (
            <div className="emptyMsg">ไม่พบรายการที่ตรงกับเงื่อนไข</div>
          )}
          {filtered.map((item) => {
            const sev    = SEVERITY_CONFIG[item.severity];
            const isOpen = expanded === item.key;
            return (
              <div key={item.key} className={`resultRow ${isOpen ? 'open' : ''}`}>
                <div className="rowSummary" onClick={() => setExpanded(isOpen ? null : item.key)}>
                  <div className="colYourConf">
                    <div className="itemChip yourConf">
                      <span
                        className="sevBadge"
                        style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.color}` }}
                      >
                        {sev.label}
                      </span>
                      <span className="itemName">{item.name}</span>
                      <span className="sectionTag">[{item.section}]</span>
                    </div>
                    {item.actual && (
                      <div className="actualChip">
                        {item.actual.length > 60 ? item.actual.slice(0, 60) + '…' : item.actual}
                      </div>
                    )}
                  </div>
                  <div className="colBaseline">
                    <div className="itemChip baseline">{item.target || '—'}</div>
                  </div>
                  <div className="colSolution">
                    <div className={`solutionChip ${item.status}`}>
                      {item.status === 'fail'     ? 'Fix Available ▾'
                       : item.status === 'manual' ? 'Manual Check'
                       : 'Not Found'}
                    </div>
                  </div>
                </div>

                {isOpen && (
                  <div className="rowDetail">
                    <div className="detailGrid">
                      <div className="detailBlock">
                        <div className="detailLabel">Current Value</div>
                        <div className="detailValue fail">{item.actual || 'Not Configured'}</div>
                      </div>
                      <div className="detailBlock">
                        <div className="detailLabel">Required Value</div>
                        <div className="detailValue pass">{item.target || '—'}</div>
                      </div>
                      <div className="detailBlock full">
                        <div className="detailLabel">Solution</div>
                        <div className="detailValue">{item.solution.text}</div>
                        <a
                          className="msLink"
                          href={item.solution.link}
                          target="_blank"
                          rel="noreferrer"
                        >
                          📖 Microsoft Documentation ↗
                        </a>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="resultFooter">
          <button className="statButton" onClick={() => navigate('/Dashboard', { state: scanData })}>
            Stat
          </button>
          <button className="finishButton" onClick={() => navigate('/home')}>
            Finish
          </button>
        </div>

      </div>
    </Layout>
  );
}