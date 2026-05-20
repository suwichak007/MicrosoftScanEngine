import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Home.css';

const API_BASE = `http://${window.location.hostname}:8000`;
const API_SCAN = `http://${window.location.hostname}:8000`;

function Home() {
  const navigate = useNavigate();

  const [baselines, setBaselines] = useState([]);
  const [version, setVersion] = useState('');
  const [loadingBaselines, setLoadingBaselines] = useState(true);
  const [baselineError, setBaselineError] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [scanMode, setScanMode] = useState('remote');

  const [ip, setIp] = useState('192.168.2.83');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [connStatus, setConnStatus] = useState('idle');
  const [connMessage, setConnMessage] = useState('');

  const [agents, setAgents] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [agentError, setAgentError] = useState('');
  const [role, setRole] = useState('Member Server');

  useEffect(() => {
    const fetchBaselines = async () => {
      setLoadingBaselines(true);
      setBaselineError('');
      try {
        const res = await fetch(`${API_BASE}/api/scan/versions`);
        const data = await res.json();
        if (res.ok && Array.isArray(data) && data.length > 0) {
          setBaselines(data);
          setVersion(data[0].version_id); 
        } else {
          setBaselineError(data?.detail || 'ไม่พบไฟล์ baseline ในระบบ');
        }
      } catch (err) {
        setBaselineError(`โหลด baseline ไม่สำเร็จ: ${err.message}`);
      } finally {
        setLoadingBaselines(false);
      }
    };
    fetchBaselines();
  }, []);

  useEffect(() => {
    if (scanMode !== 'agent') return;
    const fetchAgents = async () => {
      setLoadingAgents(true);
      setAgentError('');
      try {
        const res = await fetch(`${API_SCAN}/agent/list`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token') || ''}` },
        });
        if (res.status === 401) { navigate('/'); return; }
        const data = await res.json();
        if (res.ok && Array.isArray(data) && data.length > 0) {
          setAgents(data);
          setSelectedAgent(data[0].agent_id);
        } else {
          setAgentError('ไม่พบ agent ที่ลงทะเบียนไว้');
        }
      } catch (err) {
        setAgentError(`โหลด agent ไม่สำเร็จ: ${err.message}`);
      } finally {
        setLoadingAgents(false);
      }
    };
    fetchAgents();
  }, [scanMode]);

  const handleConnect = async () => {
    if (!ip || !username || !password) {
      setErrorMsg('กรุณากรอก IP, Username และ Password ให้ครบ');
      return;
    }
    setErrorMsg('');
    setConnStatus('loading');
    setConnMessage('');
    try {
      const res = await fetch(`${API_BASE}/api/scan/test-connection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: ip, username, password, use_ssl: false, skip_ca_check: true }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setConnStatus('success');
        setConnMessage(`เชื่อมต่อสำเร็จ — ${data.hostname || ip}`);
      } else {
        setConnStatus('error');
        setConnMessage(data.message || 'เชื่อมต่อไม่สำเร็จ');
      }
    } catch (err) {
      setConnStatus('error');
      setConnMessage(`Connection error: ${err.message}`);
    }
  };

  const handleStartRemoteScan = () => {
    if (connStatus !== 'success') { setErrorMsg('กรุณา Connect ให้สำเร็จก่อนสแกน'); return; }
    if (!version) { setErrorMsg('กรุณาเลือก Baseline Version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: { host: ip, username, password, version, role, use_ssl: false, skip_ca_check: true, target_name: `${ip} (${version})` },
      },
    });
  };

  const handleStartAgentScan = () => {
    if (!selectedAgent) { setErrorMsg('กรุณาเลือก Agent'); return; }
    if (!version) { setErrorMsg('กรุณาเลือก Baseline Version'); return; }
    setErrorMsg('');
    const agentInfo = agents.find((a) => a.agent_id === selectedAgent);
    navigate('/result', {
      state: {
        scanParams: { host: agentInfo.hostname, version, _mode: 'agent', target_name: `${agentInfo.agent_id} (${version})` },
      },
    });
  };

  const agentOnline = (a) => {
    if (!a.last_seen) return false;
    return (Date.now() - new Date(a.last_seen).getTime()) < 5 * 60 * 1000;
  };

  const selectedAgentInfo = agents.find((a) => a.agent_id === selectedAgent);
  const canScan = scanMode === 'remote'
    ? connStatus === 'success' && !loadingBaselines && !baselineError
    : !!selectedAgent && !loadingAgents && !agentError && !loadingBaselines && !baselineError;

  return (
    <div className="root">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sideTop">
          <div className="logo">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="5" stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="1.5" fill="#c8813a" />
            </svg>
            <span className="logoText">SecureScan</span>
          </div>

          <nav className="sideNav">
            <button className="sideLink active">
              <span className="sideLinkDot" />
              Home
            </button>
            <button className="sideLink" onClick={() => navigate('/history')}>
              <span className="sideLinkDot" />
              History
            </button>
            <button className="sideLink" onClick={() => navigate('/guide')}>
              <span className="sideLinkDot" />
              Guide
            </button>
            {localStorage.getItem('role') === 'admin' && (
              <button className="sideLink" onClick={() => navigate('/admin/users')}>
                <span className="sideLinkDot" />
                Users
              </button>
            )}
          </nav>
        </div>

        <button className="logoutBtn" onClick={() => navigate('/')}>
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M5 2H2v10h3M9 10l3-3-3-3M12 7H5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Log out
        </button>
      </aside>

      {/* ── Main ── */}
      <main className="main">
        {/* Header */}
        <header className="topbar">
          <div className="topbarMeta">
            <p className="topbarDate">{new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
          </div>
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

        {/* Page title */}
        <div className="pageHead">
          <h1 className="pageTitle">Network Scanner</h1>
          <p className="pageDesc">ตั้งค่าการสแกนและเลือก baseline เพื่อตรวจสอบความปลอดภัยของระบบ</p>
        </div>

        {/* Error */}
        {errorMsg && (
          <div className="errBanner">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6" /><path d="M7 4v3M7 10h.01" strokeLinecap="round" />
            </svg>
            {errorMsg}
          </div>
        )}

        {/* ── Step 1 ── */}
        <section className="section">
          <div className="sectionHead">
            <span className="stepNum">01</span>
            <h2 className="sectionTitle">เลือก Baseline Version</h2>
          </div>
          <div className="sectionBody">
            {loadingBaselines && <div className="hint"><span className="spin" />กำลังโหลด...</div>}
            {!loadingBaselines && baselineError && <p className="errText">{baselineError}</p>}
            {!loadingBaselines && !baselineError && (
              <div className="selectWrap">
                <select
                  className="sel"
                  value={version}
                  onChange={(e) => { setVersion(e.target.value); setConnStatus('idle'); setConnMessage(''); }}
                >
                  {baselines.map((b) => (
                    <option key={b.filename} value={b.version_id}>{b.display_name}</option>
                  ))}
                </select>
                <svg className="selArrow" width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M2 4l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            )}
          </div>
        </section>

        <div className="divider" />

        {/* ── Step 2 ── */}
        <section className="section">
          <div className="sectionHead">
            <span className="stepNum">02</span>
            <h2 className="sectionTitle">เลือก Target</h2>
          </div>

          {/* Mode tabs */}
          <div className="tabs">
            <button
              className={`tab ${scanMode === 'remote' ? 'active' : ''}`}
              onClick={() => { setScanMode('remote'); setErrorMsg(''); }}
            >
              Remote Scan
            </button>
            <button
              className={`tab ${scanMode === 'agent' ? 'active' : ''}`}
              onClick={() => { setScanMode('agent'); setErrorMsg(''); }}
            >
              Agent Scan
            </button>
          </div>

          {/* Remote */}
          {scanMode === 'remote' && (
            <div className="sectionBody animIn">
              <div className="fieldRow">
                <div className="field">
                  <label className="fieldLabel">IP Address</label>
                  <input className="inp" type="text" placeholder="192.168.1.50" value={ip} onChange={(e) => setIp(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Username</label>
                  <input className="inp" type="text" placeholder=".\Administrator" value={username} onChange={(e) => setUsername(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Password</label>
                  <input className="inp" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                {/* แสดง Role เฉพาะ version ที่เป็น Server */}
                {baselines.find(b => b.version_id === version)?.os_family === 'windows_server' && (
                  <div className="field">
                    <label className="fieldLabel">Target Role</label>
                    <div className="selectWrap">
                      <select className="sel" value={role} onChange={(e) => setRole(e.target.value)}>
                        <option value="Member Server">Member Server</option>
                        <option value="Domain Controller">Domain Controller</option>
                      </select>
                      <svg className="selArrow" width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M2 4l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </div>
                  </div>
                )}
              </div>

              <div className="connRow">
                <button className={`connBtn ${connStatus}`} onClick={handleConnect} disabled={connStatus === 'loading' || loadingBaselines}>
                  {connStatus === 'loading' ? <><span className="spin" />กำลังเชื่อมต่อ</> : 'ทดสอบการเชื่อมต่อ'}
                </button>
                {connMessage && (
                  <span className={`connMsg ${connStatus}`}>
                    {connStatus === 'success' ? '✓' : '✕'} {connMessage}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Agent */}
          {scanMode === 'agent' && (
            <div className="sectionBody animIn">
              {loadingAgents && <div className="hint"><span className="spin" />กำลังโหลด agents...</div>}
              {!loadingAgents && agentError && <p className="errText">{agentError}</p>}
              {!loadingAgents && !agentError && (
                <div className="agentGrid">
                  {agents.map((a) => {
                    const online = agentOnline(a);
                    return (
                      <button
                        key={a.agent_id}
                        className={`agentTile ${selectedAgent === a.agent_id ? 'active' : ''}`}
                        onClick={() => setSelectedAgent(a.agent_id)}
                      >
                        <div className="agentTileTop">
                          <span className="agentId">{a.agent_id}</span>
                          <span className={`badge ${online ? 'on' : 'off'}`}>{online ? 'Online' : 'Offline'}</span>
                        </div>
                        {a.hostname && <span className="agentHostname">{a.hostname}</span>}
                        {a.last_seen && (
                          <span className="agentSeen">Last seen {new Date(a.last_seen).toLocaleString('th-TH')}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </section>

        {/* ── Launch ── */}
        <div className="launchRow">
          {version && (
            <div className="scanSummary">
              <span className="summaryItem">{version}</span>
              {scanMode === 'remote' && ip && <><span className="summaryDivider">·</span><span className="summaryItem">{ip}</span></>}
              {scanMode === 'agent' && selectedAgentInfo && <><span className="summaryDivider">·</span><span className="summaryItem">{selectedAgentInfo.agent_id}</span></>}
            </div>
          )}
          <button
            className="scanBtn"
            onClick={scanMode === 'remote' ? handleStartRemoteScan : handleStartAgentScan}
            disabled={!canScan}
          >
            เริ่มสแกน
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M2 7h10M8 3l4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
        </div>
      </main>
    </div>
  );
}

export default Home;