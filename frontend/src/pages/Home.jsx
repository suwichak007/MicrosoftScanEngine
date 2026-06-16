import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Home.css';
import { authHeaders, clearAuth, useIsAdmin } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

function Home() {
  const navigate = useNavigate();
  const admin = useIsAdmin();

  const [baselines, setBaselines] = useState([]);
  const [version, setVersion] = useState('');
  const [loadingBaselines, setLoadingBaselines] = useState(true);
  const [baselineError, setBaselineError] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [scanMode, setScanMode] = useState('remote');

  const [ip, setIp] = useState('192.168.2.83');
  const [scanUsername, setScanUsername] = useState('');   // renamed from username
  const [password, setPassword] = useState('');
  const [connStatus, setConnStatus] = useState('idle');
  const [connMessage, setConnMessage] = useState('');

  const [agents, setAgents] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [agentError, setAgentError] = useState('');
  const [role, setRole] = useState('Member Server');
  const [subnet, setSubnet] = useState('192.168.1.0/24');      // added here
  const [maxParallel, setMaxParallel] = useState(5);            // added here
  
  useEffect(() => {
    const fetchBaselines = async () => {
      setLoadingBaselines(true);
      setBaselineError('');
      try {
        const res = await fetch(apiUrl('/api/scan/versions'), {
          headers: authHeaders(),
        });
        if (res.status === 401) { clearAuth(); navigate('/login'); return; }
        const data = await res.json();
        if (res.ok && Array.isArray(data) && data.length > 0) {
          setBaselines(data);
          setVersion(data[0].version_id);
        } else {
          setBaselineError(data?.detail || 'No baseline files found');
        }
      } catch (err) {
        setBaselineError(`Failed to load baselines: ${err.message}`);
      } finally {
        setLoadingBaselines(false);
      }
    };
    fetchBaselines();
  }, []);

  useEffect(() => {
    if (scanMode !== 'agent' && scanMode !== 'agent-subnet') return;
    const fetchAgents = async () => {
      setLoadingAgents(true);
      setAgentError('');
      try {
        const res = await fetch(apiUrl('/api/agents'), {
          headers: authHeaders(),
        });
        if (res.status === 401) { clearAuth(); navigate('/login'); return; }
        const data = await res.json();
        if (res.ok && Array.isArray(data) && data.length > 0) {
          setAgents(data);
          setSelectedAgent(data[0].agent_id);
        } else {
          setAgentError('No registered agents found');
        }
      } catch (err) {
        setAgentError(`Failed to load agents: ${err.message}`);
      } finally {
        setLoadingAgents(false);
      }
    };
    fetchAgents();
  }, [scanMode]);

  useEffect(() => {
    setVersion((prev) => {
      if (scanMode === 'agent' || scanMode === 'agent-subnet') return 'auto';
      if (prev === 'auto' && baselines.length > 0) return baselines[0].version_id;
      return prev;
    });
  }, [scanMode, baselines]);

  const handleConnect = async () => {
    if (!ip || !scanUsername || !password) {
      setErrorMsg('Please enter IP, username, and password');
      return;
    }
    setErrorMsg('');
    setConnStatus('loading');
    setConnMessage('');
    try {
      const res = await fetch(apiUrl('/api/scan/test-connection'), {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ host: ip, username: scanUsername, password, use_ssl: false, skip_ca_check: true }),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (res.ok && data.success) {
        setConnStatus('success');
        setConnMessage(`Connected successfully - ${data.hostname || ip}`);
      } else {
        setConnStatus('error');
        setConnMessage(data.message || 'Connection failed');
      }
    } catch (err) {
      setConnStatus('error');
      setConnMessage(`Connection error: ${err.message}`);
    }
  };

  const handleStartRemoteScan = () => {
    if (connStatus !== 'success') { setErrorMsg('Please connect successfully before scanning'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          host: ip, username: scanUsername, password, version, role,
          use_ssl: false, skip_ca_check: true,
          target_name: `${ip} (${version})`,
        },
      },
    });
  };

  const handleStartAgentScan = () => {
    if (!selectedAgent) { setErrorMsg('Please select an agent'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    const agentInfo = agents.find((a) => a.agent_id === selectedAgent);
    navigate('/result', {
      state: {
        scanParams: {
          agent_id: agentInfo.agent_id,
          host: agentInfo.hostname,
          version,
          role,
          _mode: 'agent',
          target_name: `${agentInfo.agent_id} (${version === 'auto' ? 'Auto detect baseline' : version})`,
        },
      },
    });
  };

  const handleStartSubnetScan = () => {
    if (!subnet)       { setErrorMsg('Please enter a subnet'); return; }
    if (!scanUsername) { setErrorMsg('Please enter a username'); return; }
    if (!password)     { setErrorMsg('Please enter a password'); return; }
    if (!version)      { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          subnet, username: scanUsername, password, version, role,
          use_ssl: false, skip_ca_check: true, max_parallel: maxParallel,
          _mode: 'subnet',
          target_name: `${subnet} (${version === 'auto' ? 'Auto detect baseline' : version})`,
        },
      },
    });
  };

  const handleStartAgentSubnetScan = () => {
    if (!subnet)  { setErrorMsg('Please enter a subnet'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          subnet,
          version,
          role,
          _mode: 'agent-subnet',
          target_name: `${subnet} (${version})`,
        },
      },
    });
  };

  const agentOnline = (a) => {
    if (!a.last_seen) return false;
    return (Date.now() - new Date(a.last_seen).getTime()) < 5 * 60 * 1000;
  };

  const selectedAgentInfo = agents.find((a) => a.agent_id === selectedAgent);
  const baselineOptions = (scanMode === 'agent' || scanMode === 'agent-subnet')
    ? [{ version_id: 'auto', display_name: 'Auto detect baseline', filename: 'auto' }, ...baselines]
    : baselines;
  const versionLabel = version === 'auto' ? 'Auto detect baseline' : version;
  const canScan = scanMode === 'remote'
    ? connStatus === 'success' && !loadingBaselines && !baselineError
    : scanMode === 'subnet'
    ? !!subnet && !!scanUsername && !!password && !loadingBaselines && !baselineError
    : scanMode === 'agent-subnet'
    ? !!subnet && !loadingBaselines && !baselineError
    : !!selectedAgent && !loadingAgents && !agentError && !loadingBaselines && !baselineError;

  return (
    <div className="root">
      {/* ── Sidebar ── */}
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
            <button className="sideLink active">
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

      {/* ── Main ── */}
      <main className="main">
        {/* Header */}
        <header className="topbar">
          <div className="topbarMeta">
            <p className="topbarDate">
              {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            </p>
          </div>
          <div className="topbarActions">
            <ProfileMenu />
          </div>
        </header>

        {/* Page title */}
        <div className="pageHead">
          <h1 className="pageTitle">Network Scanner</h1>
          <p className="pageDesc">Configure scan target and baseline for security assessment</p>
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
            <h2 className="sectionTitle">Select Baseline Version</h2>
          </div>
          <div className="sectionBody">
            {loadingBaselines && <div className="hint"><span className="spin" />Loading...</div>}
            {!loadingBaselines && baselineError && <p className="errText">{baselineError}</p>}
            {!loadingBaselines && !baselineError && (
              <div className="selectWrap">
                <select
                  className="sel"
                  value={version}
                  onChange={(e) => { setVersion(e.target.value); setConnStatus('idle'); setConnMessage(''); }}
                >
                  {baselineOptions.map((b) => (
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
            <h2 className="sectionTitle">Select Target</h2>
          </div>

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
            <button
              className={`tab ${scanMode === 'subnet' ? 'active' : ''}`}
              onClick={() => { setScanMode('subnet'); setErrorMsg(''); }}
            >
              Subnet Scan
            </button>
            <button
              className={`tab ${scanMode === 'agent-subnet' ? 'active' : ''}`}
              onClick={() => { setScanMode('agent-subnet'); setErrorMsg(''); }}
            >
              Agent Subnet
            </button>
          </div>

          {/* Remote */}
          {scanMode === 'remote' && (
            <div className="sectionBody animIn">
              <div className="fieldRow">
                <div className="field">
                  <label className="fieldLabel">IP Address</label>
                  <input className="inp" type="text" placeholder="192.168.1.50"
                    value={ip} onChange={(e) => setIp(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Username</label>
                  <input className="inp" type="text" placeholder=".\Administrator"
                    value={scanUsername} onChange={(e) => setScanUsername(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Password</label>
                  <input className="inp" type="password" placeholder="••••••••"
                    value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
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
                <button className={`connBtn ${connStatus}`} onClick={handleConnect}
                  disabled={connStatus === 'loading' || loadingBaselines}>
                  {connStatus === 'loading' ? <><span className="spin" />Connecting</> : 'Test Connection'}
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
              {loadingAgents && <div className="hint"><span className="spin" />Loading agents...</div>}
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
                        {(a.os_name || a.os_release || a.os_build) && (
                          <span className="agentSeen">
                            {[a.os_name, a.os_release, a.os_build && `build ${a.os_build}`].filter(Boolean).join(' · ')}
                          </span>
                        )}
                        {a.detected_baseline && (
                          <span className="agentSeen">Auto baseline {a.detected_baseline}</span>
                        )}
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

          {scanMode === 'agent-subnet' && (
            <div className="sectionBody animIn">
              <div className="fieldRow">
                <div className="field">
                  <label className="fieldLabel">Subnet (CIDR)</label>
                  <input className="inp" type="text" placeholder="192.168.1.0/24"
                    value={subnet} onChange={(e) => setSubnet(e.target.value)} />
                </div>
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
              {!loadingAgents && !agentError && (
                <div className="hint">
                  Only agents with a recent heartbeat and an IP address in this subnet will be scanned.
                </div>
              )}
            </div>
          )}
        </section>

          {/* Subnet */}
          {scanMode === 'subnet' && (
            <div className="sectionBody animIn">
              <div className="fieldRow">
                <div className="field">
                  <label className="fieldLabel">Subnet (CIDR)</label>
                  <input className="inp" type="text" placeholder="192.168.1.0/24"
                    value={subnet} onChange={(e) => setSubnet(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Username</label>
                  <input className="inp" type="text" placeholder=".\Administrator"
                    value={scanUsername} onChange={(e) => setScanUsername(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Password</label>
                  <input className="inp" type="password" placeholder="••••••••"
                    value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <div className="field">
                  <label className="fieldLabel">Parallel (max)</label>
                  <input className="inp" type="number" min="1" max="20"
                    value={maxParallel} onChange={(e) => setMaxParallel(Number(e.target.value))} />
                </div>
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
            </div>
          )}

        {/* ── Launch ── */}
        <div className="launchRow">
          {version && (
            <div className="scanSummary">
              <span className="summaryItem">{versionLabel}</span>
              {scanMode === 'remote' && ip && <><span className="summaryDivider">·</span><span className="summaryItem">{ip}</span></>}
              {scanMode === 'agent' && selectedAgentInfo && <><span className="summaryDivider">·</span><span className="summaryItem">{selectedAgentInfo.agent_id}</span></>}
              {scanMode === 'agent-subnet' && subnet && <><span className="summaryDivider">·</span><span className="summaryItem">{subnet}</span></>}
            </div>
          )}
          <button
            className="scanBtn"
            onClick={
              scanMode === 'remote' ? handleStartRemoteScan
              : scanMode === 'subnet' ? handleStartSubnetScan
              : scanMode === 'agent-subnet' ? handleStartAgentSubnetScan
              : handleStartAgentScan
            }
            disabled={!canScan}
          >
            Start Scan
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
