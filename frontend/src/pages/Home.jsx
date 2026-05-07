import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Home.css';

const API_BASE = `http://${window.location.hostname}:8000`;
const API_SCAN = `http://${window.location.hostname}:8000`;

function Home() {
  const navigate = useNavigate();

  // ── Shared ──────────────────────────────────────────────────────────
  const [baselines,       setBaselines]       = useState([]);
  const [version,         setVersion]         = useState('');
  const [loadingBaselines,setLoadingBaselines] = useState(true);
  const [baselineError,   setBaselineError]   = useState('');
  const [errorMsg,        setErrorMsg]        = useState('');
  const [scanMode,        setScanMode]        = useState('remote'); // 'remote' | 'agent'

  // ── Remote Scan ──────────────────────────────────────────────────────
  const [ip,         setIp]         = useState('192.168.2.83');
  const [username,   setUsername]   = useState('');
  const [password,   setPassword]   = useState('');
  const [connStatus, setConnStatus] = useState('idle');
  const [connMessage,setConnMessage]= useState('');

  // ── Agent Scan ───────────────────────────────────────────────────────
  const [agents,          setAgents]          = useState([]);
  const [selectedAgent,   setSelectedAgent]   = useState('');
  const [loadingAgents,   setLoadingAgents]   = useState(false);
  const [agentError,      setAgentError]      = useState('');

  // ── Load baselines ───────────────────────────────────────────────────
  useEffect(() => {
    const fetchBaselines = async () => {
      setLoadingBaselines(true);
      setBaselineError('');
      try {
        const res  = await fetch(`${API_BASE}/api/scan/versions`);
        const data = await res.json();
        if (res.ok && Array.isArray(data) && data.length > 0) {
          setBaselines(data);
          setVersion(data[0].version);
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

  // ── Load agents when switching to agent mode ─────────────────────────
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

  // ── Remote: test connection ──────────────────────────────────────────
  const handleConnect = async () => {
    if (!ip || !username || !password) {
      setErrorMsg('กรุณากรอก IP, Username และ Password ให้ครบ');
      return;
    }
    setErrorMsg('');
    setConnStatus('loading');
    setConnMessage('');
    try {
      const res  = await fetch(`${API_BASE}/api/scan/test-connection`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ host: ip, username, password, use_ssl: false, skip_ca_check: true }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setConnStatus('success');
        setConnMessage(`เชื่อมต่อสำเร็จ: ${data.hostname || ip}`);
      } else {
        setConnStatus('error');
        setConnMessage(data.message || 'เชื่อมต่อไม่สำเร็จ');
      }
    } catch (err) {
      setConnStatus('error');
      setConnMessage(`Connection error: ${err.message}`);
    }
  };

  // ── Remote: start scan ───────────────────────────────────────────────
  const handleStartRemoteScan = () => {
    if (connStatus !== 'success') { setErrorMsg('กรุณา Connect ให้สำเร็จก่อนสแกน'); return; }
    if (!version)                 { setErrorMsg('กรุณาเลือก Baseline Version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          host: ip, username, password, version,
          use_ssl: false, skip_ca_check: true,
          target_name: `${ip} (${version})`,
        },
      },
    });
  };

  // ── Agent: start scan ────────────────────────────────────────────────
  const handleStartAgentScan = async () => {
    if (!selectedAgent) { setErrorMsg('กรุณาเลือก Agent'); return; }
    if (!version)       { setErrorMsg('กรุณาเลือก Baseline Version'); return; }
    setErrorMsg('');

    const agentInfo = agents.find((a) => a.agent_id === selectedAgent);

    navigate('/result', {
      state: {
        scanParams: {
          host:        agentInfo.hostname,   // ← ใช้ hostname
          version,
          _mode:       'agent',
          target_name: `${agentInfo.agent_id} (${version})`,
        },
      },
    });
  };

  const agentOnline = (a) => {
    if (!a.last_seen) return false;
    return (Date.now() - new Date(a.last_seen).getTime()) < 5 * 60 * 1000; // 5 นาที
  };

  const selectedAgentInfo = agents.find((a) => a.agent_id === selectedAgent);

  // ── Render ───────────────────────────────────────────────────────────
  return (
    <div className="homePage">
      <header className="topBar">
        <div className="brand">Scanner</div>
        <div className="topBarRight">
          <div className="bellWrapper"><span className="bellIcon">🔔</span><span className="notificationDot"></span></div>
          <div className="profileCircle">👤</div>
        </div>
      </header>

      <div className="homeLayout">
        <aside className="sideBar">
          <div className="menuGroup">
            <button className="menuItem active">Home</button>
            <button className="menuItem" onClick={() => navigate('/history')}>History</button>
            <button className="menuItem" onClick={() => navigate('/guide')}>Guide</button>
          </div>
          <button className="logoutButton" onClick={() => navigate('/')}>
            <span className="logoutIcon">↪</span><span>Log Out</span>
          </button>
        </aside>

        <main className="mainContent">
          <h1 className="pageTitle">Scanner</h1>
          {errorMsg && <div className="errorBanner">{errorMsg}</div>}

          <section className="scanCard">
            {/* ── Mode Toggle ── */}
            <div className="modeToggle">
              <button
                className={`modeBtn ${scanMode === 'remote' ? 'active' : ''}`}
                onClick={() => { setScanMode('remote'); setErrorMsg(''); }}
              >
                Remote Scan
              </button>
              <button
                className={`modeBtn ${scanMode === 'agent' ? 'active' : ''}`}
                onClick={() => { setScanMode('agent'); setErrorMsg(''); }}
              >
                Agent Scan
              </button>
            </div>

            {/* ── Step 1: Baseline Version (ใช้ร่วมกัน) ── */}
            <div className="stepSection">
              <div className="stepHeader">
                <div className="stepNumber">1</div>
                <div className="stepTitleGroup">
                  <div className="stepTitle">Choose Baseline Version</div>
                  <div className="stepLine"></div>
                </div>
              </div>
              <div className="fieldGroup single">
                <label className="fieldLabel">Version</label>
                {loadingBaselines && <div className="baselineLoading">กำลังโหลด baseline...</div>}
                {!loadingBaselines && baselineError && <div className="baselineError">{baselineError}</div>}
                {!loadingBaselines && !baselineError && (
                  <select
                    className="fieldInput selectInput"
                    value={version}
                    onChange={(e) => {
                      setVersion(e.target.value);
                      setConnStatus('idle');
                      setConnMessage('');
                    }}
                  >
                    {baselines.map((b) => (
                      <option key={b.filename} value={b.version}>{b.version}</option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            {/* ── Step 2: Remote mode ── */}
            {scanMode === 'remote' && (
              <div className="stepSection">
                <div className="stepHeader">
                  <div className="stepNumber">2</div>
                  <div className="stepTitleGroup">
                    <div className="stepTitle">IP Address And HostName</div>
                    <div className="stepLine"></div>
                  </div>
                </div>
                <div className="fieldRow">
                  <div className="fieldGroup">
                    <label className="fieldLabelIP">IP</label>
                    <input className="fieldInputIP" type="text" placeholder="192.168.1.50"
                      value={ip} onChange={(e) => setIp(e.target.value)} />
                  </div>
                  <div className="fieldGroup">
                    <label className="fieldLabelIP">Username</label>
                    <input className="fieldInputIP" type="text" placeholder=".\Administrator"
                      value={username} onChange={(e) => setUsername(e.target.value)} />
                  </div>
                  <div className="fieldGroup">
                    <label className="fieldLabelIP">Password</label>
                    <input className="fieldInputIP" type="password" placeholder="••••••••"
                      value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                </div>
                <div className="actionRow">
                  <button
                    className="connectButton"
                    onClick={handleConnect}
                    disabled={connStatus === 'loading' || loadingBaselines}
                  >
                    {connStatus === 'loading' ? 'Connecting…' : 'Connect'}
                  </button>
                  {connStatus !== 'idle' && (
                    <div className="statusConnected">
                      <span className={`statusDot ${connStatus}`}>
                        {connStatus === 'success' && '✔'}
                        {connStatus === 'error'   && '✖'}
                        {connStatus === 'loading' && '…'}
                      </span>
                      <span>{connMessage}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ── Step 2: Agent mode ── */}
            {scanMode === 'agent' && (
              <div className="stepSection">
                <div className="stepHeader">
                  <div className="stepNumber">2</div>
                  <div className="stepTitleGroup">
                    <div className="stepTitle">Select Agent</div>
                    <div className="stepLine"></div>
                  </div>
                </div>

                {loadingAgents && (
                  <div className="baselineLoading" style={{ marginLeft: 28 }}>กำลังโหลด agent...</div>
                )}
                {!loadingAgents && agentError && (
                  <div className="baselineError" style={{ marginLeft: 28 }}>{agentError}</div>
                )}
                {!loadingAgents && !agentError && (
                  <>
                    <div className="fieldRow">
                      <div className="fieldGroup" style={{ marginLeft: 28 }}>
                        <label className="fieldLabel">Agent</label>
                        <select
                          className="fieldInput selectInput"
                          style={{ width: 240 }}
                          value={selectedAgent}
                          onChange={(e) => setSelectedAgent(e.target.value)}
                        >
                          {agents.map((a) => (
                            <option key={a.agent_id} value={a.agent_id}>
                              {a.agent_id}{a.hostname ? ` (${a.hostname})` : ''}
                            </option>
                          ))}
                        </select>
                      </div>

                      {selectedAgentInfo && (
                        <div className="fieldGroup" style={{ justifyContent: 'flex-end', paddingBottom: 2 }}>
                          <span className={`agentStatusBadge ${agentOnline(selectedAgentInfo) ? 'online' : 'offline'}`}>
                            ● {agentOnline(selectedAgentInfo) ? 'Online' : 'Offline'}
                          </span>
                        </div>
                      )}
                    </div>

                    {selectedAgentInfo && (
                      <div className="actionRow">
                        <div className="statusConnected">
                          <span className="statusDot success">✔</span>
                          <span>
                            {selectedAgentInfo.agent_id}
                            {selectedAgentInfo.hostname ? ` — ${selectedAgentInfo.hostname}` : ''}
                            {selectedAgentInfo.last_seen
                              ? `  (last seen: ${new Date(selectedAgentInfo.last_seen).toLocaleString('th-TH')})`
                              : ''}
                          </span>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── Start Scan button ── */}
            <div className="scanButtonRow">
              {scanMode === 'remote' ? (
                <button
                  className="scanButton"
                  onClick={handleStartRemoteScan}
                  disabled={connStatus !== 'success' || loadingBaselines || !!baselineError}
                >
                  Start Scan
                </button>
              ) : (
                <button
                  className="scanButton"
                  onClick={handleStartAgentScan}
                  disabled={!selectedAgent || loadingAgents || !!agentError || loadingBaselines || !!baselineError}
                >
                  Start Scan
                </button>
              )}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default Home;