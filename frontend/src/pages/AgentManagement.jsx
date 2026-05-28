import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth } from '../auth';
import { API_BASE, apiUrl } from '../config/api';
import './AgentManagement.css';

const INSTALL_TOKEN_PLACEHOLDER = '<INSTALL_TOKEN>';

function Sidebar({ navigate }) {
  const items = [
    { label: 'Home', path: '/home' },
    { label: 'History', path: '/history' },
    { label: 'Guide', path: '/guide' },
    { label: 'Agents', path: '/admin/agents', active: true },
    { label: 'Users', path: '/admin/users' },
  ];

  return (
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
          {items.map((item) => (
            <button
              key={item.path}
              className={`sideLink ${item.active ? 'active' : ''}`}
              onClick={() => navigate(item.path)}
            >
              <span className="sideLinkDot" />
              {item.label}
            </button>
          ))}
        </nav>
      </div>
      <button className="logoutBtn" onClick={() => { clearAuth(); navigate('/login'); }}>
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M5 2H2v10h3M9 10l3-3-3-3M12 7H5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Log out
      </button>
    </aside>
  );
}

function formatDate(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString('th-TH');
}

function buildInstallCommand() {
  return `.\\ScanAgentSetup.exe --backend-url ${API_BASE} --install-token ${INSTALL_TOKEN_PLACEHOLDER}`;
}

function healthLabel(status) {
  const labels = {
    ready: 'Ready',
    offline: 'Offline',
    missing_os_metadata: 'Missing OS',
    baseline_unresolved: 'No baseline',
    scan_error: 'Scan error',
  };
  return labels[status] || status || '-';
}

export default function AgentManagement() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [copied, setCopied] = useState('');

  const authHeader = () => ({
    'Content-Type': 'application/json',
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  });

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl('/api/agents'), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || 'ไม่สามารถโหลด agent ได้');
        return;
      }
      setAgents(Array.isArray(data) ? data : []);
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  const stats = useMemo(() => {
    const online = agents.filter((a) => a.online).length;
    return {
      total: agents.length,
      online,
      offline: agents.length - online,
    };
  }, [agents]);

  const copyText = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  };

  const copyCommand = async (copyKey = 'new-agent') => {
    try {
      await copyText(buildInstallCommand());
      setCopied(copyKey);
      window.setTimeout(() => setCopied(''), 1800);
    } catch (err) {
      setErrorMsg(`Copy command ไม่สำเร็จ: ${err.message}`);
    }
  };

  const currentUsername = localStorage.getItem('username') || '';

  return (
    <div className="root">
      <Sidebar navigate={navigate} />

      <main className="main agentMain">
        <header className="topbar">
          <p className="topbarDate">
            {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </p>
          <div className="topbarActions">
            <button className="agentRefreshBtn" onClick={fetchAgents} disabled={loading}>
              {loading ? <span className="spin" /> : null}
              Refresh
            </button>
            <div className="avatar">{currentUsername.charAt(0).toUpperCase() || 'A'}</div>
          </div>
        </header>

        <div className="pageHead agentPageHead">
          <div>
            <h1 className="pageTitle">Agent Management</h1>
            <p className="pageDesc">จัดการ agent ที่ลงทะเบียนและคัดลอกคำสั่งติดตั้งสำหรับเครื่องปลายทาง</p>
          </div>
          <button className="agentPrimaryBtn" onClick={() => copyCommand()}>
            {copied === 'new-agent' ? 'Copied' : 'Copy install command'}
          </button>
        </div>

        {errorMsg && (
          <div className="errBanner">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6" /><path d="M7 4v3M7 10h.01" strokeLinecap="round" />
            </svg>
            {errorMsg}
          </div>
        )}

        <div className="agentStats">
          <div className="agentStat">
            <span className="agentStatValue">{stats.total}</span>
            <span className="agentStatLabel">Total agents</span>
          </div>
          <div className="agentStat">
            <span className="agentStatValue">{stats.online}</span>
            <span className="agentStatLabel">Online</span>
          </div>
          <div className="agentStat">
            <span className="agentStatValue">{stats.offline}</span>
            <span className="agentStatLabel">Offline</span>
          </div>
        </div>

        <section className="agentCard">
          <div className="agentCardHead">
            <h2>Registered Agents</h2>
            <code>{buildInstallCommand()}</code>
          </div>

          {loading && (
            <div className="agentEmpty">
              <span className="spin" />
              กำลังโหลด agents...
            </div>
          )}

          {!loading && agents.length === 0 && (
            <div className="agentEmpty">
              <p>ยังไม่มี agent ที่ลงทะเบียน</p>
              <button className="agentPrimaryBtn" onClick={() => copyCommand()}>
                {copied === 'new-agent' ? 'Copied' : 'Copy install command'}
              </button>
            </div>
          )}

          {!loading && agents.length > 0 && (
            <div className="agentTableWrap">
              <table className="agentTable">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Health</th>
                    <th>Hostname</th>
                    <th>IP addresses</th>
                    <th>OS</th>
                    <th>Suggested baseline</th>
                    <th>Jobs</th>
                    <th>Last seen</th>
                    <th>Version</th>
                    <th>Agent ID</th>
                    <th className="center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => (
                    <tr key={agent.agent_id}>
                      <td>
                        <span className={`agentStatus ${agent.online ? 'online' : 'offline'}`}>
                          {agent.online ? 'Online' : 'Offline'}
                        </span>
                      </td>
                      <td>
                        <div className="agentStack">
                          <span className={`agentHealth ${agent.health_status || 'unknown'}`}>
                            {healthLabel(agent.health_status)}
                          </span>
                          {agent.health_message && (
                            <span className={agent.health_status === 'ready' ? 'muted' : 'agentBaselineError'}>
                              {agent.health_message}
                            </span>
                          )}
                          {agent.last_error_at && (
                            <span className="muted">Last error {formatDate(agent.last_error_at)}</span>
                          )}
                        </div>
                      </td>
                      <td className="agentStrong">{agent.hostname || '-'}</td>
                      <td>
                        <div className="ipList">
                          {(agent.ip_addresses || []).length === 0 && <span className="muted">-</span>}
                          {(agent.ip_addresses || []).map((ip) => (
                            <span className="ipChip" key={ip}>{ip}</span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <div className="agentStack">
                          <span className="agentStrong">{agent.os_name || '-'}</span>
                          {(agent.os_release || agent.os_build) && (
                            <span className="muted">
                              {[agent.os_release, agent.os_build && `build ${agent.os_build}`].filter(Boolean).join(' · ')}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="agentStack">
                          <span className="monoCell">{agent.detected_baseline || '-'}</span>
                          {(agent.baseline_match_type || agent.baseline_error) && (
                            <span className={agent.baseline_error ? 'agentBaselineError' : 'muted'}>
                              {agent.baseline_error || agent.baseline_match_type}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="agentStack">
                          <span className={`agentJobBadge ${agent.running_jobs ? 'running' : agent.pending_jobs ? 'pending' : ''}`}>
                            {agent.running_jobs ? `${agent.running_jobs} running` : agent.pending_jobs ? `${agent.pending_jobs} pending` : (agent.last_job_status || '-')}
                          </span>
                          {!!agent.last_job_attempts && <span className="muted">attempt {agent.last_job_attempts}</span>}
                          {agent.last_job_at && <span className="muted">{formatDate(agent.last_job_at)}</span>}
                        </div>
                      </td>
                      <td>{formatDate(agent.last_seen)}</td>
                      <td className="monoCell">{agent.agent_version || '-'}</td>
                      <td className="monoCell agentIdCell">{agent.agent_id}</td>
                      <td>
                        <div className="agentActions">
                          <button className="agentSecondaryBtn" onClick={() => copyCommand(agent.agent_id)}>
                            {copied === agent.agent_id ? 'Copied' : 'Copy install'}
                          </button>
                          <button className="agentSecondaryBtn" onClick={() => copyCommand(`${agent.agent_id}-reinstall`)}>
                            {copied === `${agent.agent_id}-reinstall` ? 'Copied' : 'Reinstall'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
