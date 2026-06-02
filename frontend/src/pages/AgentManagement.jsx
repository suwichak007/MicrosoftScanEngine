/* eslint-disable react-hooks/set-state-in-effect */
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
  const [baselines, setBaselines] = useState([]);
  const [loadingBaselines, setLoadingBaselines] = useState(true);
  const [baselineFile, setBaselineFile] = useState(null);
  const [uploadingBaseline, setUploadingBaseline] = useState(false);
  const [baselineMsg, setBaselineMsg] = useState('');
  const [baselineAnalysis, setBaselineAnalysis] = useState(null);
  const [selectedColumns, setSelectedColumns] = useState({});
  const [schedules, setSchedules] = useState([]);
  const [loadingSchedules, setLoadingSchedules] = useState(true);
  const [scheduleMsg, setScheduleMsg] = useState('');
  const [editingScheduleId, setEditingScheduleId] = useState(null);
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    scan_type: 'agent',
    agent_id: '',
    subnet: '',
    version: 'auto',
    role: 'Member Server',
    frequency: 'daily',
    time: '09:00',
    day_of_week: 0,
    enabled: true,
  });

  const authHeader = () => ({
    'Content-Type': 'application/json',
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  });
  const authOnlyHeader = () => ({
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  });

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl('/api/agents'), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (res.ok) {
        const initial = {};
        (data.sheets || []).forEach((sheet) => {
          initial[sheet.sheet] = sheet.selected_target_columns || [];
        });
        setSelectedColumns(initial);
        setBaselineAnalysis(data);
        setBaselineMsg(`Analyze complete: ${data.baseline_name}`);
        return;
      }
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

  const fetchBaselines = useCallback(async () => {
    setLoadingBaselines(true);
    try {
      const res = await fetch(apiUrl('/api/admin/baselines'), { headers: authOnlyHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || 'โหลด baseline ไม่สำเร็จ');
        return;
      }
      setBaselines(Array.isArray(data) ? data : []);
    } catch (err) {
      setErrorMsg(`โหลด baseline ไม่สำเร็จ: ${err.message}`);
    } finally {
      setLoadingBaselines(false);
    }
  }, [navigate]);

  useEffect(() => { fetchBaselines(); }, [fetchBaselines]);

  const fetchSchedules = useCallback(async () => {
    setLoadingSchedules(true);
    try {
      const res = await fetch(apiUrl('/api/admin/schedules'), { headers: authOnlyHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setScheduleMsg(data.detail || 'Load schedules failed');
        return;
      }
      setSchedules(Array.isArray(data) ? data : []);
    } catch (err) {
      setScheduleMsg(`Load schedules failed: ${err.message}`);
    } finally {
      setLoadingSchedules(false);
    }
  }, [navigate]);

  useEffect(() => { fetchSchedules(); }, [fetchSchedules]);

  const uploadBaseline = async () => {
    if (!baselineFile) {
      setBaselineMsg('กรุณาเลือกไฟล์ .xlsx ก่อน');
      return;
    }
    if (!baselineFile.name.toLowerCase().endsWith('.xlsx')) {
      setBaselineMsg('รองรับเฉพาะไฟล์ .xlsx เท่านั้น');
      return;
    }

    setUploadingBaseline(true);
    setBaselineMsg('');
    setErrorMsg('');
    setBaselineAnalysis(null);
    setSelectedColumns({});
    const form = new FormData();
    form.append('file', baselineFile);
    try {
      const res = await fetch(apiUrl('/api/admin/baselines/analyze'), {
        method: 'POST',
        headers: authOnlyHeader(),
        body: form,
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setBaselineMsg(data.detail || 'อัปโหลด baseline ไม่สำเร็จ');
        return;
      }
      setBaselineMsg(`อัปโหลดสำเร็จ: ${data.baseline_name} (${data.check_count} checks)`);
      setBaselineFile(null);
      await fetchBaselines();
    } catch (err) {
      setBaselineMsg(`อัปโหลด baseline ไม่สำเร็จ: ${err.message}`);
    } finally {
      setUploadingBaseline(false);
    }
  };

  const toggleBaselineColumn = (sheetName, columnName) => {
    setSelectedColumns((prev) => {
      const current = new Set(prev[sheetName] || []);
      if (current.has(columnName)) current.delete(columnName);
      else current.add(columnName);
      return { ...prev, [sheetName]: Array.from(current) };
    });
  };

  const confirmBaselineUpload = async () => {
    if (!baselineAnalysis?.upload_id) return;
    setUploadingBaseline(true);
    setBaselineMsg('');
    try {
      const res = await fetch(apiUrl('/api/admin/baselines/upload/confirm'), {
        method: 'POST',
        headers: authHeader(),
        body: JSON.stringify({
          upload_id: baselineAnalysis.upload_id,
          target_columns: selectedColumns,
        }),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setBaselineMsg(data.detail || 'Upload baseline failed');
        return;
      }
      setBaselineMsg(`Upload complete: ${data.baseline_name} (${data.check_count} checks)`);
      setBaselineFile(null);
      setBaselineAnalysis(null);
      setSelectedColumns({});
      await fetchBaselines();
    } catch (err) {
      setBaselineMsg(`Upload baseline failed: ${err.message}`);
    } finally {
      setUploadingBaseline(false);
    }
  };

  const resetScheduleForm = () => {
    setEditingScheduleId(null);
    setScheduleForm({
      name: '',
      scan_type: 'agent',
      agent_id: '',
      subnet: '',
      version: 'auto',
      role: 'Member Server',
      frequency: 'daily',
      time: '09:00',
      day_of_week: 0,
      enabled: true,
    });
  };

  const saveSchedule = async () => {
    setScheduleMsg('');
    try {
      const url = editingScheduleId
        ? apiUrl(`/api/admin/schedules/${editingScheduleId}`)
        : apiUrl('/api/admin/schedules');
      const res = await fetch(url, {
        method: editingScheduleId ? 'PUT' : 'POST',
        headers: authHeader(),
        body: JSON.stringify(scheduleForm),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setScheduleMsg(data.detail || 'Save schedule failed');
        return;
      }
      setScheduleMsg(`Schedule saved: ${data.name}`);
      resetScheduleForm();
      await fetchSchedules();
    } catch (err) {
      setScheduleMsg(`Save schedule failed: ${err.message}`);
    }
  };

  const editSchedule = (schedule) => {
    setEditingScheduleId(schedule.id);
    setScheduleForm({
      name: schedule.name || '',
      scan_type: schedule.scan_type || 'agent',
      agent_id: schedule.agent_id || '',
      subnet: schedule.subnet || '',
      version: schedule.version || 'auto',
      role: schedule.role || 'Member Server',
      frequency: schedule.frequency || 'daily',
      time: schedule.time || '09:00',
      day_of_week: schedule.day_of_week ?? 0,
      enabled: !!schedule.enabled,
    });
  };

  const deleteSchedule = async (scheduleId) => {
    setScheduleMsg('');
    try {
      const res = await fetch(apiUrl(`/api/admin/schedules/${scheduleId}`), {
        method: 'DELETE',
        headers: authOnlyHeader(),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setScheduleMsg(data.detail || 'Delete schedule failed');
        return;
      }
      await fetchSchedules();
    } catch (err) {
      setScheduleMsg(`Delete schedule failed: ${err.message}`);
    }
  };

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

        <section className="agentCard scheduleAdminCard">
          <div className="agentCardHead">
            <h2>Scan Scheduling</h2>
            <span className="muted">{loadingSchedules ? 'Loading...' : `${schedules.length} schedules`}</span>
          </div>
          <div className="schedulePanel">
            <div className="scheduleForm">
              <input
                className="scheduleInput"
                value={scheduleForm.name}
                onChange={(e) => setScheduleForm((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="Schedule name"
              />
              <select
                className="scheduleInput"
                value={scheduleForm.scan_type}
                onChange={(e) => setScheduleForm((prev) => ({ ...prev, scan_type: e.target.value }))}
              >
                <option value="agent">Agent</option>
                <option value="agent-subnet">Agent subnet</option>
              </select>
              {scheduleForm.scan_type === 'agent' ? (
                <select
                  className="scheduleInput"
                  value={scheduleForm.agent_id}
                  onChange={(e) => setScheduleForm((prev) => ({ ...prev, agent_id: e.target.value }))}
                >
                  <option value="">Choose agent</option>
                  {agents.map((agent) => (
                    <option key={agent.agent_id} value={agent.agent_id}>
                      {agent.hostname || agent.agent_id}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  className="scheduleInput"
                  value={scheduleForm.subnet}
                  onChange={(e) => setScheduleForm((prev) => ({ ...prev, subnet: e.target.value }))}
                  placeholder="192.168.1.0/24"
                />
              )}
              <select
                className="scheduleInput"
                value={scheduleForm.version}
                onChange={(e) => setScheduleForm((prev) => ({ ...prev, version: e.target.value }))}
              >
                <option value="auto">Auto baseline</option>
                {baselines.map((b) => (
                  <option key={`${b.filename}-${b.version_id}`} value={b.version_id}>
                    {b.display_name || b.version_id}
                  </option>
                ))}
              </select>
              <select
                className="scheduleInput"
                value={scheduleForm.role}
                onChange={(e) => setScheduleForm((prev) => ({ ...prev, role: e.target.value }))}
              >
                <option value="Member Server">Member Server</option>
                <option value="Domain Controller">Domain Controller</option>
              </select>
              <select
                className="scheduleInput"
                value={scheduleForm.frequency}
                onChange={(e) => setScheduleForm((prev) => ({
                  ...prev,
                  frequency: e.target.value,
                  time: e.target.value === 'hourly' ? '0' : '09:00',
                }))}
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
              {scheduleForm.frequency === 'weekly' && (
                <select
                  className="scheduleInput"
                  value={scheduleForm.day_of_week}
                  onChange={(e) => setScheduleForm((prev) => ({ ...prev, day_of_week: Number(e.target.value) }))}
                >
                  <option value={0}>Monday</option>
                  <option value={1}>Tuesday</option>
                  <option value={2}>Wednesday</option>
                  <option value={3}>Thursday</option>
                  <option value={4}>Friday</option>
                  <option value={5}>Saturday</option>
                  <option value={6}>Sunday</option>
                </select>
              )}
              <input
                className="scheduleInput"
                value={scheduleForm.time}
                onChange={(e) => setScheduleForm((prev) => ({ ...prev, time: e.target.value }))}
                placeholder={scheduleForm.frequency === 'hourly' ? 'Minute 0-59' : 'HH:MM'}
              />
              <label className="scheduleToggle">
                <input
                  type="checkbox"
                  checked={scheduleForm.enabled}
                  onChange={(e) => setScheduleForm((prev) => ({ ...prev, enabled: e.target.checked }))}
                />
                Enabled
              </label>
              <button className="agentPrimaryBtn" onClick={saveSchedule}>
                {editingScheduleId ? 'Update schedule' : 'Create schedule'}
              </button>
              {editingScheduleId && (
                <button className="agentSecondaryBtn" onClick={resetScheduleForm}>Cancel</button>
              )}
            </div>
            {scheduleMsg && <div className="baselineUploadMsg">{scheduleMsg}</div>}
            <div className="scheduleList">
              {loadingSchedules && <div className="baselineEmpty">Loading schedules...</div>}
              {!loadingSchedules && schedules.length === 0 && <div className="baselineEmpty">No schedules yet</div>}
              {!loadingSchedules && schedules.map((schedule) => (
                <div className="scheduleItem" key={schedule.id}>
                  <div className="agentStack">
                    <span className="agentStrong">{schedule.name}</span>
                    <span className="muted">
                      {schedule.scan_type === 'agent' ? schedule.agent_id : schedule.subnet} · {schedule.frequency} · {schedule.version}
                    </span>
                    <span className="muted">Next run {formatDate(schedule.next_run)}</span>
                    {schedule.last_error && <span className="agentBaselineError">{schedule.last_error}</span>}
                  </div>
                  <div className="agentActions">
                    <span className={`agentStatus ${schedule.enabled ? 'online' : 'offline'}`}>
                      {schedule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <button className="agentSecondaryBtn" onClick={() => editSchedule(schedule)}>Edit</button>
                    <button className="agentSecondaryBtn" onClick={() => deleteSchedule(schedule.id)}>Delete</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="agentCard baselineAdminCard">
          <div className="agentCardHead">
            <h2>Baseline Library</h2>
            <span className="muted">{loadingBaselines ? 'Loading...' : `${baselines.length} baselines`}</span>
          </div>
          <div className="baselineUploadPanel">
            <div className="baselineUploadControls">
              <label className="baselineFilePicker">
                <input
                  type="file"
                  accept=".xlsx"
                  onChange={(e) => {
                    setBaselineFile(e.target.files?.[0] || null);
                    setBaselineMsg('');
                  }}
                />
                <span>{baselineFile ? baselineFile.name : 'Choose Excel baseline'}</span>
              </label>
              <button className="agentPrimaryBtn" onClick={uploadBaseline} disabled={uploadingBaseline}>
                {uploadingBaseline ? 'Analyzing...' : 'Analyze baseline'}
              </button>
              <button className="agentSecondaryBtn" onClick={fetchBaselines} disabled={loadingBaselines}>
                Refresh
              </button>
            </div>
            {baselineMsg && <div className="baselineUploadMsg">{baselineMsg}</div>}
            {baselineAnalysis && (
              <div className="baselineColumnMapper">
                <div className="agentCardHead compactHead">
                  <h2>Column Mapping</h2>
                  <span className="muted">{baselineAnalysis.sheets?.length || 0} sheets</span>
                </div>
                {(baselineAnalysis.sheets || []).map((sheet) => (
                  <div className="baselineSheetMap" key={sheet.sheet}>
                    <div className="agentStack">
                      <span className="agentStrong">{sheet.sheet}</span>
                      <span className="muted">{sheet.sheet_type}</span>
                    </div>
                    <div className="baselineColumnChips">
                      {(sheet.columns || []).map((column) => {
                        const checked = (selectedColumns[sheet.sheet] || []).includes(column);
                        return (
                          <label className={`baselineColumnChip ${checked ? 'selected' : ''}`} key={column}>
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggleBaselineColumn(sheet.sheet, column)}
                            />
                            {column}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
                <div className="baselineMapperActions">
                  <button className="agentPrimaryBtn" onClick={confirmBaselineUpload} disabled={uploadingBaseline}>
                    {uploadingBaseline ? 'Saving...' : 'Confirm upload'}
                  </button>
                  <button
                    className="agentSecondaryBtn"
                    onClick={() => {
                      setBaselineAnalysis(null);
                      setSelectedColumns({});
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            <div className="baselineList">
              {loadingBaselines && <div className="baselineEmpty">กำลังโหลด baseline...</div>}
              {!loadingBaselines && baselines.length === 0 && <div className="baselineEmpty">ยังไม่มี baseline</div>}
              {!loadingBaselines && baselines.map((b) => (
                <div className="baselineItem" key={`${b.filename}-${b.version_id}`}>
                  <div className="agentStack">
                    <span className="agentStrong">{b.display_name || b.version_id}</span>
                    <span className="muted">{b.filename}</span>
                  </div>
                  <div className="baselineMeta">
                    <span>{b.os_family || 'unknown'}</span>
                    <span>{b.check_count || 0} checks</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

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
