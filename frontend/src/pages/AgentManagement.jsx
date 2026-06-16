/* eslint-disable react-hooks/set-state-in-effect */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth } from '../auth';
import { API_BASE, apiUrl } from '../config/api';
import './AgentManagement.css';
import ProfileMenu from './ProfileMenu';

function Sidebar({ navigate }) {
  const items = [
    { label: 'Home', path: '/home' },
    { label: 'History', path: '/history' },
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
  return `.\\ScanAgentSetup.exe --backend-url ${API_BASE}`;
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

function normalizeAgentRows(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.value)) return data.value;
  return [];
}

function baselineLabel(baseline) {
  return baseline?.display_name || baseline?.version_id || baseline?.baseline_id || baseline?.filename || 'baseline';
}

function friendlyBaselineError(detail, fallback = 'Baseline operation failed') {
  const text = String(detail || fallback);
  const lower = text.toLowerCase();
  if (lower.includes('only .xlsx') || lower.includes('.xlsx')) {
    return 'Only Microsoft Excel .xlsx files are supported.';
  }
  if (lower.includes('0 checks') || lower.includes('no checks')) {
    return 'No checks were found. Please review the Excel baseline format.';
  }
  if (lower.includes('pending upload not found')) {
    return 'The pending upload session expired. Please choose the Excel file again.';
  }
  if (lower.includes('analyze baseline failed')) {
    return text.replace(/^Analyze baseline failed:\s*/i, 'The workbook could not be analyzed: ');
  }
  if (lower.includes('convert baseline failed')) {
    return text.replace(/^Convert baseline failed:\s*/i, 'The workbook could not be converted: ');
  }
  if (lower.includes('baseline not found')) {
    return 'Baseline not found. Refresh the library and try again.';
  }
  return text;
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
  const [baselineAnalysis, setBaselineAnalysis] = useState(null);
  const [baselineColumns, setBaselineColumns] = useState({});
  const [analyzingBaseline, setAnalyzingBaseline] = useState(false);
  const [uploadingBaseline, setUploadingBaseline] = useState(false);
  const [baselineNotice, setBaselineNotice] = useState(null);
  const [baselineDeleteTarget, setBaselineDeleteTarget] = useState(null);
  const [deletingBaseline, setDeletingBaseline] = useState(false);
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
    role: 'auto',
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
        setAgents(normalizeAgentRows(data));
        return;
      }
      if (!res.ok) {
        setErrorMsg(data.detail || 'Unable to load agents');
        return;
      }
      setAgents(Array.isArray(data) ? data : []);
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
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
        setErrorMsg(data.detail || 'Unable to load baselines');
        return;
      }
      setBaselines(Array.isArray(data) ? data : []);
    } catch (err) {
      setErrorMsg(`Unable to load baselines: ${err.message}`);
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

  const resetBaselineAnalysis = () => {
    setBaselineAnalysis(null);
    setBaselineColumns({});
  };

  const analyzeBaseline = async () => {
    if (!baselineFile) {
      setBaselineNotice({
        type: 'error',
        title: 'Analyze failed',
        lines: ['Please choose a .xlsx baseline file first.'],
      });
      return;
    }
    if (!baselineFile.name.toLowerCase().endsWith('.xlsx')) {
      setBaselineNotice({
        type: 'error',
        title: 'Analyze failed',
        lines: ['Only Microsoft Excel .xlsx files are supported.'],
      });
      return;
    }

    setAnalyzingBaseline(true);
    setBaselineNotice(null);
    setErrorMsg('');
    resetBaselineAnalysis();

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
        setBaselineNotice({
          type: 'error',
          title: 'Analyze failed',
          lines: [friendlyBaselineError(data.detail, 'Analyze baseline failed')],
        });
        return;
      }

      const initialColumns = {};
      (data.sheets || []).forEach((sheet) => {
        initialColumns[sheet.sheet] = sheet.selected_target_columns || sheet.detected_target_columns || [];
      });
      setBaselineAnalysis(data);
      setBaselineColumns(initialColumns);
      setBaselineNotice({
        type: 'info',
        title: 'Workbook analyzed',
        lines: [
          `Baseline: ${data.baseline_name || data.baseline_id || 'Unknown baseline'}`,
          `Sheets: ${(data.sheets || []).length}`,
          'Review target columns below, then upload baseline.',
        ],
      });
    } catch (err) {
      setBaselineNotice({
        type: 'error',
        title: 'Analyze failed',
        lines: [friendlyBaselineError(err.message, 'Analyze baseline failed')],
      });
    } finally {
      setAnalyzingBaseline(false);
    }
  };

  const toggleBaselineColumn = (sheetName, columnName) => {
    setBaselineColumns((prev) => {
      const selected = new Set(prev[sheetName] || []);
      if (selected.has(columnName)) {
        selected.delete(columnName);
      } else {
        selected.add(columnName);
      }
      return { ...prev, [sheetName]: Array.from(selected) };
    });
  };

  const uploadBaseline = async () => {
    if (!baselineFile) {
      setBaselineNotice({
        type: 'error',
        title: 'Upload failed',
        lines: ['Please choose a .xlsx baseline file first.'],
      });
      return;
    }
    if (!baselineFile.name.toLowerCase().endsWith('.xlsx')) {
      setBaselineNotice({
        type: 'error',
        title: 'Upload failed',
        lines: ['Only Microsoft Excel .xlsx files are supported.'],
      });
      return;
    }

    setUploadingBaseline(true);
    setBaselineNotice(null);
    setErrorMsg('');
    const form = new FormData();
    form.append('file', baselineFile);
    try {
      const hasAnalysis = Boolean(baselineAnalysis?.upload_id);
      const res = hasAnalysis
        ? await fetch(apiUrl('/api/admin/baselines/upload/confirm'), {
            method: 'POST',
            headers: authHeader(),
            body: JSON.stringify({
              upload_id: baselineAnalysis.upload_id,
              target_columns: baselineColumns,
            }),
          })
        : await fetch(apiUrl('/api/admin/baselines/upload'), {
            method: 'POST',
            headers: authOnlyHeader(),
            body: form,
          });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setBaselineNotice({
          type: 'error',
          title: 'Upload failed',
          lines: [friendlyBaselineError(data.detail, 'Upload baseline failed')],
        });
        return;
      }
      setBaselineNotice({
        type: 'success',
        title: 'Upload successful',
        lines: [
          `Baseline: ${data.baseline_name || data.baseline_id || 'Unknown baseline'}`,
          `Baseline ID: ${data.baseline_id || '-'}`,
          `Source file: ${data.source_file || baselineFile.name}`,
          `Checks: ${data.check_count || 0}`,
          `Generated files: ${(data.generated_files || []).map((f) => String(f).split(/[\\/]/).pop()).join(', ') || '-'}`,
          'Agent update: agents will download the updated scanner package on their next scan job.',
        ],
      });
      setBaselineFile(null);
      resetBaselineAnalysis();
      await fetchBaselines();
    } catch (err) {
      setBaselineNotice({
        type: 'error',
        title: 'Upload failed',
        lines: [friendlyBaselineError(err.message, 'Upload baseline failed')],
      });
    } finally {
      setUploadingBaseline(false);
    }
  };

  const deleteBaseline = async (baseline) => {
    if (!baseline?.filename) return;
    setBaselineDeleteTarget(baseline);
  };

  const confirmDeleteBaseline = async () => {
    const baseline = baselineDeleteTarget;
    if (!baseline?.filename) return;
    const label = baselineLabel(baseline);
    setDeletingBaseline(true);
    setBaselineNotice(null);
    try {
      const res = await fetch(apiUrl(`/api/admin/baselines/${encodeURIComponent(baseline.filename)}`), {
        method: 'DELETE',
        headers: authOnlyHeader(),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setBaselineNotice({
          type: 'error',
          title: 'Delete failed',
          lines: [friendlyBaselineError(data.detail, 'Delete baseline failed')],
        });
        return;
      }
      setBaselineNotice({
        type: 'success',
        title: 'Baseline deleted',
        lines: [
          `Baseline: ${label}`,
          `Removed files: ${(data.removed || [data.filename]).join(', ')}`,
          'Agent update: agents will download the updated scanner package on their next scan job.',
        ],
      });
      setBaselineDeleteTarget(null);
      await fetchBaselines();
    } catch (err) {
      setBaselineNotice({
        type: 'error',
        title: 'Delete failed',
        lines: [friendlyBaselineError(err.message, 'Delete baseline failed')],
      });
    } finally {
      setDeletingBaseline(false);
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
      role: 'auto',
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
      role: schedule.role || 'auto',
      frequency: schedule.frequency || 'daily',
      time: schedule.time || '09:00',
      day_of_week: schedule.day_of_week || 0,
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
      setErrorMsg(`Unable to copy command: ${err.message}`);
    }
  };

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
            <ProfileMenu />
          </div>
        </header>

        <div className="pageHead agentPageHead">
          <div>
            <h1 className="pageTitle">Agent Management</h1>
            <p className="pageDesc">Manage registered agents, schedules, install commands, and baseline uploads</p>
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
              <div className="scheduleAutoRole">
                <span>Role</span>
                <strong>Auto-detected</strong>
              </div>
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
                      {schedule.scan_type === 'agent' ? schedule.agent_id : schedule.subnet} ? {schedule.frequency} ? {schedule.version}
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
                    setBaselineNotice(null);
                    resetBaselineAnalysis();
                  }}
                />
                <span>{baselineFile ? baselineFile.name : 'Choose Excel baseline'}</span>
              </label>
              <button className="agentSecondaryBtn" onClick={analyzeBaseline} disabled={analyzingBaseline || uploadingBaseline || !baselineFile}>
                {analyzingBaseline ? 'Analyzing...' : 'Analyze columns'}
              </button>
              <button className="agentPrimaryBtn" onClick={uploadBaseline} disabled={uploadingBaseline || !baselineFile}>
                {uploadingBaseline ? 'Uploading...' : 'Upload baseline'}
              </button>
              <button className="agentSecondaryBtn" onClick={fetchBaselines} disabled={loadingBaselines}>
                Refresh
              </button>
            </div>
            {baselineNotice && (
              <div className={`baselineNotice ${baselineNotice.type || 'info'}`}>
                <strong>{baselineNotice.title}</strong>
                {(baselineNotice.lines || []).map((line) => (
                  <span key={line}>{line}</span>
                ))}
              </div>
            )}
            {baselineAnalysis && (
              <div className="baselineColumnPanel">
                <div className="baselineColumnHead">
                  <div>
                    <strong>{baselineAnalysis.baseline_name || baselineAnalysis.baseline_id}</strong>
                    <span>Choose target columns to scan. Leave detected columns selected for the default behavior.</span>
                  </div>
                  <code>{baselineAnalysis.filename}</code>
                </div>
                <div className="baselineSheetList">
                  {(baselineAnalysis.sheets || []).map((sheet) => {
                    const selected = baselineColumns[sheet.sheet] || [];
                    return (
                      <div className="baselineSheet" key={sheet.sheet}>
                        <div className="baselineSheetTitle">
                          <span>{sheet.sheet}</span>
                          <em>{sheet.sheet_type}</em>
                        </div>
                        <div className="baselineColumnChoices">
                          {(sheet.columns || []).map((column) => {
                            const checked = selected.includes(column);
                            const detected = (sheet.detected_target_columns || []).includes(column);
                            return (
                              <label className={`baselineColumnChoice ${checked ? 'selected' : ''}`} key={`${sheet.sheet}-${column}`}>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => toggleBaselineColumn(sheet.sheet, column)}
                                />
                                <span>{column}</span>
                                {detected && <small>detected</small>}
                              </label>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            <div className="baselineList">
              {loadingBaselines && <div className="baselineEmpty">Loading baselines...</div>}
              {!loadingBaselines && baselines.length === 0 && <div className="baselineEmpty">No baselines found</div>}
              {!loadingBaselines && baselines.map((b) => (
                <div className="baselineItem" key={`${b.filename}-${b.version_id}`}>
                  <div className="agentStack">
                    <span className="agentStrong">{b.display_name || b.version_id}</span>
                    <span className="muted">{b.filename}</span>
                  </div>
                  <div className="baselineMeta">
                    <span>{b.os_family || 'unknown'}</span>
                    <span>{b.check_count || 0} checks</span>
                    {b.severity_counts && (
                      <span>
                        C:{b.severity_counts.Critical || 0} H:{b.severity_counts.High || 0} M:{b.severity_counts.Medium || 0}
                      </span>
                    )}
                    <button className="baselineDeleteBtn" onClick={() => deleteBaseline(b)}>
                      Delete
                    </button>
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
              Loading agents...
            </div>
          )}

          {!loading && agents.length === 0 && (
            <div className="agentEmpty">
              <p>No registered agents found</p>
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
                              {[agent.os_release, agent.os_build && `build ${agent.os_build}`].filter(Boolean).join(' ? ')}
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

      {baselineDeleteTarget && (
        <div className="baselineModalBackdrop" role="presentation">
          <div className="baselineModal" role="dialog" aria-modal="true" aria-labelledby="delete-baseline-title">
            <h2 id="delete-baseline-title">Delete baseline?</h2>
            <p>
              Delete "{baselineLabel(baselineDeleteTarget)}" from the active baseline library.
            </p>
            <div className="baselineModalFacts">
              <span>File: {baselineDeleteTarget.filename}</span>
              <span>Checks: {baselineDeleteTarget.check_count || 0}</span>
              <span>Agents will download the updated scanner package on their next scan job.</span>
            </div>
            <div className="baselineModalActions">
              <button
                className="agentSecondaryBtn"
                onClick={() => setBaselineDeleteTarget(null)}
                disabled={deletingBaseline}
              >
                Cancel
              </button>
              <button
                className="baselineDeleteBtn"
                onClick={confirmDeleteBaseline}
                disabled={deletingBaseline}
              >
                {deletingBaseline ? 'Deleting...' : 'Delete baseline'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


