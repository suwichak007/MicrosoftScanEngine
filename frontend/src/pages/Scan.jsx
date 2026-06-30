/* eslint-disable react-hooks/set-state-in-effect */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import {
  PanelHeader,
  ReportHeader,
  ReportPanel,
  ReportShell,
  ReportTopbar,
  StatusBadge,
} from './ReportUI';
import { formatReportDate } from './reportUtils';
import './Scan.css';

const SCAN_MODES = [
  {
    id: 'remote',
    marker: '01',
    title: 'Remote Machine',
    description: 'Connect directly to one Windows machine using administrative credentials.',
    connection: 'WinRM credentials',
    baseline: 'Manual baseline',
  },
  {
    id: 'agent',
    marker: '02',
    title: 'Registered Agent',
    description: 'Dispatch a scan to one registered agent with automatic baseline detection.',
    connection: 'Agent heartbeat',
    baseline: 'Auto-detected',
  },
  {
    id: 'subnet',
    marker: '03',
    title: 'Remote Subnet',
    description: 'Discover and scan Windows hosts in a subnet using shared credentials.',
    connection: 'WinRM discovery',
    baseline: 'Manual baseline',
  },
  {
    id: 'agent-subnet',
    marker: '04',
    title: 'Agent Subnet',
    description: 'Scan online registered agents whose IP addresses belong to a subnet.',
    connection: 'Agent heartbeat',
    baseline: 'Auto-detected per host',
  },
];

const MODE_STATUS = {
  remote: 'Needs connection test',
  agent: 'Loads online agents',
  subnet: 'Needs subnet credentials',
  'agent-subnet': 'Matches online agents by IP',
};

function ipv4ToInt(value) {
  const parts = String(value || '').trim().split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((result, part) => ((result << 8) | part) >>> 0, 0);
}

function ipInCidr(ip, cidr) {
  const [network, prefixRaw] = String(cidr || '').trim().split('/');
  const ipValue = ipv4ToInt(ip);
  const networkValue = ipv4ToInt(network);
  const prefix = Number(prefixRaw);
  if (ipValue === null || networkValue === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipValue & mask) === (networkValue & mask);
}

export default function Scan() {
  const navigate = useNavigate();
  const [baselines, setBaselines] = useState([]);
  const [version, setVersion] = useState('');
  const [loadingBaselines, setLoadingBaselines] = useState(true);
  const [baselineError, setBaselineError] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [scanMode, setScanMode] = useState('remote');

  const [ip, setIp] = useState('192.168.2.83');
  const [scanUsername, setScanUsername] = useState('');
  const [password, setPassword] = useState('');
  const [connStatus, setConnStatus] = useState('idle');
  const [connMessage, setConnMessage] = useState('');

  const [agents, setAgents] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [agentError, setAgentError] = useState('');
  const [role, setRole] = useState('Member Server');
  const [subnet, setSubnet] = useState('192.168.1.0/24');
  const [maxParallel, setMaxParallel] = useState(5);

  useEffect(() => {
    let cancelled = false;

    async function fetchBaselines() {
      setLoadingBaselines(true);
      setBaselineError('');
      try {
        const response = await fetch(apiUrl('/api/scan/versions'), { headers: authHeaders() });
        if (response.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }
        const data = await response.json();
        if (!response.ok || !Array.isArray(data) || !data.length) {
          throw new Error(data?.detail || 'No baseline files found');
        }
        if (!cancelled) {
          setBaselines(data);
          setVersion(data[0].version_id);
        }
      } catch (error) {
        if (!cancelled) setBaselineError(error.message || 'Failed to load baselines');
      } finally {
        if (!cancelled) setLoadingBaselines(false);
      }
    }

    fetchBaselines();
    return () => { cancelled = true; };
  }, [navigate]);

  useEffect(() => {
    if (scanMode !== 'agent' && scanMode !== 'agent-subnet') return undefined;
    let cancelled = false;

    async function fetchAgents() {
      setLoadingAgents(true);
      setAgentError('');
      try {
        const response = await fetch(apiUrl('/api/agents'), { headers: authHeaders() });
        if (response.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }
        const data = await response.json();
        if (!response.ok || !Array.isArray(data) || !data.length) {
          throw new Error('No registered agents found');
        }
        if (!cancelled) {
          setAgents(data);
          setSelectedAgent((current) => {
            if (current && data.some((agent) => agent.agent_id === current)) return current;
            return (data.find((agent) => agent.online && agent.baseline_ready) || data[0]).agent_id;
          });
        }
      } catch (error) {
        if (!cancelled) setAgentError(error.message || 'Failed to load agents');
      } finally {
        if (!cancelled) setLoadingAgents(false);
      }
    }

    fetchAgents();
    return () => { cancelled = true; };
  }, [navigate, scanMode]);

  useEffect(() => {
    setVersion((current) => {
      if (scanMode === 'agent' || scanMode === 'agent-subnet') return 'auto';
      if (current === 'auto' && baselines.length) return baselines[0].version_id;
      return current;
    });
  }, [baselines, scanMode]);

  const resetConnection = () => {
    setConnStatus('idle');
    setConnMessage('');
  };

  const updateRemoteField = (setter) => (event) => {
    setter(event.target.value);
    resetConnection();
  };

  const selectedAgentInfo = agents.find((agent) => agent.agent_id === selectedAgent);
  const selectedBaseline = baselines.find((baseline) => baseline.version_id === version);
  const onlineAgents = agents.filter((agent) => agent.online);
  const subnetAgents = useMemo(
    () => onlineAgents.filter((agent) => (agent.ip_addresses || []).some((address) => ipInCidr(address, subnet))),
    [onlineAgents, subnet],
  );
  const baselineOptions = (scanMode === 'agent' || scanMode === 'agent-subnet')
    ? [{ version_id: 'auto', display_name: 'Auto detect baseline', filename: 'auto', check_count: null }, ...baselines]
    : baselines;
  const isAgentMode = scanMode === 'agent' || scanMode === 'agent-subnet';
  const roleRelevant = !isAgentMode && selectedBaseline?.os_family === 'windows_server';

  const handleConnect = async () => {
    if (!ip || !scanUsername || !password) {
      setErrorMsg('Please enter IP address, username, and password');
      return;
    }
    setErrorMsg('');
    setConnStatus('loading');
    setConnMessage('');
    try {
      const response = await fetch(apiUrl('/api/scan/test-connection'), {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          host: ip,
          username: scanUsername,
          password,
          use_ssl: false,
          skip_ca_check: true,
        }),
      });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await response.json();
      if (response.ok && data.success) {
        setConnStatus('success');
        setConnMessage(`Connected to ${data.hostname || ip}`);
      } else {
        setConnStatus('error');
        setConnMessage(data.message || 'Connection failed');
      }
    } catch (error) {
      setConnStatus('error');
      setConnMessage(`Connection error: ${error.message}`);
    }
  };

  const handleStartRemoteScan = () => {
    if (connStatus !== 'success') { setErrorMsg('Test the connection successfully before starting the scan'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          host: ip,
          username: scanUsername,
          password,
          version,
          role,
          use_ssl: false,
          skip_ca_check: true,
          target_name: `${ip} (${version})`,
        },
      },
    });
  };

  const handleStartAgentScan = () => {
    if (!selectedAgentInfo) { setErrorMsg('Please select an agent'); return; }
    if (!selectedAgentInfo.online) { setErrorMsg('The selected agent is offline'); return; }
    if (!selectedAgentInfo.baseline_ready) { setErrorMsg(selectedAgentInfo.baseline_error || 'The selected agent has no compatible baseline'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          agent_id: selectedAgentInfo.agent_id,
          host: selectedAgentInfo.hostname,
          version,
          role: 'auto',
          _mode: 'agent',
          target_name: `${selectedAgentInfo.agent_id} (${version === 'auto' ? 'Auto detect baseline' : version})`,
        },
      },
    });
  };

  const handleStartSubnetScan = () => {
    if (!subnet) { setErrorMsg('Please enter a subnet'); return; }
    if (!scanUsername) { setErrorMsg('Please enter a username'); return; }
    if (!password) { setErrorMsg('Please enter a password'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          subnet,
          username: scanUsername,
          password,
          version,
          role,
          use_ssl: false,
          skip_ca_check: true,
          max_parallel: maxParallel,
          _mode: 'subnet',
          target_name: `${subnet} (${version === 'auto' ? 'Auto detect baseline' : version})`,
        },
      },
    });
  };

  const handleStartAgentSubnetScan = () => {
    if (!subnet) { setErrorMsg('Please enter a subnet'); return; }
    if (!version) { setErrorMsg('Please select a baseline version'); return; }
    if (!subnetAgents.length) { setErrorMsg('No online registered agents were found in this subnet'); return; }
    setErrorMsg('');
    navigate('/result', {
      state: {
        scanParams: {
          subnet,
          version,
          role: 'auto',
          _mode: 'agent-subnet',
          target_name: `${subnet} (${version})`,
        },
      },
    });
  };

  const startHandler = scanMode === 'remote'
    ? handleStartRemoteScan
    : scanMode === 'subnet'
      ? handleStartSubnetScan
      : scanMode === 'agent-subnet'
        ? handleStartAgentSubnetScan
        : handleStartAgentScan;

  const disabledReason = (() => {
    if (loadingBaselines) return 'Loading baselines';
    if (baselineError || !version) return 'Baseline unavailable';
    if (scanMode === 'remote') {
      if (!ip || !scanUsername || !password) return 'Enter target credentials';
      if (connStatus !== 'success') return 'Test connection first';
    }
    if (scanMode === 'agent') {
      if (loadingAgents) return 'Loading agents';
      if (agentError || !selectedAgentInfo) return 'Select an agent';
      if (!selectedAgentInfo.online) return 'Selected agent is offline';
      if (!selectedAgentInfo.baseline_ready) return 'No compatible baseline';
    }
    if (scanMode === 'subnet' && (!subnet || !scanUsername || !password)) return 'Enter subnet credentials';
    if (scanMode === 'agent-subnet') {
      if (loadingAgents) return 'Loading agents';
      if (!subnet) return 'Enter a subnet';
      if (!subnetAgents.length) return 'No online agents in subnet';
    }
    return '';
  })();
  const launchReady = !disabledReason;

  const currentMode = SCAN_MODES.find((mode) => mode.id === scanMode);
  const connectionTone = connStatus === 'success' ? 'pass' : connStatus === 'error' ? 'fail' : connStatus === 'loading' ? 'warn' : 'neutral';
  const connectionLabel = connStatus === 'success'
    ? 'Connection verified'
    : connStatus === 'error'
      ? 'Connection failed'
      : connStatus === 'loading'
        ? 'Testing connection'
        : 'Connection not tested';
  const targetSummary = scanMode === 'remote'
    ? ip || 'Not set'
    : scanMode === 'agent'
      ? selectedAgentInfo?.hostname || selectedAgentInfo?.agent_id || 'Not selected'
      : subnet || 'Not set';
  const connectionSummary = scanMode === 'remote'
    ? connStatus === 'success' ? connMessage : connStatus === 'error' ? connMessage : 'Connection not tested'
    : scanMode === 'agent'
      ? selectedAgentInfo?.online ? 'Agent online' : 'Agent offline'
      : scanMode === 'agent-subnet'
        ? `${subnetAgents.length} online agents matched`
        : `${maxParallel} parallel workers`;

  return (
    <ReportShell active="Scan">
      <ReportTopbar />
      <ReportHeader
        eyebrow="Security assessment"
        title="Start a Scan"
        subtitle="Choose a scan method, configure the target, and review the request before dispatch."
        context={[
          { label: 'Baselines', value: loadingBaselines ? 'Loading' : baselines.length },
          { label: 'Registered agents', value: agents.length || 'Load when needed' },
        ]}
        actions={(
          <>
            <button type="button" className="reportAction" onClick={() => navigate('/home')}>Home</button>
            <button type="button" className="reportAction" onClick={() => navigate('/history')}>History</button>
          </>
        )}
      />

      {errorMsg && (
        <div className="scanError">
          <span>{errorMsg}</span>
          <button type="button" onClick={() => setErrorMsg('')}>Dismiss</button>
        </div>
      )}

      <section className="scanStep">
        <div className="scanStepHead">
          <span>1</span>
          <div><h2>Choose Scan Mode</h2><p>Select how SecureScan should reach the target environment.</p></div>
        </div>
        <div className={`scanModeGrid active-${scanMode}`}>
          {SCAN_MODES.map((mode) => (
            <button
              type="button"
              className={`scanModeCard ${scanMode === mode.id ? 'active' : 'muted'}`}
              aria-pressed={scanMode === mode.id}
              key={mode.id}
              onClick={() => {
                setScanMode(mode.id);
                setErrorMsg('');
                resetConnection();
              }}
            >
              <div className="scanModeTop">
                <span className="scanModeMarker">{mode.marker}</span>
                <span className="scanModeArrow">›</span>
              </div>
              <strong>{mode.title}</strong>
              <p>{mode.description}</p>
              <div className="scanModeMeta"><span>{mode.connection}</span><span>{mode.baseline}</span></div>
              <small className="scanModeStatus">{MODE_STATUS[mode.id]}</small>
            </button>
          ))}
        </div>
        <div className="scanModeFocus">
          <span>Selected method</span>
          <strong>{currentMode.title}</strong>
          <small>{MODE_STATUS[scanMode]}</small>
        </div>
      </section>

      <section className="scanStep">
        <div className="scanStepHead">
          <span>2</span>
          <div><h2>Configure Target And Baseline</h2><p>Required fields change according to the selected scan mode.</p></div>
        </div>

        <div className="scanWorkspace">
          <ReportPanel className={`scanConfigPanel scanPrimarySurface mode-${scanMode}`}>
            <PanelHeader title={currentMode.title} subtitle={currentMode.description} />
            <div className="scanConfigBody">
              <div className="scanConfigFocusBar">
                <div>
                  <span>Target focus</span>
                  <strong>{targetSummary}</strong>
                </div>
                <StatusBadge tone={launchReady ? 'pass' : 'warn'}>
                  {scanMode === 'remote' ? connectionLabel : launchReady ? 'Ready' : 'Needs attention'}
                </StatusBadge>
              </div>
              <div className="scanFormGrid">
                {(scanMode === 'remote' || scanMode === 'subnet' || scanMode === 'agent-subnet') && (
                  <label className="scanField scanFieldPrimary">
                    <span>{scanMode === 'remote' ? 'IP address or hostname' : 'Subnet (CIDR)'}</span>
                    <input
                      type="text"
                      value={scanMode === 'remote' ? ip : subnet}
                      onChange={scanMode === 'remote' ? updateRemoteField(setIp) : (event) => setSubnet(event.target.value)}
                      placeholder={scanMode === 'remote' ? '192.168.1.50' : '192.168.1.0/24'}
                    />
                  </label>
                )}

                {(scanMode === 'remote' || scanMode === 'subnet') && (
                  <>
                    <label className="scanField scanFieldPrimary">
                      <span>Username</span>
                      <input type="text" value={scanUsername} onChange={updateRemoteField(setScanUsername)} placeholder=".\\Administrator" autoComplete="username" />
                    </label>
                    <label className="scanField scanFieldPrimary">
                      <span>Password</span>
                      <input type="password" value={password} onChange={updateRemoteField(setPassword)} placeholder="Enter administrative password" autoComplete="current-password" />
                    </label>
                  </>
                )}

                {scanMode === 'subnet' && (
                  <label className="scanField">
                    <span>Parallel workers</span>
                    <input type="number" min="1" max="20" value={maxParallel} onChange={(event) => setMaxParallel(Number(event.target.value))} />
                  </label>
                )}

                <label className="scanField scanFieldWide scanFieldSecondary">
                  <span>Baseline</span>
                  <select
                    value={version}
                    disabled={loadingBaselines || Boolean(baselineError)}
                    onChange={(event) => {
                      setVersion(event.target.value);
                      resetConnection();
                    }}
                  >
                    {baselineOptions.map((baseline) => (
                      <option key={baseline.filename} value={baseline.version_id}>
                        {baseline.display_name}{baseline.check_count ? ` (${baseline.check_count} checks)` : ''}
                      </option>
                    ))}
                  </select>
                  {loadingBaselines && <small>Loading available baselines...</small>}
                  {baselineError && <small className="error">{baselineError}</small>}
                </label>

                {roleRelevant && (
                  <label className="scanField">
                    <span>Target role</span>
                    <select value={role} onChange={(event) => setRole(event.target.value)}>
                      <option value="Member Server">Member Server</option>
                      <option value="Domain Controller">Domain Controller</option>
                    </select>
                    <small>Controls which server policy column is assessed.</small>
                  </label>
                )}
                {isAgentMode && (
                  <div className="scanField">
                    <span>Target role</span>
                    <strong>Auto-detected by agent</strong>
                    <small>Windows ProductType selects Member Server or Domain Controller on the target.</small>
                  </div>
                )}
              </div>

              {scanMode === 'remote' && (
                <div className="scanConnectionRow">
                  <button
                    type="button"
                    className="scanSecondaryButton"
                    onClick={handleConnect}
                    disabled={connStatus === 'loading' || loadingBaselines}
                  >
                    {connStatus === 'loading' ? 'Testing Connection...' : 'Test Connection'}
                  </button>
                  <div className={`scanConnectionState ${connectionTone}`}>
                    <StatusBadge tone={connectionTone}>{connectionLabel}</StatusBadge>
                    <span>{connMessage || 'Verify the remote target before launching this scan.'}</span>
                  </div>
                </div>
              )}

              {scanMode === 'agent' && (
                <div className="scanAgentSection">
                  {selectedAgentInfo && (
                    <div className={`scanSelectedAgent ${selectedAgentInfo.online && selectedAgentInfo.baseline_ready ? 'ready' : selectedAgentInfo.online ? 'warn' : 'offline'}`}>
                      <div>
                        <span>Selected agent</span>
                        <strong>{selectedAgentInfo.hostname || selectedAgentInfo.agent_id}</strong>
                        <small>{selectedAgentInfo.detected_baseline || selectedAgentInfo.baseline_error || 'Baseline not detected'}</small>
                      </div>
                      <StatusBadge tone={selectedAgentInfo.online ? selectedAgentInfo.baseline_ready ? 'pass' : 'warn' : 'fail'}>
                        {selectedAgentInfo.online ? selectedAgentInfo.baseline_ready ? 'Ready' : 'Needs attention' : 'Offline'}
                      </StatusBadge>
                    </div>
                  )}
                  {loadingAgents && <div className="scanInlineState">Loading registered agents...</div>}
                  {agentError && <div className="scanInlineState error">{agentError}</div>}
                  {!loadingAgents && !agentError && (
                    <div className="scanAgentGrid">
                      {agents.map((agent) => (
                        <button
                          type="button"
                          key={agent.agent_id}
                          className={`scanAgentCard ${selectedAgent === agent.agent_id ? 'active' : ''} ${!agent.online ? 'offline' : ''} ${agent.online && agent.baseline_ready ? 'ready' : ''}`}
                          onClick={() => setSelectedAgent(agent.agent_id)}
                        >
                          <div>
                            <strong>{agent.hostname || agent.agent_id}</strong>
                            <StatusBadge tone={agent.online ? agent.baseline_ready ? 'pass' : 'warn' : 'fail'}>
                              {agent.online ? agent.baseline_ready ? 'Ready' : 'Needs attention' : 'Offline'}
                            </StatusBadge>
                          </div>
                          <span>{agent.agent_id}</span>
                          <span>{[agent.os_name, agent.os_release, agent.os_build && `build ${agent.os_build}`].filter(Boolean).join(' | ')}</span>
                          <span>{agent.detected_baseline || agent.baseline_error || 'Baseline not detected'}</span>
                          <span>{agent.detected_role || 'Role will be detected on the next heartbeat'}</span>
                          <small>Last seen {formatReportDate(agent.last_seen)}</small>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {scanMode === 'agent-subnet' && (
                <div className="scanSubnetAgentSummary">
                  <div><strong>{subnetAgents.length}</strong><span>online agents matched</span></div>
                  <div><strong>{onlineAgents.length}</strong><span>online agents total</span></div>
                  <div><strong>{subnetAgents.filter((agent) => agent.baseline_ready).length}</strong><span>baseline ready</span></div>
                  <p>Only online agents with an IPv4 address inside {subnet || 'the selected subnet'} will receive a scan job.</p>
                </div>
              )}
            </div>
          </ReportPanel>

          <ReportPanel className={`scanReviewPanel ${disabledReason ? 'blocked' : 'ready'}`}>
            <PanelHeader title="Review Request" subtitle="Confirm the effective scan settings before launch." />
            <div className={`scanLaunchStatus ${launchReady ? 'ready' : 'blocked'}`}>
              <StatusBadge tone={launchReady ? 'pass' : 'warn'}>
                {launchReady ? 'Ready to scan' : 'Blocked'}
              </StatusBadge>
              <strong>{currentMode.title}</strong>
            </div>
            <dl className="scanReviewList">
              <div><dt>Mode</dt><dd>{currentMode.title}</dd></div>
              <div><dt>Target</dt><dd>{targetSummary}</dd></div>
              <div><dt>Baseline</dt><dd>{version === 'auto' ? 'Auto detect baseline' : version || 'Not selected'}</dd></div>
              {roleRelevant && <div><dt>Role</dt><dd>{role}</dd></div>}
              {isAgentMode && <div><dt>Role</dt><dd>{selectedAgentInfo?.detected_role || 'Auto-detected on target'}</dd></div>}
              <div><dt>Availability</dt><dd>{connectionSummary}</dd></div>
              {scanMode === 'subnet' && <div><dt>Parallel workers</dt><dd>{maxParallel}</dd></div>}
            </dl>
            <div className="scanLaunch">
              {disabledReason && <p className="scanDisabledReason">{disabledReason}</p>}
              <button type="button" className="scanPrimaryButton" onClick={startHandler} disabled={Boolean(disabledReason)}>
                Start Scan
              </button>
              <small>Progress and results will open on the next screen.</small>
            </div>
          </ReportPanel>
        </div>
      </section>
    </ReportShell>
  );
}
