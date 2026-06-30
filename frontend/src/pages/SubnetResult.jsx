import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
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
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import {
  MetricCard,
  MetricGrid,
  PanelHeader,
  ReportHeader,
  ReportPanel,
  ReportShell,
  ReportTopbar,
  StatusBadge,
} from './ReportUI';
import { formatReportDate } from './reportUtils';
import './SubnetResult.css';

const SEVERITY_COLORS = {
  critical: '#c2413b',
  high: '#dc6b2f',
  medium: '#d6a11d',
  low: '#64748b',
};

function normalizeFindingStatus(status, target = '', actual = '', raw = '') {
  const statusText = String(status || '').trim().toLowerCase();
  if (statusText) {
    if (/^(pass|passed|compliant)\b/.test(statusText)) return 'pass';
    if (/^(fail|failed|non-compliant|noncompliant)\b/.test(statusText)) return 'fail';
    if (/^(manual|n\/a|na|skip|skipped)\b/.test(statusText)) return 'manual';
  }

  const rawText = String(raw || '').toLowerCase();
  const explicitStatus = rawText.match(/["']?status["']?\s*[:=]\s*["']?(pass|passed|fail|failed|manual|n\/a|na|skip|skipped|compliant|non-compliant|noncompliant)\b/);
  if (explicitStatus) return normalizeFindingStatus(explicitStatus[1], target, actual, '');
  if (/\bmanual\b|\bn\/a\b|\bskipped?\b/.test(rawText)) return 'manual';
  if (/\bfailed?\b|\bnon-compliant\b|\bnoncompliant\b/.test(rawText)) return 'fail';
  if (/\bpassed?\b|\bcompliant\b/.test(rawText)) return 'pass';
  if (target && actual && String(target).trim().toLowerCase() === String(actual).trim().toLowerCase()) return 'pass';
  return 'fail';
}

function normalizePolicyPart(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function policyIdentity(item) {
  const settingIdentity = [
    item.policyPath,
    item.registryPath,
    item.name,
    item.section,
  ].map(normalizePolicyPart).filter(Boolean).join('|');

  if (settingIdentity) return settingIdentity;

  return [
    item.checkId,
    item.sourceKey,
    item.name,
    item.section,
  ].map(normalizePolicyPart).filter(Boolean).join('|');
}

function parseScanItems(details, findings) {
  if (Array.isArray(findings) && findings.length > 0) {
    return findings.map((item) => ({
      key: item.source_key || item.check_id || item.check_name,
      sourceKey: item.source_key || '',
      checkId: item.check_id || '',
      name: item.check_name || item.source_key || 'Unknown check',
      section: item.category || 'General',
      severity: String(item.severity || 'Low').toLowerCase(),
      policyPath: item.policy_path || '',
      registryPath: item.registry_path || '',
      target: item.expected_value || '',
      actual: item.current_value || '',
      status: normalizeFindingStatus(item.status, item.expected_value, item.current_value, item.raw_result),
    }));
  }

  return Object.entries(details || {})
    .filter(([key]) => !String(key).startsWith('_'))
    .map(([key, value]) => {
      const raw = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value || '');
      const sectionMatch = key.match(/^\[([^\]]+)\]/);
      const target = (raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/) || [])[1]?.trim() || '';
      const actual = (raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/) || [])[1]?.trim().replace(/\)\s*$/, '') || '';
      return {
        key,
        sourceKey: key,
        checkId: '',
        name: key.replace(/^\[[^\]]+\]\s*/, ''),
        section: sectionMatch ? sectionMatch[1] : 'General',
        severity: 'low',
        policyPath: '',
        registryPath: '',
        target,
        actual,
        status: normalizeFindingStatus(raw, target, actual, raw),
      };
    });
}

function hostLabel(host) {
  return host.hostname || host.host || host.target_name || host.agent_id || 'Unknown host';
}

function scoreTone(score) {
  if (score >= 70) return 'pass';
  if (score >= 40) return 'warn';
  return 'fail';
}

function ChartEmpty({ children }) {
  return <div className="fleetEmpty">{children}</div>;
}

export default function SubnetResult() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [scanData, setScanData] = useState(null);
  const [children, setChildren] = useState([]);
  const [detailModal, setDetailModal] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function loadReport() {
      setLoading(true);
      setErrorMsg('');
      try {
        const reportRes = await fetch(apiUrl(`/api/scan/history/${id}`), { headers: authHeaders() });
        if (reportRes.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }
        const report = await reportRes.json();
        if (!reportRes.ok) throw new Error(report.detail || 'Subnet report not found');

        const childRes = await fetch(apiUrl(`/api/scan/history/${id}/children`), { headers: authHeaders() });
        if (childRes.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }
        const childRows = childRes.ok ? await childRes.json() : [];
        if (cancelled) return;

        const details = report.details || {};
        setScanData({
          ...report,
          subnet: details.subnet || report.hostname || report.target_name || 'Subnet',
          method: details.method || 'agent subnet',
          results: Array.isArray(details.results) ? details.results : [],
        });
        setChildren(Array.isArray(childRows) ? childRows : []);
      } catch (error) {
        if (!cancelled) setErrorMsg(error.message || 'Unable to load subnet result');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadReport();
    return () => { cancelled = true; };
  }, [id, navigate]);

  const overview = useMemo(() => {
    const parentResults = scanData?.results || [];
    const parentByHost = new Map(
      parentResults.map((row) => [hostLabel(row).toLowerCase(), row]),
    );
    const childHosts = children.map((child) => {
      const items = parseScanItems(child.details, child.findings);
      const failItems = items.filter((item) => item.status === 'fail');
      const passItems = items.filter((item) => item.status === 'pass');
      const parentRow = parentByHost.get(hostLabel(child).toLowerCase()) || {};
      return {
        ...parentRow,
        ...child,
        state: 'done',
        scanItems: items,
        failItems,
        passItems,
        failCount: Number.isFinite(Number(child.fail_count)) ? Number(child.fail_count) : failItems.length,
        passCount: Number.isFinite(Number(child.pass_count)) ? Number(child.pass_count) : passItems.length,
      };
    });

    const childNames = new Set(childHosts.map((host) => hostLabel(host).toLowerCase()));
    const unresolvedHosts = parentResults
      .filter((row) => !childNames.has(hostLabel(row).toLowerCase()))
      .map((row) => ({
        ...row,
        state: row.status === 'done' ? 'done' : 'error',
        scanItems: [],
        failItems: [],
        passItems: [],
        failCount: Number(row.fail_count || 0),
        passCount: Number(row.pass_count || 0),
      }));
    const hostRows = [...childHosts, ...unresolvedHosts];
    const completedHosts = childHosts.filter((host) => host.scanItems.length > 0);
    const failedPolicyMap = new Map();
    const passedPolicyMap = new Map();
    const categoryMap = new Map();
    const derivedSeverity = { critical: 0, high: 0, medium: 0, low: 0 };

    const upsertPolicy = (map, item, hostname) => {
      const key = policyIdentity(item) || item.key || item.name;
      if (!map.has(key)) {
        map.set(key, {
          key,
          name: item.name,
          section: item.section,
          severity: item.severity,
          hosts: new Set(),
        });
      }
      map.get(key).hosts.add(hostname);
    };

    const itemPriority = { fail: 3, manual: 2, pass: 1 };
    const uniquePolicyStatuses = (items) => {
      const byPolicy = new Map();
      items.forEach((item) => {
        const key = policyIdentity(item) || item.key || item.name;
        const previous = byPolicy.get(key);
        if (!previous || (itemPriority[item.status] || 0) > (itemPriority[previous.status] || 0)) {
          byPolicy.set(key, item);
        }
      });
      return Array.from(byPolicy.values());
    };

    completedHosts.forEach((host) => {
      const hostname = hostLabel(host);
      uniquePolicyStatuses(host.scanItems).forEach((item) => {
        if (item.status === 'pass') {
          upsertPolicy(passedPolicyMap, item, hostname);
          return;
        }
        if (item.status !== 'fail') return;
        upsertPolicy(failedPolicyMap, item, hostname);
        categoryMap.set(item.section || 'General', (categoryMap.get(item.section || 'General') || 0) + 1);
        const severity = Object.hasOwn(derivedSeverity, item.severity) ? item.severity : 'low';
        derivedSeverity[severity] += 1;
      });
    });

    const repeatedPolicies = Array.from(failedPolicyMap.values())
      .map((item) => ({ ...item, hosts: Array.from(item.hosts) }))
      .filter((item) => item.hosts.length > 1)
      .sort((a, b) => b.hosts.length - a.hosts.length || a.name.localeCompare(b.name));
    const passedEverywhere = Array.from(passedPolicyMap.values())
      .map((item) => ({ ...item, hosts: Array.from(item.hosts) }))
      .filter((item) => completedHosts.length > 0 && item.hosts.length === completedHosts.length)
      .sort((a, b) => a.section.localeCompare(b.section) || a.name.localeCompare(b.name));
    const categoryBreakdown = Array.from(categoryMap.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
    const authoritativeSeverity = scanData?.score_breakdown?.severity_failed;
    const severityCounts = authoritativeSeverity
      ? {
          critical: Number(authoritativeSeverity.critical || 0),
          high: Number(authoritativeSeverity.high || 0),
          medium: Number(authoritativeSeverity.medium || 0),
          low: Number(authoritativeSeverity.low || 0),
        }
      : derivedSeverity;
    const severityData = Object.entries(severityCounts)
      .map(([name, value]) => ({ name: name[0].toUpperCase() + name.slice(1), key: name, value }))
      .filter((item) => item.value > 0);
    const ranking = [...childHosts]
      .sort((a, b) => Number(a.score || 0) - Number(b.score || 0))
      .map((host) => ({
        name: hostLabel(host),
        score: Number(host.score || 0),
        failures: host.failCount,
      }));

    return {
      hostRows,
      completedHostCount: completedHosts.length,
      attentionHosts: childHosts.filter((host) => host.failCount > 0).length + unresolvedHosts.length,
      errorHostCount: unresolvedHosts.filter((host) => host.state === 'error').length,
      repeatedPolicies,
      commonFails: repeatedPolicies.slice(0, 8),
      repeatedPolicyCount: repeatedPolicies.length,
      passedEverywhere,
      commonPasses: passedEverywhere.slice(0, 8),
      passedEverywhereCount: passedEverywhere.length,
      categoryBreakdown,
      severityCounts,
      severityData,
      ranking,
      worstHosts: [...childHosts]
        .sort((a, b) => b.failCount - a.failCount || Number(a.score || 0) - Number(b.score || 0))
        .slice(0, 6),
    };
  }, [children, scanData]);

  const openPolicyModal = (type) => {
    const failed = type === 'fail';
    setDetailModal({
      title: failed ? 'Repeated Failed Policies' : 'Checks Passed On Every Host',
      subtitle: failed
        ? `${overview.repeatedPolicyCount} policies failed on more than one host`
        : `${overview.passedEverywhereCount} checks passed on all ${overview.completedHostCount} completed hosts`,
      tone: failed ? 'fail' : 'pass',
      rows: failed ? overview.repeatedPolicies : overview.passedEverywhere,
      empty: failed ? 'No repeated failed policies found' : 'No checks passed on every host',
    });
  };

  const totalHosts = Math.max(Number(scanData?.host_count || 0), overview.hostRows.length);
  const totalPassed = Number(scanData?.pass_count || 0);
  const totalFailed = Number(scanData?.fail_count || 0);
  const failedHosts = Number(scanData?.failed_host_count ?? 0) + overview.errorHostCount;
  const criticalHigh = Number(scanData?.critical_count || overview.severityCounts.critical)
    + Number(scanData?.high_count || overview.severityCounts.high);
  const assessed = scanData?.score_breakdown?.total_assessed_count
    ?? scanData?.score_breakdown?.assessed_weight
    ?? totalPassed + totalFailed;

  return (
    <ReportShell active="History">
      <ReportTopbar />

      {loading && <div className="fleetState">Loading subnet report...</div>}
      {!loading && errorMsg && <div className="fleetState error">{errorMsg}</div>}

      {!loading && scanData && (
        <>
          <ReportHeader
            eyebrow="Fleet security report"
            title={scanData.subnet}
            subtitle="Review compliance posture across scanned hosts and drill into the controls driving fleet risk."
            score={scanData.score}
            scoreLabel="Fleet compliance"
            context={[
              { label: 'Baseline', value: scanData.version || 'Auto-selected per host' },
              { label: 'Scan ID', value: `#${scanData.id}` },
              { label: 'Scanned', value: formatReportDate(scanData.scan_date) },
              { label: 'Hosts', value: `${totalHosts} discovered / ${overview.completedHostCount} completed` },
              { label: 'Assessed', value: assessed ? `${totalPassed}/${assessed}` : '' },
            ]}
            actions={(
              <>
                <button type="button" className="reportAction" onClick={() => navigate('/history')}>History</button>
                <button type="button" className="reportAction primary" onClick={() => navigate('/scan/new')}>New Scan</button>
              </>
            )}
          />

          <MetricGrid>
            <MetricCard label="Total hosts" value={totalHosts} hint={`${overview.completedHostCount} completed`} tone="info" />
            <MetricCard label="Hosts requiring attention" value={failedHosts} hint={`${overview.errorHostCount} unavailable/error`} tone="fail" />
            <MetricCard label="Passed checks" value={totalPassed} hint="Across completed hosts" tone="pass" />
            <MetricCard label="Failed checks" value={totalFailed} hint={`${criticalHigh} Critical or High`} tone="critical" />
            <MetricCard label="Passed everywhere" value={overview.passedEverywhereCount} hint="Common fleet strengths" tone="pass" />
          </MetricGrid>

          <div className="fleetChartGrid">
            <ReportPanel className="fleetChartPanel">
              <PanelHeader title="Failure Severity" subtitle={`${totalFailed} failed checks across the fleet`} />
              {overview.severityData.length ? (
                <div className="fleetSeverityBody">
                  <div className="fleetChartCanvas">
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie data={overview.severityData} dataKey="value" nameKey="name" innerRadius={54} outerRadius={82} paddingAngle={2}>
                          {overview.severityData.map((item) => <Cell key={item.key} fill={SEVERITY_COLORS[item.key]} />)}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="fleetDonutLabel"><strong>{criticalHigh}</strong><span>Critical + High</span></div>
                  </div>
                  <div className="fleetLegend">
                    {overview.severityData.map((item) => (
                      <div key={item.key}>
                        <i style={{ background: SEVERITY_COLORS[item.key] }} />
                        <span>{item.name}</span>
                        <strong>{item.value}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              ) : <ChartEmpty>No failed severity data available</ChartEmpty>}
            </ReportPanel>

            <ReportPanel className="fleetChartPanel fleetCategoryPanel">
              <PanelHeader title="Failed Checks By Category" subtitle="Largest control areas contributing to fleet failures" />
              {overview.categoryBreakdown.length ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={overview.categoryBreakdown} layout="vertical" margin={{ top: 8, right: 24, left: 12, bottom: 4 }}>
                    <CartesianGrid stroke="#eef1f5" horizontal={false} />
                    <XAxis type="number" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#667085' }} />
                    <YAxis dataKey="name" type="category" width={138} axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#475467' }} />
                    <Tooltip />
                    <Bar dataKey="count" name="Failed checks" fill="#2563eb" radius={[0, 4, 4, 0]} barSize={14} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <ChartEmpty>No failed category data available</ChartEmpty>}
            </ReportPanel>

            <ReportPanel className="fleetChartPanel fleetRankingPanel">
              <PanelHeader title="Host Compliance Ranking" subtitle="Lowest compliance scores appear first" />
              {overview.ranking.length ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={overview.ranking} layout="vertical" margin={{ top: 8, right: 24, left: 12, bottom: 4 }}>
                    <CartesianGrid stroke="#eef1f5" horizontal={false} />
                    <XAxis type="number" domain={[0, 100]} axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#667085' }} />
                    <YAxis dataKey="name" type="category" width={132} axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: '#475467' }} />
                    <Tooltip formatter={(value, name, item) => [`${value}% (${item.payload.failures} failed)`, 'Compliance']} />
                    <Bar dataKey="score" name="Compliance" radius={[0, 4, 4, 0]} barSize={16}>
                      {overview.ranking.map((host) => (
                        <Cell
                          key={host.name}
                          fill={host.score >= 70 ? '#15803d' : host.score >= 40 ? '#b45309' : '#c2413b'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : <ChartEmpty>No completed host scans available</ChartEmpty>}
            </ReportPanel>
          </div>

          <div className="fleetInsightGrid">
            <ReportPanel>
              <PanelHeader title="Hosts Requiring Attention" subtitle="Prioritized by failed checks and compliance score" />
              <div className="fleetList">
                {!overview.worstHosts.length && <ChartEmpty>No completed host scans available</ChartEmpty>}
                {overview.worstHosts.map((host) => (
                  <div className="fleetHostRow" key={host.scan_id || host.id || hostLabel(host)}>
                    <div className="fleetHostIdentity">
                      <strong>{hostLabel(host)}</strong>
                      <span>{host.version || scanData.version}</span>
                    </div>
                    <div className="fleetHostCounts">
                      <span>{host.passCount} pass</span>
                      <strong>{host.failCount} fail</strong>
                    </div>
                    <StatusBadge tone={scoreTone(Number(host.score || 0))}>{Number(host.score || 0)}%</StatusBadge>
                    {host.scan_id && (
                      <button type="button" className="fleetLinkButton" onClick={() => navigate(`/scan/${host.scan_id}/report`)}>
                        View Report
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </ReportPanel>

            <ReportPanel>
              <PanelHeader
                title="Repeated Failed Policies"
                subtitle={`${overview.repeatedPolicyCount} controls failed on multiple hosts`}
                action={<button type="button" className="fleetTextButton" onClick={() => openPolicyModal('fail')} disabled={!overview.repeatedPolicyCount}>View all</button>}
              />
              <div className="fleetList">
                {!overview.commonFails.length && <ChartEmpty>No repeated failed policies found</ChartEmpty>}
                {overview.commonFails.map((item) => (
                  <div className="fleetPolicyRow" key={item.key}>
                    <div>
                      <strong>{item.name}</strong>
                      <span>{item.section}</span>
                    </div>
                    <StatusBadge tone={item.severity === 'critical' ? 'fail' : 'warn'}>{item.severity}</StatusBadge>
                    <b>{item.hosts.length}/{overview.completedHostCount} hosts</b>
                  </div>
                ))}
              </div>
            </ReportPanel>
          </div>

          <ReportPanel className="fleetPassPanel">
            <PanelHeader
              title="Passed On Every Host"
              subtitle="Controls consistently compliant across all completed host scans"
              action={<button type="button" className="fleetTextButton" onClick={() => openPolicyModal('pass')} disabled={!overview.passedEverywhereCount}>View all</button>}
            />
            <div className="fleetPassGrid">
              {!overview.commonPasses.length && <ChartEmpty>No controls passed on every host</ChartEmpty>}
              {overview.commonPasses.map((item) => (
                <div className="fleetPassItem" key={item.key}>
                  <span>{item.section}</span>
                  <strong>{item.name}</strong>
                  <StatusBadge tone="pass">{item.hosts.length} hosts</StatusBadge>
                </div>
              ))}
            </div>
          </ReportPanel>

          <ReportPanel className="fleetHostTablePanel">
            <PanelHeader title="All Scanned Hosts" subtitle="Open a child report to review findings and remediation for a specific machine" />
            <div className="fleetTableWrap">
              <div className="fleetHostTable fleetHostTableHead">
                <span>Host</span>
                <span>Score</span>
                <span>Passed</span>
                <span>Failed</span>
                <span>Status</span>
                <span>Action</span>
              </div>
              {!overview.hostRows.length && <ChartEmpty>No subnet hosts were recorded</ChartEmpty>}
              {overview.hostRows.map((host, index) => (
                <div className="fleetHostTable" key={host.scan_id || host.id || `${hostLabel(host)}-${index}`}>
                  <div className="fleetHostIdentity">
                    <strong>{hostLabel(host)}</strong>
                    <span>
                      {host.agent_id || host.host || ''}
                      {Array.isArray(host.ip_addresses) && host.ip_addresses.length ? ` | ${host.ip_addresses.join(', ')}` : ''}
                    </span>
                  </div>
                  <StatusBadge tone={host.state === 'error' ? 'fail' : scoreTone(Number(host.score || 0))}>
                    {host.state === 'error' ? '-' : `${Number(host.score || 0)}%`}
                  </StatusBadge>
                  <span className="fleetNumber pass">{host.passCount || 0}</span>
                  <span className="fleetNumber fail">{host.failCount || 0}</span>
                  <div>
                    <StatusBadge tone={host.state === 'error' ? 'fail' : 'pass'}>{host.state === 'error' ? 'Error' : 'Completed'}</StatusBadge>
                    {host.error && <small className="fleetHostError">{host.error}</small>}
                  </div>
                  <div>
                    {host.scan_id
                      ? <button type="button" className="fleetLinkButton" onClick={() => navigate(`/scan/${host.scan_id}/report`)}>View Report</button>
                      : <span className="fleetUnavailable">Unavailable</span>}
                  </div>
                </div>
              ))}
            </div>
          </ReportPanel>
        </>
      )}

      {detailModal && (
        <div className="fleetModalBackdrop" role="presentation" onClick={() => setDetailModal(null)}>
          <div className="fleetModal" role="dialog" aria-modal="true" aria-labelledby="fleet-modal-title" onClick={(event) => event.stopPropagation()}>
            <div className="fleetModalHead">
              <div>
                <h2 id="fleet-modal-title">{detailModal.title}</h2>
                <p>{detailModal.subtitle}</p>
              </div>
              <button type="button" onClick={() => setDetailModal(null)} aria-label="Close">x</button>
            </div>
            <div className="fleetModalList">
              {!detailModal.rows.length && <ChartEmpty>{detailModal.empty}</ChartEmpty>}
              {detailModal.rows.map((item) => (
                <div className="fleetModalRow" key={item.key}>
                  <div>
                    <strong>{item.name}</strong>
                    <span>{item.section}</span>
                  </div>
                  <StatusBadge tone={detailModal.tone}>
                    {detailModal.tone === 'pass' ? 'Passed' : item.severity || 'Failed'}
                  </StatusBadge>
                  <b>{item.hosts.length} hosts</b>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </ReportShell>
  );
}
