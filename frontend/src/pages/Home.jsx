import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authHeaders, clearAuth, useCurrentUser } from '../auth';
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
import './HomeOverview.css';

const scoreTone = (score) => {
  if (Number(score) >= 70) return 'pass';
  if (Number(score) >= 40) return 'warn';
  return 'fail';
};

function reportPath(scan) {
  if (!scan?.id) return '';
  return scan.scan_type === 'subnet'
    ? `/scan/${scan.id}/subnet`
    : `/scan/${scan.id}/report`;
}

export default function Home() {
  const navigate = useNavigate();
  const { user } = useCurrentUser();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function loadReports() {
      setLoading(true);
      setErrorMsg('');
      try {
        const response = await fetch(apiUrl('/api/scan/history?limit=5'), { headers: authHeaders() });
        if (response.status === 401) {
          clearAuth();
          navigate('/login');
          return;
        }
        const data = await response.json();
        if (!response.ok || !Array.isArray(data)) throw new Error(data?.detail || 'Failed to load scan history');
        if (!cancelled) setReports(data);
      } catch (error) {
        if (!cancelled) setErrorMsg(error.message || 'Failed to load scan history');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadReports();
    return () => { cancelled = true; };
  }, [navigate]);

  const latestScan = reports[0] || null;
  const latestPass = Number(latestScan?.pass_count || 0);
  const latestFail = Number(latestScan?.fail_count || 0);
  const latestAssessed = Number(
    latestScan?.score_breakdown?.total_assessed_count
      ?? latestScan?.score_breakdown?.assessed_weight
      ?? latestPass + latestFail,
  );
  const latestManual = Number(
    latestScan?.score_breakdown?.excluded_manual_count
      ?? Math.max(0, Number(latestScan?.items_scanned || 0) - latestPass - latestFail),
  );
  const latestScore = Number.isFinite(Number(latestScan?.score)) ? Math.round(Number(latestScan.score)) : 0;
  const latestTarget = latestScan?.hostname || latestScan?.target_name || 'Unknown target';
  const riskTotal = Number(latestScan?.critical_count || 0) + Number(latestScan?.high_count || 0);
  const latestFocusTone = riskTotal > 0 || latestFail > 0 ? 'attention' : 'healthy';
  const attentionCount = latestScan?.scan_type === 'subnet'
    ? Number(latestScan?.failed_host_count || 0)
    : (latestFail > 0 ? 1 : 0);
  const primaryHomeAction = latestScan ? {
    label: latestFail > 0 || riskTotal > 0 ? 'Review Findings' : 'View Latest Report',
    path: reportPath(latestScan),
  } : {
    label: 'Start Scan',
    path: '/scan/new',
  };

  const recentStats = useMemo(() => ({
    single: reports.filter((item) => item.scan_type !== 'subnet').length,
    subnet: reports.filter((item) => item.scan_type === 'subnet').length,
  }), [reports]);

  return (
    <ReportShell active="Home">
      <ReportTopbar />
      <ReportHeader
        eyebrow="Security overview"
        title={user?.username ? `Welcome, ${user.username}` : 'Security Overview'}
        subtitle="Review the latest compliance posture and continue into reports, scanning, or remediation."
        context={[
          { label: 'Recent reports', value: reports.length || 'No data' },
          { label: 'Latest scan', value: latestScan ? formatReportDate(latestScan.scan_date) : 'No data' },
        ]}
        actions={<button type="button" className="reportAction primary" onClick={() => navigate('/scan/new')}>Start Scan</button>}
      />

      {loading && <div className="homeState">Loading security overview...</div>}

      {!loading && errorMsg && (
        <div className="homeError">
          <div>
            <strong>Unable to load the security overview</strong>
            <span>{errorMsg}</span>
          </div>
          <button type="button" onClick={() => navigate('/history')}>Open History</button>
        </div>
      )}

      {!loading && !errorMsg && !latestScan && (
        <ReportPanel className="homeEmpty">
          <span className="homeEmptyMark" aria-hidden="true">+</span>
          <h2>No scan data</h2>
          <p>Start a scan to create the first compliance report for this environment.</p>
          <button type="button" className="homePrimaryButton" onClick={() => navigate('/scan/new')}>Start Scan</button>
        </ReportPanel>
      )}

      {!loading && !errorMsg && latestScan && (
        <>
          <ReportPanel className={`homeAttentionPanel ${latestFocusTone}`}>
            <div className="homeAttentionMain">
              <span className="homeAttentionEyebrow">Needs attention</span>
              <h2>
                {latestFocusTone === 'attention'
                  ? `${attentionCount || latestFail} ${latestScan.scan_type === 'subnet' ? 'host signals' : 'failed checks'} need review`
                  : 'Latest scan is in a healthy state'}
              </h2>
              <div className="homeAttentionStats">
                <span><b>{latestFail}</b> failed</span>
                <span><b>{riskTotal}</b> critical/high</span>
                <span><b>{latestManual}</b> manual</span>
                {latestScan.scan_type === 'subnet' && <span><b>{attentionCount}</b> hosts</span>}
              </div>
            </div>
            <div className="homeAttentionActions">
              <button type="button" className="homePrimaryButton" onClick={() => navigate(primaryHomeAction.path)}>
                {primaryHomeAction.label}
              </button>
              <button type="button" className="homeSecondaryButton" onClick={() => navigate('/scan/new')}>Start New Scan</button>
            </div>
          </ReportPanel>

          <div className="homeActionRail" aria-label="Primary workflow">
            <button type="button" className="homeActionTile scan" onClick={() => navigate('/scan/new')}>
              <div>
                <span>Scan</span>
                <strong>Start assessment</strong>
              </div>
              <b aria-hidden="true">→</b>
            </button>
            <button type="button" className="homeActionTile remediate" onClick={() => navigate(reportPath(latestScan))}>
              <div>
                <span>Remediate</span>
                <strong>{latestFail || riskTotal ? 'Review failed checks' : 'Inspect latest report'}</strong>
              </div>
              <b aria-hidden="true">→</b>
            </button>
            <button type="button" className="homeActionTile verify" onClick={() => navigate('/history')}>
              <div>
                <span>Verify</span>
                <strong>Compare history</strong>
              </div>
              <b aria-hidden="true">→</b>
            </button>
          </div>

          <div className="homeMetricFocus">
          <MetricGrid>
            <MetricCard label="Compliance score" value={`${latestScore}%`} hint="Assessed pass rate" tone={scoreTone(latestScore)} />
            <MetricCard label="Passed checks" value={latestPass} hint={`${latestAssessed} assessed`} tone="pass" />
            <MetricCard label="Failed checks" value={latestFail} hint="Require remediation" tone="fail" />
            <MetricCard label="Critical or High" value={riskTotal} hint={`${latestScan.critical_count || 0} Critical / ${latestScan.high_count || 0} High`} tone="critical" />
            <MetricCard label="Manual or excluded" value={latestManual} hint="Not included in score" />
          </MetricGrid>
          </div>

          <div className="homeOverviewGrid">
            <ReportPanel className={`homeLatestPanel ${latestFocusTone}`}>
              <div className="homeLatestHead">
                <div>
                  <span>Latest scan</span>
                  <h2>{latestTarget}</h2>
                  <p>{formatReportDate(latestScan.scan_date)}</p>
                </div>
                <StatusBadge tone={scoreTone(latestScore)}>{latestScore}% compliant</StatusBadge>
              </div>

              <div className="homeLatestBody">
                <div className="homeScoreRing" style={{ '--home-score': latestScore }}>
                  <div><strong>{latestScore}%</strong><span>Compliance</span></div>
                </div>
                <dl className="homeContext">
                  <div><dt>Baseline</dt><dd>{latestScan.version || 'Unknown baseline'}</dd></div>
                  <div><dt>Scan type</dt><dd>{latestScan.scan_type === 'subnet' ? 'Subnet / Fleet' : 'Single host'}</dd></div>
                  <div><dt>Scan ID</dt><dd>#{latestScan.id}</dd></div>
                  {latestScan.scan_type === 'subnet' && (
                    <div><dt>Hosts</dt><dd>{latestScan.host_count || latestScan.items_scanned || 0}</dd></div>
                  )}
                </dl>
              </div>

              <div className="homeQuickActions">
                <button type="button" className="homePrimaryButton" onClick={() => navigate(reportPath(latestScan))}>View Latest Report</button>
                <button type="button" className="homeSecondaryButton" onClick={() => navigate('/scan/new')}>Start New Scan</button>
                <button type="button" className="homeSecondaryButton" onClick={() => navigate('/history')}>Open History</button>
              </div>
            </ReportPanel>

            <ReportPanel className="homePosturePanel">
              <PanelHeader title="Current Posture" subtitle="Latest report signals requiring attention" />
              <div className="homePostureList">
                <div><span>Failed checks</span><strong className="fail">{latestFail}</strong></div>
                <div><span>Critical findings</span><strong className="fail">{Number(latestScan.critical_count || 0)}</strong></div>
                <div><span>High findings</span><strong className="warn">{Number(latestScan.high_count || 0)}</strong></div>
                <div><span>Manual or excluded</span><strong>{latestManual}</strong></div>
                {latestScan.scan_type === 'subnet' && (
                  <div><span>Hosts requiring attention</span><strong className="fail">{Number(latestScan.failed_host_count || 0)}</strong></div>
                )}
              </div>
            </ReportPanel>
          </div>

          <ReportPanel className="homeRecentPanel">
            <PanelHeader
              title="Recent Reports"
              subtitle={`${recentStats.single} single-host and ${recentStats.subnet} subnet reports in this view`}
              action={<button type="button" className="homeTextButton" onClick={() => navigate('/history')}>View all history</button>}
            />
            <div className="homeRecentTableWrap">
              <div className="homeRecentRow homeRecentHead">
                <span>Report</span>
                <span>Target</span>
                <span>Type</span>
                <span>Score</span>
                <span>Failed</span>
                <span>Action</span>
              </div>
              {reports.map((report) => (
                <div className="homeRecentRow" key={report.id}>
                  <div><strong>#{report.id}</strong><span>{formatReportDate(report.scan_date)}</span></div>
                  <div><strong>{report.hostname || report.target_name || 'Unknown target'}</strong><span>{report.version || 'Unknown baseline'}</span></div>
                  <StatusBadge tone={report.scan_type === 'subnet' ? 'info' : 'neutral'}>
                    {report.scan_type === 'subnet' ? 'Subnet' : 'Single'}
                  </StatusBadge>
                  <StatusBadge tone={scoreTone(report.score)}>{report.score}%</StatusBadge>
                  <strong className="homeRecentFail">{report.fail_count || 0}</strong>
                  <button type="button" className="homeSecondaryButton" onClick={() => navigate(reportPath(report))}>View Report</button>
                </div>
              ))}
            </div>
          </ReportPanel>
        </>
      )}
    </ReportShell>
  );
}
