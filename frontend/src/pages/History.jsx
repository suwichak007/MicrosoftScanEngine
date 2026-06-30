/* eslint-disable react-hooks/set-state-in-effect */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import {
  MetricCard,
  MetricGrid,
  ReportHeader,
  ReportPanel,
  ReportShell,
  ReportTopbar,
  StatusBadge,
} from './ReportUI';
import { formatReportDate } from './reportUtils';
import './History.css';

const authHeader = () => ({
  'Content-Type': 'application/json',
  Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
});

const scoreTone = (score) => {
  if (Number(score) >= 70) return 'pass';
  if (Number(score) >= 40) return 'warn';
  return 'fail';
};

function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const compareLinkHandled = useRef(false);

  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [deleting, setDeleting] = useState(null);
  const [deleteScan, setDeleteScan] = useState(null);
  const [expandedSubnet, setExpandedSubnet] = useState(null);
  const [subnetChildren, setSubnetChildren] = useState({});
  const [comparison, setComparison] = useState(null);
  const [compareScan, setCompareScan] = useState(null);
  const [compareCandidates, setCompareCandidates] = useState([]);
  const [compareBaseId, setCompareBaseId] = useState('');
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareCandidateLoading, setCompareCandidateLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const response = await fetch(apiUrl('/api/scan/history?limit=50'), { headers: authHeader() });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await response.json();
      if (!response.ok || !Array.isArray(data)) throw new Error(data?.detail || 'Unable to load history');
      setHistory(data);
    } catch (error) {
      setErrorMsg(error.message || 'Unable to load history');
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const loadChildren = async (scanId) => {
    if (subnetChildren[scanId]) {
      setExpandedSubnet((current) => current === scanId ? null : scanId);
      return;
    }
    try {
      const response = await fetch(apiUrl(`/api/scan/history/${scanId}/children`), { headers: authHeader() });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || 'Unable to load child scans');
      setSubnetChildren((current) => ({ ...current, [scanId]: Array.isArray(data) ? data : [] }));
      setExpandedSubnet(scanId);
    } catch (error) {
      setErrorMsg(error.message || 'Unable to load child scans');
    }
  };

  const handleView = async (id) => {
    try {
      const response = await fetch(apiUrl(`/api/scan/history/${id}`), { headers: authHeader() });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || 'Unable to load report details');
      navigate(`/scan/${id}/report`, {
        state: {
          fromHistory: {
            score: data.score,
            details: data.details,
            findings: data.findings || [],
            summary: data.summary || null,
            targetName: data.target_name,
            hostname: data.hostname || '',
            version: data.version || '',
            scan_id: data.id,
            scan_date: data.scan_date || '',
          },
        },
      });
    } catch (error) {
      setErrorMsg(error.message || 'Unable to open report');
    }
  };

  const confirmDelete = async () => {
    if (!deleteScan?.id) return;
    setDeleting(deleteScan.id);
    setErrorMsg('');
    try {
      const response = await fetch(apiUrl(`/api/scan/history/${deleteScan.id}`), {
        method: 'DELETE',
        headers: authHeader(),
      });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data?.detail || 'Unable to delete history item');
      }
      setHistory((current) => current.filter((item) => item.id !== deleteScan.id));
      setSubnetChildren((current) => {
        const next = { ...current };
        delete next[deleteScan.id];
        return next;
      });
      if (expandedSubnet === deleteScan.id) setExpandedSubnet(null);
      setDeleteScan(null);
    } catch (error) {
      setErrorMsg(error.message || 'Unable to delete history item');
    } finally {
      setDeleting(null);
    }
  };

  const beginCompare = useCallback(async (scan) => {
    if (!scan?.id) return;
    setCompareCandidateLoading(true);
    setErrorMsg('');
    try {
      const response = await fetch(apiUrl(`/api/scan/history/${scan.id}/compare-candidates`), {
        headers: authHeader(),
      });
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const candidates = await response.json();
      if (!response.ok || !Array.isArray(candidates)) {
        throw new Error(candidates?.detail || 'Unable to load comparison candidates');
      }
      if (!candidates.length) {
        setErrorMsg('No earlier scan for the same host is available for comparison');
        return;
      }
      const compatible = candidates.find((item) => item.same_baseline);
      setCompareCandidates(candidates);
      setCompareScan(scan);
      setCompareBaseId(String((compatible || candidates[0]).id));
    } catch (error) {
      setErrorMsg(error.message || 'Unable to load comparison candidates');
    } finally {
      setCompareCandidateLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    if (loading || compareLinkHandled.current || !history.length) return;
    const requestedId = Number(new URLSearchParams(location.search).get('compare'));
    if (!requestedId) return;
    compareLinkHandled.current = true;
    const requestedScan = history.find((item) => item.id === requestedId && item.scan_type !== 'subnet');
    if (!requestedScan) {
      setErrorMsg(`Scan #${requestedId} is not available in the current history list`);
      return;
    }
    beginCompare(requestedScan);
  }, [beginCompare, history, loading, location.search]);

  const runComparison = async () => {
    if (!compareScan || !compareBaseId) return;
    setCompareLoading(true);
    setErrorMsg('');
    try {
      const response = await fetch(
        apiUrl(`/api/scan/history/${compareScan.id}/compare/${compareBaseId}`),
        { headers: authHeader() },
      );
      if (response.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data?.detail || 'Compare failed');
      setComparison(data);
      setCompareScan(null);
    } catch (error) {
      setErrorMsg(error.message || 'Compare failed');
    } finally {
      setCompareLoading(false);
    }
  };

  const filteredHistory = useMemo(() => {
    const query = search.trim().toLowerCase();
    return history.filter((item) => {
      if (typeFilter !== 'all' && item.scan_type !== typeFilter) return false;
      if (!query) return true;
      return [
        item.id,
        item.hostname,
        item.target_name,
        item.version,
      ].some((value) => String(value || '').toLowerCase().includes(query));
    });
  }, [history, search, typeFilter]);

  const singleCount = history.filter((item) => item.scan_type !== 'subnet').length;
  const subnetCount = history.filter((item) => item.scan_type === 'subnet').length;
  const latestScan = history[0];
  const selectedBase = compareScan
    ? compareCandidates.find((item) => String(item.id) === compareBaseId)
    : null;
  const baselineMismatch = Boolean(
    compareScan && selectedBase && (selectedBase.version || '') !== (compareScan.version || ''),
  );

  const comparisonSections = [
    { key: 'fixed', title: 'Fixed checks', empty: 'No checks were fixed', tone: 'fixed' },
    { key: 'newly_failed', title: 'New failures', empty: 'No new failures', tone: 'new' },
    { key: 'still_failing', title: 'Still failing', empty: 'No checks remain failing', tone: 'still' },
  ];

  const openComparisonFinding = (item) => {
    const check = item.comparison_key || item.check_id || item.source_key || item.check_name;
    if (!comparison?.current_scan_id || !check) return;
    navigate(`/scan/${comparison.current_scan_id}/report?check=${encodeURIComponent(check)}`);
  };

  return (
    <ReportShell active="History">
      <ReportTopbar />
      <ReportHeader
        eyebrow="Scan operations"
        title="Scan History"
        subtitle="Find reports, inspect fleet scans, and compare remediation progress over time."
        context={[
          { label: 'Reports loaded', value: history.length },
          { label: 'Latest scan', value: latestScan ? formatReportDate(latestScan.scan_date) : 'No data' },
        ]}
        actions={<button type="button" className="reportAction primary" onClick={() => navigate('/scan/new')}>Start Scan</button>}
      />

      <MetricGrid>
        <MetricCard label="Reports" value={history.length} hint="Latest 50 records" tone="info" />
        <MetricCard label="Single host" value={singleCount} hint="Machine-level reports" />
        <MetricCard label="Subnet" value={subnetCount} hint="Fleet reports" tone="info" />
        <MetricCard label="Latest score" value={latestScan ? `${latestScan.score}%` : '-'} hint={latestScan?.hostname || latestScan?.target_name || 'No scans'} tone={latestScan ? scoreTone(latestScan.score) : 'neutral'} />
        <MetricCard label="Visible results" value={filteredHistory.length} hint="After current filters" />
      </MetricGrid>

      {errorMsg && (
        <div className="historyError">
          <span>{errorMsg}</span>
          <button type="button" onClick={() => setErrorMsg('')}>Dismiss</button>
        </div>
      )}

      {comparison && (
        <ReportPanel className="historyComparisonPanel">
          <div className="historyComparisonHead">
            <div>
              <span>Scan comparison</span>
              <h2>Scan #{comparison.base_scan_id} to #{comparison.current_scan_id}</h2>
              <p>
                {comparison.hostname || 'Unknown host'} | {formatReportDate(comparison.base_scan_date)}
                {' to '}
                {formatReportDate(comparison.current_scan_date)}
              </p>
            </div>
            <button type="button" className="historySecondaryButton" onClick={() => setComparison(null)}>Close</button>
          </div>

          <div className="historyCompareMetrics">
            <div>
              <span>Compliance score</span>
              <strong>{comparison.base_score}% <i>to</i> {comparison.score}%</strong>
              <small className={comparison.score_delta >= 0 ? 'positive' : 'negative'}>
                {comparison.score_delta > 0 ? '+' : ''}{comparison.score_delta} points
              </small>
            </div>
            <div><span>Fixed</span><strong>{comparison.counts?.fixed || 0}</strong></div>
            <div><span>New failures</span><strong>{comparison.counts?.newly_failed || 0}</strong></div>
            <div><span>Still failing</span><strong>{comparison.counts?.still_failing || 0}</strong></div>
          </div>

          {!comparison.baseline_compatible && (
            <div className="historyCompareWarning">
              Baselines differ: {comparison.base_version || 'Unknown'} to {comparison.version || 'Unknown'}.
              Added or removed checks may appear as fixed or newly failed.
            </div>
          )}

          <div className="historyComparisonLists">
            {comparisonSections.map((section) => {
              const rows = comparison[section.key] || [];
              return (
                <section className={`historyComparisonList ${section.tone}`} key={section.key}>
                  <header><strong>{section.title}</strong><span>{rows.length}</span></header>
                  {rows.length ? (
                    <div className="historyComparisonBody">
                      {rows.slice(0, 12).map((item, index) => (
                        <button
                          type="button"
                          className="historyComparisonFinding"
                          key={item.check_id || item.source_key || `${section.key}-${index}`}
                          onClick={() => openComparisonFinding(item)}
                        >
                          <div>
                            <strong>{item.check_name || item.check_id || 'Unnamed check'}</strong>
                            <span>{item.category || 'General'} | {item.severity || 'Low'}</span>
                          </div>
                          <code>
                            {section.key === 'fixed'
                              ? (item.base_value || item.current_value || item.expected_value || '-')
                              : (item.current_value || item.expected_value || '-')}
                          </code>
                        </button>
                      ))}
                      {rows.length > 12 && <p>+{rows.length - 12} more checks</p>}
                    </div>
                  ) : <div className="historyComparisonEmpty">{section.empty}</div>}
                </section>
              );
            })}
          </div>
        </ReportPanel>
      )}

      <ReportPanel className="historyConsole">
        <div className="historyToolbar">
          <div>
            <strong>Reports</strong>
            <span>{filteredHistory.length} of {history.length}</span>
          </div>
          <div className="historyFilters">
            <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} aria-label="Filter by scan type">
              <option value="all">All scan types</option>
              <option value="single">Single host</option>
              <option value="subnet">Subnet</option>
            </select>
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search target, baseline, or scan ID"
              aria-label="Search scan history"
            />
            {(search || typeFilter !== 'all') && (
              <button type="button" onClick={() => { setSearch(''); setTypeFilter('all'); }}>Clear</button>
            )}
          </div>
        </div>

        {loading ? (
          <div className="historyState">Loading scan history...</div>
        ) : !history.length ? (
          <div className="historyState">
            <strong>No scan history</strong>
            <span>Start a scan to create the first security report.</span>
            <button type="button" className="historyPrimaryButton" onClick={() => navigate('/scan/new')}>Start Scan</button>
          </div>
        ) : !filteredHistory.length ? (
          <div className="historyState">No reports match the current filters.</div>
        ) : (
          <div className="historyTableWrap">
            <div className="historyDataRow historyDataHead">
              <span>Scan</span>
              <span>Target</span>
              <span>Type</span>
              <span>Baseline</span>
              <span>Score</span>
              <span>Pass</span>
              <span>Fail</span>
              <span>Actions</span>
            </div>
            {filteredHistory.map((scan) => (
              <React.Fragment key={scan.id}>
                <div className="historyDataRow">
                  <div className="historyScanCell">
                    <strong>#{scan.id}</strong>
                    <span>{formatReportDate(scan.scan_date)}</span>
                  </div>
                  <div className="historyTargetCell">
                    <strong>{scan.hostname || scan.target_name || 'Unknown target'}</strong>
                    <span>{scan.target_name || ''}</span>
                  </div>
                  <StatusBadge tone={scan.scan_type === 'subnet' ? 'info' : 'neutral'}>
                    {scan.scan_type === 'subnet' ? 'Subnet' : 'Single'}
                  </StatusBadge>
                  <span className="historyBaseline">{scan.version || 'Unknown baseline'}</span>
                  <StatusBadge tone={scoreTone(scan.score)}>{scan.score}%</StatusBadge>
                  <span className="historyNumber pass">{scan.pass_count || 0}</span>
                  <span className="historyNumber fail">{scan.fail_count || 0}</span>
                  <div className="historyRowActions">
                    {scan.scan_type === 'subnet' ? (
                      <>
                        <button type="button" className="historyPrimaryButton" onClick={() => navigate(`/scan/${scan.id}/subnet`)}>Fleet Report</button>
                        <button type="button" className="historySecondaryButton" onClick={() => loadChildren(scan.id)}>
                          {expandedSubnet === scan.id ? 'Hide Hosts' : 'Hosts'}
                        </button>
                      </>
                    ) : (
                      <>
                        <button type="button" className="historyPrimaryButton" onClick={() => handleView(scan.id)}>View</button>
                        <button type="button" className="historySecondaryButton" onClick={() => beginCompare(scan)}>Compare</button>
                      </>
                    )}
                    <button type="button" className="historyDangerButton" onClick={() => setDeleteScan(scan)}>Delete</button>
                  </div>
                </div>

                {expandedSubnet === scan.id && (
                  <div className="historyChildren">
                    {!subnetChildren[scan.id]?.length && <div className="historyChildEmpty">No child reports found.</div>}
                    {subnetChildren[scan.id]?.map((child) => (
                      <div className="historyChildRow" key={child.id}>
                        <span className="historyChildBranch">Child</span>
                        <div className="historyTargetCell">
                          <strong>{child.hostname || child.target_name || 'Unknown host'}</strong>
                          <span>#{child.id} | {formatReportDate(child.scan_date)}</span>
                        </div>
                        <span className="historyBaseline">{child.version || 'Unknown baseline'}</span>
                        <StatusBadge tone={scoreTone(child.score)}>{child.score}%</StatusBadge>
                        <span className="historyNumber pass">{child.pass_count || 0} pass</span>
                        <span className="historyNumber fail">{child.fail_count || 0} fail</span>
                        <button type="button" className="historyPrimaryButton" onClick={() => handleView(child.id)}>View Report</button>
                      </div>
                    ))}
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        )}
      </ReportPanel>

      {compareScan && (
        <div className="historyModalBackdrop" role="presentation" onMouseDown={() => setCompareScan(null)}>
          <div className="historyModal" role="dialog" aria-modal="true" aria-labelledby="compare-title" onMouseDown={(event) => event.stopPropagation()}>
            <div className="historyModalHead">
              <div>
                <span>Choose previous scan</span>
                <h2 id="compare-title">Compare scan #{compareScan.id}</h2>
                <p>{compareScan.hostname || compareScan.target_name}</p>
              </div>
              <button type="button" onClick={() => setCompareScan(null)} aria-label="Close">×</button>
            </div>
            <div className="historyModalBody">
              <label className="historyCompareField">
                <span>Previous scan</span>
                <select value={compareBaseId} onChange={(event) => setCompareBaseId(event.target.value)}>
                  {compareCandidates.map((item) => (
                    <option value={item.id} key={item.id}>
                      #{item.id} | {formatReportDate(item.scan_date)} | {item.score}% | {item.version || 'Unknown baseline'}
                      {!item.same_baseline ? ' (different baseline)' : ''}
                    </option>
                  ))}
                </select>
              </label>
              {compareCandidateLoading && <div className="historyState">Loading comparison candidates...</div>}
              <div className="historyComparePreview">
                <div>
                  <span>Previous</span>
                  <strong>#{selectedBase?.id || '-'} | {selectedBase?.score ?? 0}%</strong>
                  <small>{selectedBase ? formatReportDate(selectedBase.scan_date) : ''}</small>
                </div>
                <div>
                  <span>Current</span>
                  <strong>#{compareScan.id} | {compareScan.score}%</strong>
                  <small>{formatReportDate(compareScan.scan_date)}</small>
                </div>
              </div>
              {baselineMismatch && (
                <div className="historyCompareWarning">
                  These scans use different baselines. Check additions or removals may affect the comparison.
                </div>
              )}
            </div>
            <div className="historyModalActions">
              <button type="button" className="historySecondaryButton" onClick={() => setCompareScan(null)}>Cancel</button>
              <button type="button" className="historyPrimaryButton" onClick={runComparison} disabled={compareLoading}>
                {compareLoading ? 'Comparing...' : 'Compare Scans'}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteScan && (
        <div className="historyModalBackdrop" role="presentation" onMouseDown={() => !deleting && setDeleteScan(null)}>
          <div className="historyModal historyDeleteModal" role="dialog" aria-modal="true" aria-labelledby="delete-title" onMouseDown={(event) => event.stopPropagation()}>
            <div className="historyModalHead">
              <div>
                <span>Delete report</span>
                <h2 id="delete-title">Delete scan #{deleteScan.id}?</h2>
                <p>{deleteScan.hostname || deleteScan.target_name || 'Unknown target'}</p>
              </div>
            </div>
            <div className="historyModalBody">
              <div className="historyDeleteWarning">
                This removes the selected history record from the application. This action cannot be undone.
              </div>
              <dl>
                <div><dt>Type</dt><dd>{deleteScan.scan_type === 'subnet' ? 'Subnet report' : 'Single-host report'}</dd></div>
                <div><dt>Scanned</dt><dd>{formatReportDate(deleteScan.scan_date)}</dd></div>
                <div><dt>Baseline</dt><dd>{deleteScan.version || 'Unknown baseline'}</dd></div>
              </dl>
            </div>
            <div className="historyModalActions">
              <button type="button" className="historySecondaryButton" onClick={() => setDeleteScan(null)} disabled={Boolean(deleting)}>Cancel</button>
              <button type="button" className="historyDangerButton solid" onClick={confirmDelete} disabled={Boolean(deleting)}>
                {deleting ? 'Deleting...' : 'Delete Report'}
              </button>
            </div>
          </div>
        </div>
      )}
    </ReportShell>
  );
}

export default History;
