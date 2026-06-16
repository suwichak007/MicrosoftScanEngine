/* eslint-disable react-hooks/set-state-in-effect */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import './Result.css';
import { authHeaders, clearAuth, useIsAdmin } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

function Layout({ children, navigate }) {
  const admin = useIsAdmin();

  return (
    <div className="root">
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
            <button className="sideLink" onClick={() => navigate('/home')}><span className="sideLinkDot" />Home</button>
            <button className="sideLink" onClick={() => navigate('/history')}><span className="sideLinkDot" />History</button>
            {admin && (
              <>
                <button className="sideLink" onClick={() => navigate('/admin/agents')}><span className="sideLinkDot" />Agents</button>
                <button className="sideLink" onClick={() => navigate('/admin/users')}><span className="sideLinkDot" />Users</button>
              </>
            )}
          </nav>
        </div>
        <button className="logoutBtn" onClick={() => { clearAuth(); navigate('/login'); }}>
          Log out
        </button>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

function Topbar() {
  return (
    <header className="topbar">
      <p className="topbarDate">
        {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
      </p>
      <div className="topbarActions"><ProfileMenu /></div>
    </header>
  );
}

function normalizeFindingStatus(status, target = '', actual = '', raw = '') {
  const text = String(status || raw || '').toLowerCase();
  if (text.includes('pass')) return 'pass';
  if (text.includes('manual') || text.includes('n/a')) return 'manual';
  if (text.includes('fail')) return 'fail';
  if (target && actual && String(target).trim().toLowerCase() === String(actual).trim().toLowerCase()) return 'pass';
  return 'fail';
}

function parseScanItems(details, findings) {
  if (Array.isArray(findings) && findings.length > 0) {
    return findings
      .map((item) => ({
        key: item.source_key || item.check_id || item.check_name,
        checkId: item.check_id || '',
        name: item.check_name || item.source_key || 'Unknown check',
        section: item.category || 'General',
        severity: String(item.severity || 'Low').toLowerCase(),
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
        checkId: '',
        name: key.replace(/^\[[^\]]+\]\s*/, ''),
        section: sectionMatch ? sectionMatch[1] : 'General',
        severity: 'low',
        target,
        actual,
        status: normalizeFindingStatus(raw, target, actual, raw),
      };
    });
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
    setLoading(true);
    setErrorMsg('');
    fetch(apiUrl(`/api/scan/history/${id}`), {
      headers: authHeaders(),
    })
      .then((res) => {
        if (res.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!res.ok) return res.json().then((e) => Promise.reject(e.detail || 'Subnet report not found'));
        return res.json();
      })
      .then((data) => {
        const details = data.details || {};
        const results = Array.isArray(details.results) ? details.results : [];
        setScanData({
          id: data.id,
          subnet: details.subnet || data.hostname || data.target_name,
          targetName: data.target_name,
          version: data.version || '',
          score: data.score || 0,
          score_breakdown: data.score_breakdown || null,
          method: details.method || 'subnet',
          results,
          success_count: results.filter((r) => r.status === 'done').length,
          failed_count: results.filter((r) => r.status === 'error').length,
        });
        return fetch(apiUrl(`/api/scan/history/${id}/children`), {
          headers: authHeaders(),
        });
      })
      .then((res) => {
        if (!res) return [];
        if (res.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!res.ok) return [];
        return res.json();
      })
      .then((rows) => {
        setChildren(Array.isArray(rows) ? rows : []);
      })
      .catch((err) => setErrorMsg(typeof err === 'string' ? err : 'Unable to load subnet result'))
      .finally(() => setLoading(false));
  }, [id, navigate]);

  const scoreColor = (score) => {
    if (score >= 70) return 'var(--green)';
    if (score >= 40) return 'var(--amber)';
    return 'var(--red)';
  };

  const overview = useMemo(() => {
    const hostRows = children.map((child) => {
      const items = parseScanItems(child.details, child.findings);
      const fails = items.filter((item) => item.status === 'fail');
      const passes = items.filter((item) => item.status === 'pass');
      return {
        ...child,
        scanItems: items,
        failItems: fails,
        passItems: passes,
        failCount: Number.isFinite(child.fail_count) && child.fail_count > 0 ? child.fail_count : fails.length,
        passCount: Number.isFinite(child.pass_count) && child.pass_count > 0 ? child.pass_count : passes.length,
      };
    });
    const completedHosts = hostRows.filter((host) => (host.scanItems || []).length > 0);
    const worstHosts = [...hostRows]
      .sort((a, b) => (b.failCount - a.failCount) || ((a.score || 0) - (b.score || 0)))
      .slice(0, 5);
    const failedPolicyMap = new Map();
    const passedPolicyMap = new Map();
    const categoryMap = new Map();
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

    const upsertPolicy = (map, item, hostName) => {
      const key = item.checkId || item.key || item.name;
      if (!map.has(key)) {
        map.set(key, {
          key,
          name: item.name,
          section: item.section,
          severity: item.severity,
          hosts: new Set(),
        });
      }
      map.get(key).hosts.add(hostName);
    };

    hostRows.forEach((host) => {
      const hostName = host.hostname || host.host || host.target_name || 'Unknown host';
      host.failItems.forEach((item) => {
        upsertPolicy(failedPolicyMap, item, hostName);
        const section = item.section || 'General';
        categoryMap.set(section, (categoryMap.get(section) || 0) + 1);
        const sev = ['critical', 'high', 'medium', 'low'].includes(item.severity) ? item.severity : 'low';
        severityCounts[sev] += 1;
      });
      host.passItems.forEach((item) => upsertPolicy(passedPolicyMap, item, hostName));
    });
    const repeatedPolicies = Array.from(failedPolicyMap.values())
      .map((item) => ({ ...item, hosts: Array.from(item.hosts) }))
      .filter((item) => item.hosts.length > 1)
      .sort((a, b) => b.hosts.length - a.hosts.length);
    const commonFails = repeatedPolicies
      .slice(0, 8);
    const passedEverywhere = Array.from(passedPolicyMap.values())
      .map((item) => ({ ...item, hosts: Array.from(item.hosts) }))
      .filter((item) => completedHosts.length > 0 && item.hosts.length === completedHosts.length)
      .sort((a, b) => a.section.localeCompare(b.section) || a.name.localeCompare(b.name));
    const commonPasses = passedEverywhere.slice(0, 8);
    const categoryBreakdown = Array.from(categoryMap.entries())
      .map(([section, count]) => ({ section, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
    const maxCategoryCount = Math.max(1, ...categoryBreakdown.map((item) => item.count));
    const totalFails = hostRows.reduce((sum, host) => sum + host.failCount, 0);
    const totalPasses = hostRows.reduce((sum, host) => sum + host.passCount, 0);
    const cleanHosts = hostRows.filter((host) => host.failCount === 0).length;
    return {
      hostRows,
      completedHostCount: completedHosts.length,
      worstHosts,
      repeatedPolicies,
      commonFails,
      passedEverywhere,
      commonPasses,
      passedEverywhereCount: passedEverywhere.length,
      repeatedPolicyCount: repeatedPolicies.length,
      categoryBreakdown,
      maxCategoryCount,
      severityCounts,
      totalFails,
      totalPasses,
      cleanHosts,
    };
  }, [children]);

  const openPolicyModal = (type) => {
    if (type === 'fail') {
      setDetailModal({
        title: 'All Repeated Failed Policies',
        subtitle: `${overview.repeatedPolicyCount} policies failed on multiple hosts`,
        badgeClass: 'fail',
        rows: overview.repeatedPolicies,
        empty: 'No repeated failed policies found',
      });
      return;
    }
    setDetailModal({
      title: 'All Checks Passed On Every Host',
      subtitle: `${overview.passedEverywhereCount} checks passed on ${overview.completedHostCount} scanned hosts`,
      badgeClass: 'pass',
      rows: overview.passedEverywhere,
      empty: 'No checks passed on every scanned host yet',
    });
  };

  return (
    <Layout navigate={navigate}>
      <Topbar />
      <div className="pageHead">
        <h1 className="pageTitle">Subnet Scan Result</h1>
        <p className="pageDesc">{scanData?.subnet || 'Subnet'}  {scanData?.version || ''}</p>
      </div>

      {loading && <div className="emptyMsg">Loading...</div>}
      {errorMsg && <div className="errBanner">{errorMsg}</div>}

      {!loading && scanData && (
        <>
          <div className="scoreSummary" style={{ marginBottom: 24 }}>
            <div className="scoreCircleWrap">
              <div className="scoreText" style={{ color: scoreColor(scanData.score) }}>{scanData.score}%</div>
            </div>
            <div className="scoreDetail">
              <div className="scoreLabel">{scanData.subnet}</div>
              <div className="scoreVersion">{scanData.version}</div>
              <div className="scoreVersion">NIST/CIS-informed fleet compliance score</div>
              {scanData.score_breakdown && (
                <div className="scoreVersion">
                  Assessed weight {scanData.score_breakdown.passed_weight}/{scanData.score_breakdown.assessed_weight}
                  {scanData.score_breakdown.excluded_manual_count ? ` · ${scanData.score_breakdown.excluded_manual_count} manual excluded` : ''}
                </div>
              )}
              <div className="scoreCounts" style={{ marginTop: 8 }}>
                <span className="countBadge pass"> {scanData.success_count} successful</span>
                <span className="countBadge fail"> {scanData.failed_count} failed</span>
              </div>
            </div>
          </div>

          <div className="subnetOverviewGrid">
            <div className="subnetMetricCard danger">
              <div className="subnetMetricVisual">
                <span>{overview.severityCounts.critical + overview.severityCounts.high}</span>
              </div>
              <span className="subnetMetricValue">{overview.totalFails}</span>
              <span className="subnetMetricLabel">Total failed checks</span>
              <div className="subnetMetricFoot">Critical + High: {overview.severityCounts.critical + overview.severityCounts.high}</div>
            </div>
            <div className="subnetMetricCard warning">
              <div className="subnetMetricBar">
                <i style={{ width: `${Math.min(100, overview.completedHostCount ? (overview.repeatedPolicyCount / Math.max(overview.totalFails, 1)) * 100 : 0)}%` }} />
              </div>
              <span className="subnetMetricValue">{overview.repeatedPolicyCount}</span>
              <span className="subnetMetricLabel">Failed on multiple hosts</span>
              <button className="subnetInlineBtn" onClick={() => openPolicyModal('fail')} disabled={overview.repeatedPolicyCount === 0}>
                View all
              </button>
            </div>
            <div className="subnetMetricCard success">
              <div className="subnetMetricBar good">
                <i style={{ width: `${Math.min(100, overview.totalPasses ? (overview.passedEverywhereCount / Math.max(overview.totalPasses, 1)) * 100 : 0)}%` }} />
              </div>
              <span className="subnetMetricValue">{overview.passedEverywhereCount}</span>
              <span className="subnetMetricLabel">Passed on every scanned host</span>
              <button className="subnetInlineBtn" onClick={() => openPolicyModal('pass')} disabled={overview.passedEverywhereCount === 0}>
                View all
              </button>
            </div>
            <div className="subnetMetricCard neutral">
              <div className="subnetHostDots" aria-hidden="true">
                {overview.hostRows.slice(0, 16).map((host) => (
                  <span key={host.scan_id || host.id || host.hostname} className={host.failCount === 0 ? 'clean' : 'dirty'} />
                ))}
              </div>
              <span className="subnetMetricValue">{overview.cleanHosts}</span>
              <span className="subnetMetricLabel">Hosts with no failed checks</span>
              <div className="subnetMetricFoot">Scanned hosts: {overview.completedHostCount}</div>
            </div>
          </div>

          <div className="subnetSeverityStrip">
            <span>Critical: {overview.severityCounts.critical}</span>
            <span>High: {overview.severityCounts.high}</span>
            <span>Medium: {overview.severityCounts.medium}</span>
            <span>Low: {overview.severityCounts.low}</span>
            <span>Pass total: {overview.totalPasses}</span>
          </div>

          <div className="subnetInsightGrid">
            <section className="resultCard subnetInsightCard">
              <div className="subnetInsightHead">
                <h2>Hosts With Most Failures</h2>
                <span>{overview.worstHosts.length} hosts</span>
              </div>
              <div className="subnetInsightList">
                {overview.worstHosts.length === 0 && <div className="emptyMsg">No completed child scan details yet</div>}
                {overview.worstHosts.map((host) => (
                  <div className="subnetInsightRow" key={host.scan_id || host.id}>
                    <div>
                      <div className="itemName">{host.hostname || host.host || host.target_name}</div>
                      <div className="sectionTag">{host.version || scanData.version}</div>
                    </div>
                    <div className="subnetInsightScore">
                      <span style={{ color: scoreColor(host.score || 0) }}>{host.score || 0}%</span>
                      <strong>{host.failCount} fail</strong>
                    </div>
                    {host.scan_id && (
                      <button className="connBtn smallBtn" onClick={() => navigate(`/scan/${host.scan_id}/report`)}>
                        View
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </section>

            <section className="resultCard subnetInsightCard">
              <div className="subnetInsightHead">
                <h2>Most Common Failed Policies</h2>
                <div className="subnetHeadActions">
                  <span>
                    {overview.repeatedPolicyCount > overview.commonFails.length
                      ? `Top ${overview.commonFails.length} of ${overview.repeatedPolicyCount}`
                      : `${overview.repeatedPolicyCount} policies`}
                  </span>
                  <button className="subnetInlineBtn compact" onClick={() => openPolicyModal('fail')} disabled={overview.repeatedPolicyCount === 0}>
                    View all
                  </button>
                </div>
              </div>
              <div className="subnetInsightList">
                {overview.commonFails.length === 0 && <div className="emptyMsg">No repeated failed policies found</div>}
                {overview.commonFails.map((item) => (
                  <div className="subnetPolicyRow" key={item.key}>
                    <div>
                      <div className="itemName">{item.name}</div>
                      <div className="sectionTag">{item.section}</div>
                    </div>
                    <span className="countBadge fail">{item.hosts.length} hosts</span>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <div className="subnetInsightGrid">
            <section className="resultCard subnetInsightCard">
              <div className="subnetInsightHead">
                <h2>Failed Category Breakdown</h2>
                <span>{overview.categoryBreakdown.length} categories</span>
              </div>
              <div className="subnetCategoryList">
                {overview.categoryBreakdown.length === 0 && <div className="emptyMsg">No failed categories found</div>}
                {overview.categoryBreakdown.map((item) => (
                  <div className="subnetCategoryRow" key={item.section}>
                    <div className="subnetCategoryTop">
                      <strong>{item.section}</strong>
                      <span>{item.count} failed checks</span>
                    </div>
                    <div className="subnetCategoryTrack">
                      <div
                        className="subnetCategoryFill"
                        style={{ width: `${Math.max(5, (item.count / overview.maxCategoryCount) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="resultCard subnetInsightCard">
              <div className="subnetInsightHead">
                <h2>Passed On Every Host</h2>
                <div className="subnetHeadActions">
                  <span>
                    {overview.passedEverywhereCount > overview.commonPasses.length
                      ? `Top ${overview.commonPasses.length} of ${overview.passedEverywhereCount}`
                      : `${overview.passedEverywhereCount} checks`}
                  </span>
                  <button className="subnetInlineBtn compact" onClick={() => openPolicyModal('pass')} disabled={overview.passedEverywhereCount === 0}>
                    View all
                  </button>
                </div>
              </div>
              <div className="subnetInsightList">
                {overview.commonPasses.length === 0 && <div className="emptyMsg">No checks passed on every scanned host yet</div>}
                {overview.commonPasses.map((item) => (
                  <div className="subnetPolicyRow" key={item.key}>
                    <div>
                      <div className="itemName">{item.name}</div>
                      <div className="sectionTag">{item.section}</div>
                    </div>
                    <span className="countBadge pass">{item.hosts.length} hosts</span>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <div className="resultCard">
            <div className="colHeaders" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
              <div>Host</div>
              <div>Score</div>
              <div>Status</div>
              <div>Detail</div>
            </div>
            <div className="itemList">
              {scanData.results.length === 0 && <div className="emptyMsg">No subnet result items found</div>}
              {scanData.results.map((r, index) => (
                <div key={`${r.host || r.agent_id || index}`} className="resultRow">
                  <div className="rowSummary" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
                    <div>
                      <div className="itemName">{r.hostname || r.host || r.agent_id || 'Unknown host'}</div>
                      <div className="sectionTag">
                        {r.agent_id || r.host || ''}
                        {Array.isArray(r.ip_addresses) && r.ip_addresses.length > 0 ? ` ? ${r.ip_addresses.join(', ')}` : ''}
                      </div>
                    </div>
                    <div>
                      <span style={{
                        fontFamily: 'DM Mono, monospace',
                        fontSize: 14,
                        fontWeight: 500,
                        color: scoreColor(r.score || 0),
                      }}>
                        {r.status === 'done' ? `${r.score || 0}%` : '-'}
                      </span>
                    </div>
                    <div>
                      <span className={`badge ${r.status === 'done' ? 'on' : 'off'}`}>
                        {r.status === 'done' ? 'Done' : 'Error'}
                      </span>
                      {r.error && <div className="sectionTag" style={{ color: 'var(--red)', marginTop: 4 }}>{r.error}</div>}
                    </div>
                    <div>
                      {r.scan_id && (
                        <button
                          className="connBtn"
                          style={{ padding: '4px 12px', fontSize: 12 }}
                          onClick={() => navigate(`/scan/${r.scan_id}/report`)}
                        >
                          View 
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="resultFooter">
              <button className="statButton" onClick={() => navigate('/history')}>History</button>
              <button className="finishButton" onClick={() => navigate('/home')}>Finish</button>
            </div>
          </div>
        </>
      )}
      {detailModal && (
        <div className="subnetModalBackdrop" role="presentation" onClick={() => setDetailModal(null)}>
          <div className="subnetModal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <div className="subnetModalHead">
              <div>
                <h2>{detailModal.title}</h2>
                <p>{detailModal.subtitle}</p>
              </div>
              <button className="subnetModalClose" onClick={() => setDetailModal(null)}>Close</button>
            </div>
            <div className="subnetModalList">
              {detailModal.rows.length === 0 && <div className="emptyMsg">{detailModal.empty}</div>}
              {detailModal.rows.map((item) => (
                <div className="subnetModalRow" key={item.key}>
                  <div>
                    <div className="itemName">{item.name}</div>
                    <div className="sectionTag">{item.section}</div>
                  </div>
                  <span className={`countBadge ${detailModal.badgeClass}`}>{item.hosts.length} hosts</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}


