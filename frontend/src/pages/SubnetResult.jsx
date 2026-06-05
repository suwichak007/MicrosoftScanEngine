/* eslint-disable react-hooks/set-state-in-effect */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import './Result.css';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

function Layout({ children, navigate }) {
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
            {localStorage.getItem('role') === 'admin' && (
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

function parseFailItems(details, findings) {
  if (Array.isArray(findings) && findings.length > 0) {
    return findings
      .filter((item) => String(item.status || '').toLowerCase() === 'fail')
      .map((item) => ({
        key: item.source_key || item.check_id || item.check_name,
        name: item.check_name || item.source_key || 'Unknown check',
        section: item.category || 'General',
        severity: String(item.severity || 'Low').toLowerCase(),
        target: item.expected_value || '',
        actual: item.current_value || '',
      }));
  }

  return Object.entries(details || {})
    .filter(([, value]) => {
      const status = typeof value === 'object' && value !== null ? value.status : value;
      return String(status || '').startsWith('Fail');
    })
    .map(([key, value]) => {
      const raw = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value || '');
      const sectionMatch = key.match(/^\[([^\]]+)\]/);
      const target = (raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/) || [])[1]?.trim() || '';
      const actual = (raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/) || [])[1]?.trim().replace(/\)\s*$/, '') || '';
      return {
        key,
        name: key.replace(/^\[[^\]]+\]\s*/, ''),
        section: sectionMatch ? sectionMatch[1] : 'General',
        severity: 'low',
        target,
        actual,
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
      .catch((err) => setErrorMsg(typeof err === 'string' ? err : 'ไม่สามารถโหลด Subnet Result ได้'))
      .finally(() => setLoading(false));
  }, [id, navigate]);

  const scoreColor = (score) => {
    if (score >= 70) return 'var(--green)';
    if (score >= 40) return 'var(--amber)';
    return 'var(--red)';
  };

  const overview = useMemo(() => {
    const hostRows = children.map((child) => {
      const fails = parseFailItems(child.details, child.findings);
      return {
        ...child,
        failItems: fails,
        failCount: child.fail_count ?? fails.length,
        passCount: child.pass_count ?? 0,
      };
    });
    const worstHosts = [...hostRows]
      .sort((a, b) => (b.failCount - a.failCount) || ((a.score || 0) - (b.score || 0)))
      .slice(0, 5);
    const policyMap = new Map();
    hostRows.forEach((host) => {
      host.failItems.forEach((item) => {
        const key = item.key || item.name;
        if (!policyMap.has(key)) {
          policyMap.set(key, {
            key,
            name: item.name,
            section: item.section,
            severity: item.severity,
            hosts: [],
          });
        }
        policyMap.get(key).hosts.push(host.hostname || host.host || host.target_name || 'Unknown host');
      });
    });
    const commonFails = Array.from(policyMap.values())
      .sort((a, b) => b.hosts.length - a.hosts.length)
      .slice(0, 8);
    const totalFails = hostRows.reduce((sum, host) => sum + host.failCount, 0);
    const cleanHosts = hostRows.filter((host) => host.failCount === 0).length;
    return { hostRows, worstHosts, commonFails, totalFails, cleanHosts };
  }, [children]);

  return (
    <Layout navigate={navigate}>
      <Topbar />
      <div className="pageHead">
        <h1 className="pageTitle">Subnet Scan Result</h1>
        <p className="pageDesc">{scanData?.subnet || 'Subnet'} — {scanData?.version || ''}</p>
      </div>

      {loading && <div className="emptyMsg">กำลังโหลด...</div>}
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
              <div className="scoreCounts" style={{ marginTop: 8 }}>
                <span className="countBadge pass">✔ {scanData.success_count} สำเร็จ</span>
                <span className="countBadge fail">✖ {scanData.failed_count} ล้มเหลว</span>
              </div>
            </div>
          </div>

          <div className="subnetOverviewGrid">
            <div className="subnetMetricCard">
              <span className="subnetMetricValue">{overview.totalFails}</span>
              <span className="subnetMetricLabel">Total failed checks</span>
            </div>
            <div className="subnetMetricCard">
              <span className="subnetMetricValue">{overview.commonFails.length}</span>
              <span className="subnetMetricLabel">Repeated failed policies</span>
            </div>
            <div className="subnetMetricCard">
              <span className="subnetMetricValue">{overview.cleanHosts}</span>
              <span className="subnetMetricLabel">Hosts with no failed checks</span>
            </div>
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
                <span>{overview.commonFails.length} policies</span>
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

          <div className="resultCard">
            <div className="colHeaders" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
              <div>Host</div>
              <div>Score</div>
              <div>Status</div>
              <div>Detail</div>
            </div>
            <div className="itemList">
              {scanData.results.length === 0 && <div className="emptyMsg">ไม่พบรายการเครื่องใน subnet นี้</div>}
              {scanData.results.map((r, index) => (
                <div key={`${r.host || r.agent_id || index}`} className="resultRow">
                  <div className="rowSummary" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
                    <div>
                      <div className="itemName">{r.hostname || r.host || r.agent_id || 'Unknown host'}</div>
                      <div className="sectionTag">
                        {r.agent_id || r.host || ''}
                        {Array.isArray(r.ip_addresses) && r.ip_addresses.length > 0 ? ` · ${r.ip_addresses.join(', ')}` : ''}
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
                          View →
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
    </Layout>
  );
}
