import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './History.css';
import { clearAuth, useIsAdmin } from '../auth';
import { apiUrl } from '../config/api';
import ProfileMenu from './ProfileMenu';

function History() {
  const navigate = useNavigate();
  const admin = useIsAdmin();

  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [deleting, setDeleting] = useState(null);
  const [expandedSubnet, setExpandedSubnet] = useState(null);
  const [subnetChildren, setSubnetChildren] = useState({});
  const [comparison, setComparison] = useState(null);

  const getToken    = () => localStorage.getItem('token') || '';
  const authHeader  = () => ({
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${getToken()}`,
  });

  useEffect(() => { fetchHistory(); }, []);

  const fetchHistory = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl('/api/scan/history?limit=50'), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (res.ok && Array.isArray(data)) {
        setHistory(data);
      } else {
        setErrorMsg('Unable to load history');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const loadChildren = async (scanId) => {
    if (subnetChildren[scanId]) {
      setExpandedSubnet(expandedSubnet === scanId ? null : scanId);
      return;
    }
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${scanId}/children`), {
        headers: authHeader(),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      setSubnetChildren(prev => ({ ...prev, [scanId]: data }));
      setExpandedSubnet(scanId);
    } catch (err) {
      setErrorMsg(`Unable to load child scans: ${err.message}`);
    }
  };

  const handleView = async (id) => {
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${id}`), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (res.ok) {
        navigate(`/scan/${id}/report`, {
          state: {
            fromHistory: {
              score:      data.score,
              details:    data.details,
              findings:   data.findings || [],
              summary:    data.summary || null,
              targetName: data.target_name,
              hostname:   data.hostname || '',
              version:    data.version  || '',
              scan_id:    data.id,
            },
          },
        });
      } else {
        setErrorMsg(data.detail || 'Unable to load report details');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this history item?')) return;
    setDeleting(id);
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${id}`), {
        method: 'DELETE',
        headers: authHeader(),
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      if (res.ok) {
        setHistory((prev) => prev.filter((h) => h.id !== id));
      } else {
        const data = await res.json();
        setErrorMsg(data.detail || 'Unable to delete history item');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setDeleting(null);
    }
  };

  const handleCompare = async (scan) => {
    const host = (scan.hostname || scan.target_name || '').toLowerCase();
    const currentTime = new Date(scan.scan_date).getTime();
    const base = history
      .filter((item) => item.id !== scan.id && item.scan_type !== 'subnet')
      .filter((item) => (item.hostname || item.target_name || '').toLowerCase() === host)
      .filter((item) => new Date(item.scan_date).getTime() < currentTime)
      .sort((a, b) => new Date(b.scan_date) - new Date(a.scan_date))[0];
    if (!base) {
      setErrorMsg('No earlier scan for the same host is available for comparison');
      return;
    }
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${scan.id}/compare/${base.id}`), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || 'Compare failed');
        return;
      }
      setComparison(data);
    } catch (err) {
      setErrorMsg(`Compare failed: ${err.message}`);
    }
  };

  const formatDate = (isoStr) => {
    const d = new Date(isoStr);
    return (
      d.toLocaleDateString('th-TH', { day: '2-digit', month: '2-digit', year: 'numeric' }) +
      ' ' +
      d.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' })
    );
  };

  const scoreColor = (score) => {
    if (score >= 70) return 'var(--green)';
    if (score >= 40) return 'var(--amber)';
    return 'var(--red)';
  };

  return (
    <div className="root">
      {/*  Sidebar  */}
      <aside className="sidebar">
        <div className="sideTop">
          <div className="logo">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="5"  stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="1.5" fill="#c8813a" />
            </svg>
            <span className="logoText">SecureScan</span>
          </div>
          <nav className="sideNav">
            <button className="sideLink" onClick={() => navigate('/home')}>
              <span className="sideLinkDot" />Home
            </button>
            <button className="sideLink active">
              <span className="sideLinkDot" />History
            </button>
            {admin && (
              <>
                <button className="sideLink" onClick={() => navigate('/admin/agents')}>
                  <span className="sideLinkDot" />Agents
                </button>
                <button className="sideLink" onClick={() => navigate('/admin/users')}>
                  <span className="sideLinkDot" />Users
                </button>
              </>
            )}
          </nav>
        </div>
        <button className="logoutBtn" onClick={() => { clearAuth(); navigate('/login'); }}>
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M5 2H2v10h3M9 10l3-3-3-3M12 7H5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Log out
        </button>
      </aside>

      {/*  Main  */}
      <main className="main">
        {/* Topbar */}
        <header className="topbar">
          <p className="topbarDate">
            {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </p>
          <div className="topbarActions">
            <ProfileMenu />
          </div>
        </header>

        {/* Page head */}
        <div className="pageHead">
          <h1 className="pageTitle">History</h1>
          <p className="pageDesc">Security scan history and reports</p>
        </div>

        {/* Error */}
        {errorMsg && (
          <div className="errBanner">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6" /><path d="M7 4v3M7 10h.01" strokeLinecap="round" />
            </svg>
            {errorMsg}
          </div>
        )}

        {comparison && (
          <div className="historyCard" style={{ marginBottom: 16, padding: 16 }}>
            <div className="historyActions" style={{ justifyContent: 'space-between' }}>
              <strong>Comparison: scan #{comparison.base_scan_id}  #{comparison.current_scan_id}</strong>
              <button className="deleteBtn" onClick={() => setComparison(null)}>Close</button>
            </div>
            <div className="historyCompareGrid">
              <div><span>Score delta</span><strong>{comparison.score_delta > 0 ? '+' : ''}{comparison.score_delta}%</strong></div>
              <div><span>Fixed</span><strong>{comparison.counts?.fixed || 0}</strong></div>
              <div><span>New fail</span><strong>{comparison.counts?.newly_failed || 0}</strong></div>
              <div><span>Still failing</span><strong>{comparison.counts?.still_failing || 0}</strong></div>
            </div>
          </div>
        )}

        {/* Card */}
        <div className="historyCard">
          {loading ? (
            <div className="historyEmpty">
              <span className="spin" /> Loading...
            </div>
          ) : history.length === 0 ? (
            <div className="historyEmpty">No scan history found</div>
          ) : (
            <table className="historyTable">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Target</th>
                  <th>Version</th>
                  <th className="center">Score</th>
                  <th className="center">Pass</th>
                  <th className="center">Fail</th>
                  <th className="center">Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <React.Fragment key={h.id}>
                    <tr>
                      <td className="monoCell">{formatDate(h.scan_date)}</td>
                      <td className="targetCell">
                        {h.scan_type === 'subnet' && (
                          <span style={{
                            fontSize: 10, background: 'var(--amber-pale)',
                            color: 'var(--amber)', border: '1px solid var(--amber)',
                            borderRadius: 4, padding: '1px 6px', marginRight: 6,
                          }}>
                            SUBNET
                          </span>
                        )}
                        {h.target_name}
                      </td>
                      <td className="monoCell">{h.version || ''}</td>
                      <td className="scoreCell" style={{ color: scoreColor(h.score) }}>{h.score}%</td>
                      <td className="passCell"> {h.pass_count}</td>
                      <td className="failCell"> {h.fail_count}</td>
                      <td>
                        <div className="historyActions">
                          {h.scan_type === 'subnet' ? (
                            <>
                              <button className="viewBtn" onClick={() => navigate(`/scan/${h.id}/subnet`)}>View</button>
                              <button className="viewBtn" onClick={() => loadChildren(h.id)}>
                                {expandedSubnet === h.id ? 'Hide' : 'Children'}
                              </button>
                            </>
                          ) : (
                            <>
                              <button className="viewBtn" onClick={() => handleView(h.id)}>View</button>
                              <button className="viewBtn" onClick={() => handleCompare(h)}>Compare</button>
                            </>
                          )}
                          <button
                            className="deleteBtn"
                            onClick={() => handleDelete(h.id)}
                            disabled={deleting === h.id}
                          >
                            {deleting === h.id ? '' : 'Delete'}
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/*  Children rows  */}
                    {expandedSubnet === h.id && subnetChildren[h.id]?.map((child) => (
                      <tr key={child.id} style={{ background: 'var(--cream-dark)' }}>
                        <td className="monoCell" style={{ paddingLeft: 32 }}>
                          {formatDate(child.scan_date)}
                        </td>
                        <td className="targetCell" style={{ paddingLeft: 32 }}>
                           {child.hostname || child.target_name}
                        </td>
                        <td className="monoCell">{child.version || ''}</td>
                        <td className="scoreCell" style={{ color: scoreColor(child.score) }}>
                          {child.score}%
                        </td>
                        <td className="passCell"> {child.pass_count}</td>
                        <td className="failCell"> {child.fail_count}</td>
                        <td>
                          <div className="historyActions">
                            <button className="viewBtn" onClick={() => handleView(child.id)}>View</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          )}

          <div className="historyFooter">
            <button className="backBtn"   onClick={() => navigate(-1)}> Back</button>
            <button className="finishBtn" onClick={() => navigate('/home')}>Finish</button>
          </div>
        </div>
      </main>
    </div>
  );
}

export default History;


