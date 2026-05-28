import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './History.css';
import { clearAuth } from '../auth';
import { apiUrl } from '../config/api';

function History() {
  const navigate = useNavigate();

  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [deleting, setDeleting] = useState(null);
  const [expandedSubnet, setExpandedSubnet] = useState(null);
  const [subnetChildren, setSubnetChildren] = useState({});

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
        setErrorMsg('โหลดประวัติไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
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
        headers: authHeader(),  // ← แก้จาก authHeaders() เป็น authHeader()
      });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      const data = await res.json();
      setSubnetChildren(prev => ({ ...prev, [scanId]: data }));
      setExpandedSubnet(scanId);
    } catch (err) {
      setErrorMsg(`โหลด children ไม่สำเร็จ: ${err.message}`);
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
              scan_id:    data.id,        // ← เพิ่ม
            },
          },
        });
      } else {
        setErrorMsg(data.detail || 'โหลดรายละเอียดไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('ต้องการลบประวัตินี้?')) return;
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
        setErrorMsg(data.detail || 'ลบไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setDeleting(null);
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
      {/* ── Sidebar ── */}
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
            <button className="sideLink" onClick={() => navigate('/guide')}>
              <span className="sideLinkDot" />Guide
            </button>
            {localStorage.getItem('role') === 'admin' && (
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

      {/* ── Main ── */}
      <main className="main">
        {/* Topbar */}
        <header className="topbar">
          <p className="topbarDate">
            {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
          </p>
          <div className="topbarActions">
            <button className="notifBtn">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M8 1a5 5 0 0 1 5 5v3l1 2H2l1-2V6a5 5 0 0 1 5-5zM6.5 13a1.5 1.5 0 0 0 3 0" strokeLinecap="round" />
              </svg>
              <span className="notifDot" />
            </button>
            <div className="avatar">จ</div>
          </div>
        </header>

        {/* Page head */}
        <div className="pageHead">
          <h1 className="pageTitle">History</h1>
          <p className="pageDesc">ประวัติการสแกนความปลอดภัยของระบบ</p>
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

        {/* Card */}
        <div className="historyCard">
          {loading ? (
            <div className="historyEmpty">
              <span className="spin" />กำลังโหลด...
            </div>
          ) : history.length === 0 ? (
            <div className="historyEmpty">ยังไม่มีประวัติการสแกน</div>
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
                      <td className="monoCell">{h.version || '—'}</td>
                      <td className="scoreCell" style={{ color: scoreColor(h.score) }}>{h.score}%</td>
                      <td className="passCell">✔ {h.pass_count}</td>
                      <td className="failCell">✖ {h.fail_count}</td>
                      <td>
                        <div className="historyActions">
                          {h.scan_type === 'subnet' ? (
                            <>
                              <button className="viewBtn" onClick={() => navigate(`/scan/${h.id}/subnet`)}>View</button>
                              <button className="viewBtn" onClick={() => loadChildren(h.id)}>
                                {expandedSubnet === h.id ? '▲ ซ่อน' : '▼ รายเครื่อง'}
                              </button>
                            </>
                          ) : (
                            <button className="viewBtn" onClick={() => handleView(h.id)}>View</button>
                          )}
                          <button
                            className="deleteBtn"
                            onClick={() => handleDelete(h.id)}
                            disabled={deleting === h.id}
                          >
                            {deleting === h.id ? '…' : 'Delete'}
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* ── Children rows ── */}
                    {expandedSubnet === h.id && subnetChildren[h.id]?.map((child) => (
                      <tr key={child.id} style={{ background: 'var(--cream-dark)' }}>
                        <td className="monoCell" style={{ paddingLeft: 32 }}>
                          {formatDate(child.scan_date)}
                        </td>
                        <td className="targetCell" style={{ paddingLeft: 32 }}>
                          ↳ {child.hostname || child.target_name}
                        </td>
                        <td className="monoCell">{child.version || '—'}</td>
                        <td className="scoreCell" style={{ color: scoreColor(child.score) }}>
                          {child.score}%
                        </td>
                        <td className="passCell">✔ {child.pass_count}</td>
                        <td className="failCell">✖ {child.fail_count}</td>
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
            <button className="backBtn"   onClick={() => navigate(-1)}>← Back</button>
            <button className="finishBtn" onClick={() => navigate('/home')}>Finish</button>
          </div>
        </div>
      </main>
    </div>
  );
}

export default History;
