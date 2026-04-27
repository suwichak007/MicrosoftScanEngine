import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './History.css';

const API_BASE = `http://${window.location.hostname}:8000`;

function History() {
  const navigate = useNavigate();

  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [deleting, setDeleting] = useState(null);

  // ── ดึง token จาก localStorage ──
  const getToken = () => localStorage.getItem('token') || '';

  // ── auth header ──
  const authHeader = () => ({
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${getToken()}`,
  });

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res  = await fetch(`${API_BASE}/api/scan/history?limit=50`, {
        headers: authHeader(),
      });

      // token หมดอายุหรือไม่มีสิทธิ์ → ไปหน้า login
      if (res.status === 401) {
        localStorage.removeItem('token');
        navigate('/');
        return;
      }

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

  const handleView = async (id) => {
    try {
      const res  = await fetch(`${API_BASE}/api/scan/history/${id}`, {
        headers: authHeader(),
      });

      if (res.status === 401) {
        localStorage.removeItem('token');
        navigate('/');
        return;
      }

      const data = await res.json();
      if (res.ok) {
        navigate('/result', {
          state: {
            fromHistory: {
              score:      data.score,
              details:    data.details,
              targetName: data.target_name,
              hostname:   data.hostname || '',
              version:    data.version  || '',
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
      const res = await fetch(`${API_BASE}/api/scan/history/${id}`, {
        method:  'DELETE',
        headers: authHeader(),
      });

      if (res.status === 401) {
        localStorage.removeItem('token');
        navigate('/');
        return;
      }

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
    return d.toLocaleDateString('th-TH', {
      day:   '2-digit',
      month: '2-digit',
      year:  'numeric',
    }) + ' ' + d.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' });
  };

  const scoreColor = (score) => {
    if (score >= 70) return '#20d320';
    if (score >= 40) return '#f5d000';
    return '#ff4d4d';
  };

  return (
    <div className="historyPage">
      <header className="topBar">
        <div className="brand">Scanner</div>
        <div className="topBarRight">
          <div className="bellWrapper">
            <span className="bellIcon">🔔</span>
            <span className="notificationDot"></span>
          </div>
          <div className="profileCircle">👤</div>
        </div>
      </header>

      <div className="homeLayout">
        <aside className="sideBar">
          <div className="menuGroup">
            <button className="menuItem" onClick={() => navigate('/home')}>Home</button>
            <button className="menuItem active">History</button>
            <button className="menuItem" onClick={() => navigate('/guide')}>Guide</button>
          </div>
          <button className="logoutButton" onClick={() => navigate('/')}>
            <span className="logoutIcon">↪</span><span>Log Out</span>
          </button>
        </aside>

        <main className="mainContent">
          <h1 className="pageTitle">History</h1>

          {errorMsg && <div className="errorBanner">{errorMsg}</div>}

          <div className="historyCard">
            {loading ? (
              <div className="historyEmpty">กำลังโหลด...</div>
            ) : history.length === 0 ? (
              <div className="historyEmpty">ยังไม่มีประวัติการสแกน</div>
            ) : (
              <table className="historyTable">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Target</th>
                    <th>Version</th>
                    <th>Score</th>
                    <th>Pass</th>
                    <th>Fail</th>
                    <th>Links</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h) => (
                    <tr key={h.id}>
                      <td><div className="historyCell">{formatDate(h.scan_date)}</div></td>
                      <td><div className="historyCell">{h.target_name}</div></td>
                      <td><div className="historyCell">{h.version || '—'}</div></td>
                      <td>
                        <div className="historyCell scoreCell" style={{ color: scoreColor(h.score) }}>
                          {h.score}%
                        </div>
                      </td>
                      <td><div className="historyCell passCell">✔ {h.pass_count}</div></td>
                      <td><div className="historyCell failCell">✖ {h.fail_count}</div></td>
                      <td>
                        <div className="historyActions">
                          <button className="viewBtn" onClick={() => handleView(h.id)}>View</button>
                          <button
                            className="deleteBtn"
                            onClick={() => handleDelete(h.id)}
                            disabled={deleting === h.id}
                          >
                            {deleting === h.id ? '...' : 'Delete'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <div className="historyFooter">
              <button className="backBtn"   onClick={() => navigate('/home')}>Back</button>
              <button className="finishBtn" onClick={() => navigate('/home')}>Finish</button>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default History;