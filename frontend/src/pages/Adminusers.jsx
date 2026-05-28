import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth } from '../auth';

const API_BASE = `http://${window.location.hostname}:8000`;

// ─── Inline styles (ใช้ style เดียวกับ History.jsx) ──────────────────────────
const S = {
  root: { display: 'flex', minHeight: '100vh', background: 'var(--bg, #f5f5f0)' },

  // Sidebar
  sidebar: {
    width: '200px', minHeight: '100vh', background: 'var(--ink, #1a1a2e)',
    display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
    padding: '24px 0', flexShrink: 0,
  },
  sideTop: { display: 'flex', flexDirection: 'column', gap: '32px' },
  logo: { display: 'flex', alignItems: 'center', gap: '10px', padding: '0 20px' },
  logoText: { color: '#fff', fontWeight: 700, fontSize: '15px' },
  sideNav: { display: 'flex', flexDirection: 'column', gap: '2px' },
  sideLink: {
    display: 'flex', alignItems: 'center', gap: '10px',
    padding: '9px 20px', background: 'transparent', border: 'none',
    color: 'rgba(255,255,255,0.55)', fontSize: '13px', fontWeight: 500,
    cursor: 'pointer', textAlign: 'left', borderRadius: 0, transition: 'all 0.15s',
  },
  sideLinkActive: { color: '#fff', background: 'rgba(255,255,255,0.07)' },
  sideDot: {
    width: '5px', height: '5px', borderRadius: '50%',
    background: 'rgba(255,255,255,0.25)', flexShrink: 0,
  },
  sideDotActive: { background: '#c8813a' },
  logoutBtn: {
    display: 'flex', alignItems: 'center', gap: '8px',
    margin: '0 12px', padding: '8px 12px', borderRadius: '8px',
    border: '1px solid rgba(255,255,255,0.1)', background: 'transparent',
    color: 'rgba(255,255,255,0.5)', fontSize: '12px', cursor: 'pointer',
  },

  // Main
  main: { flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 },
  topbar: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '16px 32px', background: '#fff',
    borderBottom: '1px solid #f0f0ec',
  },
  topbarDate: { fontSize: '12px', color: '#9ca3af', margin: 0 },
  topbarActions: { display: 'flex', alignItems: 'center', gap: '12px' },
  avatar: {
    width: '32px', height: '32px', borderRadius: '50%',
    background: '#c8813a', color: '#fff',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: '13px', fontWeight: 700,
  },

  // Page
  pageHead: { padding: '28px 32px 0' },
  pageTitle: { fontSize: '24px', fontWeight: 700, color: '#1a1a2e', margin: '0 0 4px' },
  pageDesc:  { fontSize: '13px', color: '#9ca3af', margin: 0 },

  content: { padding: '24px 32px', flex: 1 },

  // Stats row
  statsRow: { display: 'flex', gap: '16px', marginBottom: '24px' },
  statCard: {
    flex: 1, background: '#fff', borderRadius: '12px', padding: '18px 20px',
    border: '1px solid #f0f0ec',
  },
  statNum:   { fontSize: '28px', fontWeight: 700, color: '#1a1a2e', lineHeight: 1 },
  statLabel: { fontSize: '12px', color: '#9ca3af', marginTop: '4px' },

  // Card
  card: {
    background: '#fff', borderRadius: '12px',
    border: '1px solid #f0f0ec', overflow: 'hidden',
  },
  cardHead: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '16px 20px', borderBottom: '1px solid #f0f0ec',
  },
  cardTitle: { fontSize: '14px', fontWeight: 600, color: '#1a1a2e', margin: 0 },

  // Table
  table: { width: '100%', borderCollapse: 'collapse' },
  th: {
    padding: '10px 16px', textAlign: 'left', fontSize: '11px',
    fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase',
    letterSpacing: '0.05em', borderBottom: '1px solid #f0f0ec',
    background: '#fafaf8',
  },
  td: {
    padding: '12px 16px', fontSize: '13px', color: '#374151',
    borderBottom: '1px solid #f9f9f7',
  },

  // Badges
  badgeAdmin: {
    display: 'inline-flex', alignItems: 'center', gap: '4px',
    padding: '2px 10px', borderRadius: '20px', fontSize: '11px', fontWeight: 600,
    background: 'rgba(200,129,58,0.12)', color: '#c8813a',
    border: '1px solid rgba(200,129,58,0.3)',
  },
  badgeViewer: {
    display: 'inline-flex', alignItems: 'center', gap: '4px',
    padding: '2px 10px', borderRadius: '20px', fontSize: '11px', fontWeight: 600,
    background: 'rgba(99,102,241,0.10)', color: '#6366f1',
    border: '1px solid rgba(99,102,241,0.25)',
  },

  // Action buttons
  actionRow: { display: 'flex', gap: '6px', alignItems: 'center' },
  btnSm: {
    padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: 500,
    cursor: 'pointer', border: '1px solid transparent', transition: 'all 0.15s',
  },
  btnRole: { background: '#f3f4f6', color: '#374151', border: '1px solid #e5e7eb' },
  btnReset: { background: 'rgba(99,102,241,0.08)', color: '#6366f1', border: '1px solid rgba(99,102,241,0.25)' },
  btnDelete: { background: 'rgba(220,38,38,0.08)', color: '#dc2626', border: '1px solid rgba(220,38,38,0.2)' },

  // Error banner
  errBanner: {
    display: 'flex', alignItems: 'center', gap: '8px',
    padding: '10px 16px', borderRadius: '8px', marginBottom: '16px',
    background: 'rgba(220,38,38,0.08)', color: '#dc2626',
    border: '1px solid rgba(220,38,38,0.2)', fontSize: '13px',
  },

  // Modal overlay
  overlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
  },
  modal: {
    background: '#fff', borderRadius: '14px', padding: '28px',
    width: '360px', boxShadow: '0 20px 60px rgba(0,0,0,0.15)',
  },
  modalTitle: { fontSize: '16px', fontWeight: 700, color: '#1a1a2e', marginBottom: '6px' },
  modalDesc:  { fontSize: '13px', color: '#6b7280', marginBottom: '20px' },
  modalInput: {
    width: '100%', padding: '9px 12px', borderRadius: '8px', fontSize: '13px',
    border: '1px solid #e5e7eb', outline: 'none', marginBottom: '16px',
    boxSizing: 'border-box',
  },
  modalActions: { display: 'flex', gap: '8px', justifyContent: 'flex-end' },
  btnCancel: {
    padding: '8px 16px', borderRadius: '8px', fontSize: '13px',
    background: '#f3f4f6', color: '#374151', border: '1px solid #e5e7eb', cursor: 'pointer',
  },
  btnConfirm: {
    padding: '8px 16px', borderRadius: '8px', fontSize: '13px',
    background: '#c8813a', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600,
  },
  btnConfirmDanger: {
    padding: '8px 16px', borderRadius: '8px', fontSize: '13px',
    background: '#dc2626', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600,
  },

  // Empty
  empty: { padding: '48px', textAlign: 'center', color: '#9ca3af', fontSize: '13px' },

  // Loading spinner
  spin: {
    display: 'inline-block', width: '14px', height: '14px',
    border: '2px solid #e5e7eb', borderTopColor: '#c8813a',
    borderRadius: '50%', animation: 'spin 0.7s linear infinite',
  },
};

// ─── Modal Components ─────────────────────────────────────────────────────────

function ResetPasswordModal({ user, onConfirm, onClose }) {
  const [pw, setPw]   = useState('');
  const [err, setErr] = useState('');

  const handleSubmit = () => {
    if (pw.length < 6) { setErr('Password ต้องมีอย่างน้อย 6 ตัวอักษร'); return; }
    onConfirm(pw);
  };

  return (
    <div style={S.overlay} onClick={onClose}>
      <div style={S.modal} onClick={(e) => e.stopPropagation()}>
        <div style={S.modalTitle}>Reset Password</div>
        <div style={S.modalDesc}>ตั้ง password ใหม่สำหรับ <b>{user.username}</b></div>
        {err && <div style={{ color: '#dc2626', fontSize: '12px', marginBottom: '8px' }}>{err}</div>}
        <input
          style={S.modalInput}
          type="password"
          placeholder="New password (min 6 chars)"
          value={pw}
          onChange={(e) => { setPw(e.target.value); setErr(''); }}
          autoFocus
        />
        <div style={S.modalActions}>
          <button style={S.btnCancel} onClick={onClose}>Cancel</button>
          <button style={S.btnConfirm} onClick={handleSubmit}>Reset</button>
        </div>
      </div>
    </div>
  );
}

function DeleteModal({ user, onConfirm, onClose }) {
  return (
    <div style={S.overlay} onClick={onClose}>
      <div style={S.modal} onClick={(e) => e.stopPropagation()}>
        <div style={S.modalTitle}>ลบ User</div>
        <div style={S.modalDesc}>
          ต้องการลบ <b>{user.username}</b> ออกจากระบบ?<br />
          การกระทำนี้ไม่สามารถย้อนกลับได้
        </div>
        <div style={S.modalActions}>
          <button style={S.btnCancel} onClick={onClose}>Cancel</button>
          <button style={S.btnConfirmDanger} onClick={onConfirm}>ลบ</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AdminUsers() {
  const navigate = useNavigate();

  const [users,    setUsers]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [errorMsg, setErrorMsg] = useState('');

  // Modal state
  const [resetModal,  setResetModal]  = useState(null); // user object
  const [deleteModal, setDeleteModal] = useState(null); // user object
  const [saving,      setSaving]      = useState(false);

  const token      = () => localStorage.getItem('token') || '';
  const authHeader = () => ({
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${token()}`,
  });

  // ─── Fetch users ──────────────────────────────────────────────────
  const fetchUsers = useCallback(async () => {
    console.log('token:', localStorage.getItem('token'));
    console.log('API_BASE:', API_BASE);
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch(`${API_BASE}/api/admin/users`, { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      if (res.status === 403) { setErrorMsg('ต้องการสิทธิ์ Admin'); setLoading(false); return; }
      const data = await res.json();
      if (res.ok) setUsers(data);
      else setErrorMsg(data.detail || 'โหลดข้อมูลไม่สำเร็จ');
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  // ─── Toggle role ──────────────────────────────────────────────────
  const handleToggleRole = async (user) => {
    const newRole = user.role === 'admin' ? 'viewer' : 'admin';
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${user.id}/role`, {
        method:  'PATCH',
        headers: authHeader(),
        body:    JSON.stringify({ role: newRole }),
      });
      const data = await res.json();
      if (res.ok) {
        setUsers((prev) => prev.map((u) => u.id === user.id ? { ...u, role: newRole } : u));
      } else {
        setErrorMsg(data.detail || 'เปลี่ยน role ไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  // ─── Reset password ───────────────────────────────────────────────
  const handleResetPassword = async (newPassword) => {
    if (!resetModal) return;
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${resetModal.id}/reset-password`, {
        method:  'POST',
        headers: authHeader(),
        body:    JSON.stringify({ new_password: newPassword }),
      });
      const data = await res.json();
      if (res.ok) {
        setResetModal(null);
      } else {
        setErrorMsg(data.detail || 'Reset password ไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  // ─── Delete user ──────────────────────────────────────────────────
  const handleDelete = async () => {
    if (!deleteModal) return;
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${deleteModal.id}`, {
        method:  'DELETE',
        headers: authHeader(),
      });
      const data = await res.json();
      if (res.ok) {
        setUsers((prev) => prev.filter((u) => u.id !== deleteModal.id));
        setDeleteModal(null);
      } else {
        setErrorMsg(data.detail || 'ลบ user ไม่สำเร็จ');
      }
    } catch (err) {
      setErrorMsg(`เกิดข้อผิดพลาด: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  // ─── Stats ────────────────────────────────────────────────────────
  const totalUsers  = users.length;
  const adminCount  = users.filter((u) => u.role === 'admin').length;
  const viewerCount = users.filter((u) => u.role === 'viewer').length;

  const currentUsername = localStorage.getItem('username') || '';

  return (
    <>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        button:hover { opacity: 0.85; }
      `}</style>

      <div style={S.root}>
        {/* ── Sidebar ── */}
        <aside style={S.sidebar}>
          <div style={S.sideTop}>
            <div style={S.logo}>
              <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
                <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5" />
                <circle cx="11" cy="11" r="5"  stroke="#c8813a" strokeWidth="1.5" />
                <circle cx="11" cy="11" r="1.5" fill="#c8813a" />
              </svg>
              <span style={S.logoText}>SecureScan</span>
            </div>
            <nav style={S.sideNav}>
              {[
                { label: 'Home',    path: '/home' },
                { label: 'History', path: '/history' },
                { label: 'Guide',   path: '/guide' },
                { label: 'Agents',  path: '/admin/agents' },
                { label: 'Users',   path: '/admin/users', active: true },
              ].map((item) => (
                <button
                  key={item.path}
                  style={{ ...S.sideLink, ...(item.active ? S.sideLinkActive : {}) }}
                  onClick={() => navigate(item.path)}
                >
                  <span style={{ ...S.sideDot, ...(item.active ? S.sideDotActive : {}) }} />
                  {item.label}
                </button>
              ))}
            </nav>
          </div>
          <button style={S.logoutBtn} onClick={() => { clearAuth(); navigate('/login'); }}>
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M5 2H2v10h3M9 10l3-3-3-3M12 7H5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Log out
          </button>
        </aside>

        {/* ── Main ── */}
        <main style={S.main}>
          {/* Topbar */}
          <header style={S.topbar}>
            <p style={S.topbarDate}>
              {new Date().toLocaleDateString('th-TH', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            </p>
            <div style={S.topbarActions}>
              <div style={S.avatar}>{currentUsername.charAt(0).toUpperCase() || 'A'}</div>
            </div>
          </header>

          {/* Page head */}
          <div style={S.pageHead}>
            <h1 style={S.pageTitle}>User Management</h1>
            <p style={S.pageDesc}>จัดการผู้ใช้งานในระบบ</p>
          </div>

          <div style={S.content}>
            {/* Error */}
            {errorMsg && (
              <div style={S.errBanner}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="7" cy="7" r="6" /><path d="M7 4v3M7 10h.01" strokeLinecap="round" />
                </svg>
                {errorMsg}
              </div>
            )}

            {/* Stats */}
            <div style={S.statsRow}>
              {[
                { num: totalUsers,  label: 'Users ทั้งหมด' },
                { num: adminCount,  label: 'Admin' },
                { num: viewerCount, label: 'Viewer' },
              ].map((s) => (
                <div key={s.label} style={S.statCard}>
                  <div style={S.statNum}>{s.num}</div>
                  <div style={S.statLabel}>{s.label}</div>
                </div>
              ))}
            </div>

            {/* Table */}
            <div style={S.card}>
              <div style={S.cardHead}>
                <h2 style={S.cardTitle}>รายชื่อผู้ใช้งาน</h2>
                <span style={{ fontSize: '12px', color: '#9ca3af' }}>{totalUsers} users</span>
              </div>

              {loading ? (
                <div style={S.empty}>
                  <span style={S.spin} /> กำลังโหลด...
                </div>
              ) : users.length === 0 ? (
                <div style={S.empty}>ไม่พบผู้ใช้งาน</div>
              ) : (
                <table style={S.table}>
                  <thead>
                    <tr>
                      <th style={S.th}>ID</th>
                      <th style={S.th}>Username</th>
                      <th style={S.th}>Role</th>
                      <th style={S.th}>Status</th>
                      <th style={{ ...S.th, textAlign: 'center' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user) => {
                      const isSelf = user.username === currentUsername;
                      return (
                        <tr key={user.id}>
                          <td style={{ ...S.td, color: '#9ca3af', fontFamily: 'monospace' }}>
                            #{user.id}
                          </td>
                          <td style={S.td}>
                            <span style={{ fontWeight: 600 }}>{user.username}</span>
                            {isSelf && (
                              <span style={{
                                marginLeft: '8px', fontSize: '10px', color: '#9ca3af',
                                background: '#f3f4f6', padding: '1px 6px', borderRadius: '4px',
                              }}>
                                คุณ
                              </span>
                            )}
                          </td>
                          <td style={S.td}>
                            <span style={user.role === 'admin' ? S.badgeAdmin : S.badgeViewer}>
                              {user.role === 'admin' ? '★ Admin' : '● Viewer'}
                            </span>
                          </td>
                          <td style={S.td}>
                            <span style={{
                              fontSize: '11px', fontWeight: 500,
                              color: user.is_active ? '#16a34a' : '#dc2626',
                            }}>
                              {user.is_active ? '● Active' : '○ Inactive'}
                            </span>
                          </td>
                          <td style={{ ...S.td, textAlign: 'center' }}>
                            <div style={{ ...S.actionRow, justifyContent: 'center' }}>
                              {/* Toggle Role */}
                              <button
                                style={{ ...S.btnSm, ...S.btnRole }}
                                onClick={() => handleToggleRole(user)}
                                disabled={saving || isSelf}
                                title={isSelf ? 'ไม่สามารถเปลี่ยน role ตัวเองได้' : `เปลี่ยนเป็น ${user.role === 'admin' ? 'Viewer' : 'Admin'}`}
                              >
                                {user.role === 'admin' ? '→ Viewer' : '→ Admin'}
                              </button>

                              {/* Reset Password */}
                              <button
                                style={{ ...S.btnSm, ...S.btnReset }}
                                onClick={() => setResetModal(user)}
                                disabled={saving}
                              >
                                Reset PW
                              </button>

                              {/* Delete */}
                              <button
                                style={{ ...S.btnSm, ...S.btnDelete }}
                                onClick={() => setDeleteModal(user)}
                                disabled={saving || isSelf}
                                title={isSelf ? 'ไม่สามารถลบตัวเองได้' : 'ลบ user'}
                              >
                                ลบ
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </main>
      </div>

      {/* ── Modals ── */}
      {resetModal && (
        <ResetPasswordModal
          user={resetModal}
          onConfirm={handleResetPassword}
          onClose={() => setResetModal(null)}
        />
      )}
      {deleteModal && (
        <DeleteModal
          user={deleteModal}
          onConfirm={handleDelete}
          onClose={() => setDeleteModal(null)}
        />
      )}
    </>
  );
}
