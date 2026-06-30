/* eslint-disable react-hooks/set-state-in-effect */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth, useCurrentUser } from '../auth';
import { apiUrl } from '../config/api';
import {
  MetricCard,
  MetricGrid,
  ReportHeader,
  ReportShell,
  ReportTopbar,
} from './ReportUI';
import './Adminusers.css';

function roleLabel(role) {
  if (role === 'owner') return 'Owner';
  if (role === 'admin') return 'Admin';
  return 'Viewer';
}

function roleDescription(role) {
  if (role === 'owner') return 'Protected system owner';
  if (role === 'admin') return 'Can manage agents, baselines, schedules, and users';
  return 'Can scan and view permitted reports';
}

function UserModal({ title, description, children, actions, onClose, width = '420px' }) {
  return (
    <div className="userModalBackdrop" role="presentation" onClick={onClose}>
      <div
        className="userModal"
        role="dialog"
        aria-modal="true"
        style={{ '--user-modal-width': width }}
        onClick={(event) => event.stopPropagation()}
      >
        <h2>{title}</h2>
        {description && <p>{description}</p>}
        {children}
        <div className="userModalActions">{actions}</div>
      </div>
    </div>
  );
}

function ResetPasswordModal({ user, onConfirm, onClose, saving }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    onConfirm(password);
  };

  return (
    <UserModal
      title="Reset password"
      description={`Set a new local password for ${user.username}.`}
      onClose={onClose}
      actions={(
        <>
          <button className="userBtn secondary" type="button" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="userBtn primary" type="button" onClick={handleSubmit} disabled={saving}>
            {saving ? 'Resetting...' : 'Reset password'}
          </button>
        </>
      )}
    >
      {error && <div className="userInlineError">{error}</div>}
      <label className="userField">
        <span>New password</span>
        <input
          type="password"
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
            setError('');
          }}
          placeholder="Minimum 6 characters"
          autoFocus
        />
      </label>
    </UserModal>
  );
}

function DeleteUserModal({ user, onConfirm, onClose, saving }) {
  return (
    <UserModal
      title="Delete user?"
      description={`Delete ${user.username} from SecureScan. This action cannot be undone.`}
      onClose={onClose}
      actions={(
        <>
          <button className="userBtn secondary" type="button" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="userBtn danger" type="button" onClick={onConfirm} disabled={saving}>
            {saving ? 'Deleting...' : 'Delete user'}
          </button>
        </>
      )}
    >
      <div className="userWarning">
        Reports and audit records remain for traceability, but this account will no longer be available.
      </div>
    </UserModal>
  );
}

function ChangeRoleModal({ user, onConfirm, onClose, saving }) {
  const [selectedRole, setSelectedRole] = useState(user.role || 'viewer');
  const [review, setReview] = useState(false);
  const changed = selectedRole !== user.role;
  const options = [
    { role: 'viewer', title: 'Viewer', desc: 'Read reports and run allowed scans.' },
    { role: 'admin', title: 'Admin', desc: 'Manage users, agents, baselines, and schedules.' },
  ];

  if (review) {
    return (
      <UserModal
        title="Confirm role change"
        description={`Change ${user.username} from ${roleLabel(user.role)} to ${roleLabel(selectedRole)}.`}
        onClose={onClose}
        width="480px"
        actions={(
          <>
            <button className="userBtn secondary" type="button" onClick={() => setReview(false)} disabled={saving}>Back</button>
            <button className="userBtn secondary" type="button" onClick={onClose} disabled={saving}>Cancel</button>
            <button
              className={selectedRole === 'viewer' ? 'userBtn danger' : 'userBtn primary'}
              type="button"
              onClick={() => onConfirm(selectedRole)}
              disabled={saving}
            >
              {saving ? 'Saving...' : 'Confirm change'}
            </button>
          </>
        )}
      >
        <div className="userWarning">
          Role changes affect access to scan data and administrative actions. Confirm only if this change is intentional.
        </div>
      </UserModal>
    );
  }

  return (
    <UserModal
      title="Change user role"
      description={`Update permissions for ${user.username}. Owner role cannot be assigned from this page.`}
      onClose={onClose}
      width="520px"
      actions={(
        <>
          <button className="userBtn secondary" type="button" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="userBtn primary" type="button" onClick={() => setReview(true)} disabled={!changed || saving}>
            Review change
          </button>
        </>
      )}
    >
      <div className="roleOptionGrid">
        {options.map((option) => (
          <button
            key={option.role}
            className={`roleOption ${selectedRole === option.role ? 'selected' : ''}`}
            type="button"
            onClick={() => setSelectedRole(option.role)}
          >
            <strong>{option.title}</strong>
            <span>{option.desc}</span>
          </button>
        ))}
      </div>
      {selectedRole === 'admin' && selectedRole !== user.role && (
        <div className="userWarning">
          This grants elevated access to administrative operations.
        </div>
      )}
    </UserModal>
  );
}

export default function AdminUsers() {
  const navigate = useNavigate();
  const { user: currentUser } = useCurrentUser();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');
  const [resetModal, setResetModal] = useState(null);
  const [deleteModal, setDeleteModal] = useState(null);
  const [roleModal, setRoleModal] = useState(null);
  const [saving, setSaving] = useState(false);

  const authHeader = useCallback(() => ({
    'Content-Type': 'application/json',
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  }), []);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl('/api/admin/users'), { headers: authHeader() });
      if (res.status === 401) { clearAuth(); navigate('/login'); return; }
      if (res.status === 403) { setErrorMsg('Admin permission required'); return; }
      const data = await res.json();
      if (res.ok) {
        setUsers(Array.isArray(data) ? data : []);
      } else {
        setErrorMsg(data.detail || 'Unable to load users');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [authHeader, navigate]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleChangeRole = async (newRole) => {
    if (!roleModal || newRole === roleModal.role) return;
    setSaving(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl(`/api/admin/users/${roleModal.id}/role`), {
        method: 'PATCH',
        headers: authHeader(),
        body: JSON.stringify({ role: newRole }),
      });
      const data = await res.json();
      if (res.ok) {
        setUsers((prev) => prev.map((row) => (row.id === roleModal.id ? { ...row, role: newRole } : row)));
        setRoleModal(null);
      } else {
        setErrorMsg(data.detail || 'Unable to change role');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleResetPassword = async (newPassword) => {
    if (!resetModal) return;
    setSaving(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl(`/api/admin/users/${resetModal.id}/reset-password`), {
        method: 'POST',
        headers: authHeader(),
        body: JSON.stringify({ new_password: newPassword }),
      });
      const data = await res.json();
      if (res.ok) {
        setResetModal(null);
      } else {
        setErrorMsg(data.detail || 'Unable to reset password');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    setSaving(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl(`/api/admin/users/${deleteModal.id}`), {
        method: 'DELETE',
        headers: authHeader(),
      });
      const data = await res.json();
      if (res.ok) {
        setUsers((prev) => prev.filter((row) => row.id !== deleteModal.id));
        setDeleteModal(null);
      } else {
        setErrorMsg(data.detail || 'Unable to delete user');
      }
    } catch (err) {
      setErrorMsg(`Error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const stats = useMemo(() => ({
    total: users.length,
    owner: users.filter((row) => row.role === 'owner').length,
    admin: users.filter((row) => row.role === 'admin').length,
    viewer: users.filter((row) => row.role === 'viewer').length,
  }), [users]);

  const currentUsername = currentUser?.username || '';

  return (
    <ReportShell active="Users">
      <ReportTopbar />
      <div className="userManagement">
        <ReportHeader
          eyebrow="Access control"
          title="User Management"
          subtitle="Manage local and directory-backed user access for scanner operations."
          context={[
            { label: 'Signed in as', value: currentUsername || '-' },
            { label: 'Current role', value: roleLabel(currentUser?.role) },
          ]}
          actions={(
            <button className="reportAction" type="button" onClick={fetchUsers} disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          )}
        />

        {errorMsg && (
          <div className="userErrorBanner">
            <span aria-hidden="true">!</span>
            {errorMsg}
          </div>
        )}

        <MetricGrid>
          <MetricCard label="Total users" value={stats.total} hint="All accounts" tone="info" />
          <MetricCard label="Owners" value={stats.owner} hint="Protected" tone="neutral" />
          <MetricCard label="Admins" value={stats.admin} hint="Elevated access" tone="warn" />
          <MetricCard label="Viewers" value={stats.viewer} hint="Read-only users" tone="neutral" />
        </MetricGrid>

        <section className="userPanel">
          <div className="userPanelHead">
            <div>
              <h2>User list</h2>
              <p>Owner accounts are protected. Admin role changes are restricted by server-side policy.</p>
            </div>
            <span>{stats.total} users</span>
          </div>

          {loading ? (
            <div className="userEmpty">
              <span className="userSpin" />
              Loading users...
            </div>
          ) : users.length === 0 ? (
            <div className="userEmpty">No users found</div>
          ) : (
            <div className="userTableWrap">
              <table className="userTable">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Access summary</th>
                    <th className="center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((row) => {
                    const isSelf = row.username === currentUsername;
                    const isOwner = row.role === 'owner';
                    const canManageRole = !isSelf && (
                      currentUser?.role === 'owner' ||
                      !['admin', 'owner'].includes(row.role)
                    );
                    return (
                      <tr key={row.id}>
                        <td className="monoCell">#{row.id}</td>
                        <td>
                          <div className="userIdentity">
                            <strong>{row.username}</strong>
                            {isSelf && <span>You</span>}
                          </div>
                        </td>
                        <td>
                          <span className={`userRoleBadge ${row.role || 'viewer'}`}>{roleLabel(row.role)}</span>
                        </td>
                        <td>
                          <span className={`userStatus ${row.is_active ? 'active' : 'inactive'}`}>
                            {row.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="userAccessSummary">{roleDescription(row.role)}</td>
                        <td>
                          {isOwner ? (
                            <span className="userProtected">Protected owner</span>
                          ) : (
                            <div className="userActionGroup">
                              <button
                                className="userBtn secondary"
                                type="button"
                                onClick={() => setRoleModal(row)}
                                disabled={saving || !canManageRole}
                                title={isSelf ? 'You cannot change your own role' : !canManageRole ? 'Only owner can manage admin or owner roles' : 'Change role'}
                              >
                                Change role
                              </button>
                              <button
                                className="userBtn secondary"
                                type="button"
                                onClick={() => setResetModal(row)}
                                disabled={saving}
                              >
                                Reset password
                              </button>
                              <button
                                className="userBtn dangerGhost"
                                type="button"
                                onClick={() => setDeleteModal(row)}
                                disabled={saving || isSelf}
                                title={isSelf ? 'You cannot delete yourself' : 'Delete user'}
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {resetModal && (
        <ResetPasswordModal
          user={resetModal}
          onConfirm={handleResetPassword}
          onClose={() => setResetModal(null)}
          saving={saving}
        />
      )}
      {roleModal && (
        <ChangeRoleModal
          user={roleModal}
          onConfirm={handleChangeRole}
          onClose={() => setRoleModal(null)}
          saving={saving}
        />
      )}
      {deleteModal && (
        <DeleteUserModal
          user={deleteModal}
          onConfirm={handleDelete}
          onClose={() => setDeleteModal(null)}
          saving={saving}
        />
      )}
    </ReportShell>
  );
}
