import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import './ChangePassword.css';

export default function ChangePassword() {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword,     setNewPassword]     = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error,           setError]           = useState('');
  const [success,         setSuccess]         = useState('');
  const [loading,         setLoading]         = useState(false);

  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew,     setShowNew]     = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  // password strength
  const strength = (() => {
    if (!newPassword) return 0;
    let s = 0;
    if (newPassword.length >= 8)              s++;
    if (/[A-Z]/.test(newPassword))            s++;
    if (/[0-9]/.test(newPassword))            s++;
    if (/[^A-Za-z0-9]/.test(newPassword))     s++;
    return s;
  })();

  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][strength];
  const strengthColor = ['', 'var(--red)', 'var(--amber-lt)', 'var(--amber)', 'var(--green)'][strength];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Password confirmation does not match');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(
        apiUrl('/api/user/change-password'),
        {
          method: 'POST',
          headers: authHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            current_password: currentPassword,
            new_password:     newPassword,
          }),
        }
      );

      if (res.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }

      const data = await res.json();

      if (res.ok) {
        setSuccess('Password changed successfully. Please sign in again.');
        setTimeout(() => {
          clearAuth();
          navigate('/login');
        }, 2000);
      } else {
        setError(data.detail || 'Request failed');
      }
    } catch {
      setError('Unable to connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cp-page">
      <div className="cp-card">

        {/* Brand */}
        <div className="cp-brand">
          <div className="cp-brand-icon">
            <svg width="18" height="18" viewBox="0 0 22 22" fill="none">
              <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="5"  stroke="#c8813a" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="1.5" fill="#c8813a" />
            </svg>
          </div>
          <span className="cp-brand-name">SecureScan</span>
        </div>

        {/* Lock icon */}
        <div className="cp-lock-icon">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" strokeWidth="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" strokeLinecap="round" />
          </svg>
        </div>

        <h1 className="cp-title">Change Password</h1>
        <p className="cp-subtitle">Update password for {localStorage.getItem('username') || ''}</p>

        {/* Messages */}
        {error && (
          <div className="cp-msg cp-err">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6" />
              <path d="M7 4v3M7 10h.01" strokeLinecap="round" />
            </svg>
            {error}
          </div>
        )}
        {success && (
          <div className="cp-msg cp-ok">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6" />
              <path d="M4.5 7l2 2 3-3" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {success}
          </div>
        )}

        <form onSubmit={handleSubmit}>

          {/* Current password */}
          <div className="cp-field">
            <label className="cp-label">Current Password</label>
            <div className="cp-input-wrap">
              <input
                className="cp-input"
                type={showCurrent ? 'text' : 'password'}
                placeholder=""
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="cp-eye"
                onClick={() => setShowCurrent(!showCurrent)}
                tabIndex={-1}
              >
                {showCurrent ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" strokeLinecap="round" />
                    <line x1="1" y1="1" x2="23" y2="23" strokeLinecap="round" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          {/* New password */}
          <div className="cp-field">
            <label className="cp-label">New Password</label>
            <div className="cp-input-wrap">
              <input
                className="cp-input"
                type={showNew ? 'text' : 'password'}
                placeholder=""
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="cp-eye"
                onClick={() => setShowNew(!showNew)}
                tabIndex={-1}
              >
                {showNew ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" strokeLinecap="round" />
                    <line x1="1" y1="1" x2="23" y2="23" strokeLinecap="round" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>

            {/* Strength bar */}
            {newPassword && (
              <div className="cp-strength">
                <div className="cp-strength-bars">
                  {[1, 2, 3, 4].map((n) => (
                    <div
                      key={n}
                      className="cp-strength-bar"
                      style={{ background: n <= strength ? strengthColor : 'var(--cream-mid)' }}
                    />
                  ))}
                </div>
                <span className="cp-strength-label" style={{ color: strengthColor }}>
                  {strengthLabel}
                </span>
              </div>
            )}
          </div>

          {/* Confirm password */}
          <div className="cp-field">
            <label className="cp-label">Confirm New Password</label>
            <div className="cp-input-wrap">
              <input
                className="cp-input"
                type={showConfirm ? 'text' : 'password'}
                placeholder=""
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
              <button
                type="button"
                className="cp-eye"
                onClick={() => setShowConfirm(!showConfirm)}
                tabIndex={-1}
              >
                {showConfirm ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" strokeLinecap="round" />
                    <line x1="1" y1="1" x2="23" y2="23" strokeLinecap="round" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>
            {/* Match indicator */}
            {confirmPassword && (
              <div
                className="cp-match"
                style={{ color: newPassword === confirmPassword ? 'var(--green)' : 'var(--red)' }}
              >
                {newPassword === confirmPassword ? 'Passwords match' : 'Passwords do not match'}
              </div>
            )}
          </div>

          <button type="submit" className="cp-btn" disabled={loading}>
            {loading ? (
              <><span className="cp-spin" /> Saving...</>
            ) : (
              'Change Password'
            )}
          </button>
        </form>

        <button className="cp-back" onClick={() => navigate(-1)}>
           Back
        </button>
      </div>
    </div>
  );
}


