import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import './Register.css';
import { apiUrl } from '../config/api';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (password !== confirmPassword) {
      setError('Password และ Confirm Password ไม่ตรงกัน');
      return;
    }

    try {
      const response = await fetch(apiUrl('/register'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (response.ok) {
        setSuccess('Register success! กำลังไปหน้า Login...');
        setTimeout(() => navigate('/'), 1500);
      } else {
        setError(data.detail || 'Register failed');
      }
    } catch (err) {
      setError('Cannot connect to server');
    }
  };

  return (
    <div className="register-page">
      <div className="register-card">
        <div className="register-brand">
          <div className="register-brand-icon">
            <svg width="18" height="18" viewBox="0 0 22 22" fill="none">
              <circle cx="11" cy="11" r="10" stroke="#c8813a" strokeWidth="1.5"/>
              <circle cx="11" cy="11" r="5"  stroke="#c8813a" strokeWidth="1.5"/>
              <circle cx="11" cy="11" r="1.5" fill="#c8813a"/>
            </svg>
          </div>
          <span className="register-brand-name">SecureScan</span>
        </div>

        <h1 className="register-title">Create account</h1>
        <p className="register-subtitle">Join SecureScan to start monitoring your network</p>

        {error && (
          <div className="register-err">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6"/><path d="M7 4v3M7 10h.01" strokeLinecap="round"/>
            </svg>
            {error}
          </div>
        )}

        {success && (
          <div className="register-ok">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="7" cy="7" r="6"/><path d="M4.5 7l2 2 3-3" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            {success}
          </div>
        )}

        <form onSubmit={handleRegister}>
          <div className="register-field">
            <label className="register-label">Username / Email</label>
            <input
              className="register-input"
              type="text"
              placeholder="you@example.com"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="register-divider" />

          <div className="register-field">
            <label className="register-label">Password</label>
            <input
              className="register-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="register-field">
            <label className="register-label">Confirm Password</label>
            <input
              className="register-input"
              type="password"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <button type="submit" className="register-btn">Create Account →</button>
        </form>

        <div className="register-footer">
          Already have an account? <Link to="/">Sign in</Link>
        </div>
      </div>
    </div>
  );
}

export default Register;
