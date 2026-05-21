import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

export function clearAuth() {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  localStorage.removeItem('role');
  sessionStorage.removeItem('scanResult');
}

export function authHeaders(extra = {}) {
  return {
    ...extra,
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  };
}

export function ProtectedRoute({ children, role }) {
  const location = useLocation();
  const token = localStorage.getItem('token');
  const currentRole = localStorage.getItem('role');

  if (!token) {
    return React.createElement(Navigate, {
      to: '/login',
      replace: true,
      state: { from: location },
    });
  }

  if (role && currentRole !== role) {
    return React.createElement(Navigate, { to: '/home', replace: true });
  }

  return children;
}
