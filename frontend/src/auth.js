import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { apiUrl } from './config/api';

let cachedToken = '';
let cachedUser = null;

export function clearAuth() {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  localStorage.removeItem('role');
  sessionStorage.removeItem('scanResult');
  cachedToken = '';
  cachedUser = null;
}

export function authHeaders(extra = {}) {
  return {
    ...extra,
    Authorization: `Bearer ${localStorage.getItem('token') || ''}`,
  };
}

export async function fetchCurrentUser({ force = false } = {}) {
  const token = localStorage.getItem('token') || '';
  if (!token) throw new Error('missing token');
  if (!force && cachedUser && cachedToken === token) return cachedUser;

  const res = await fetch(apiUrl('/api/me'), { headers: authHeaders() });
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) clearAuth();
    throw new Error(`current user request failed (${res.status})`);
  }

  const user = await res.json();
  cachedToken = token;
  cachedUser = user;
  if (user?.username) localStorage.setItem('username', user.username);
  localStorage.removeItem('role');
  return user;
}

export function isAdmin() {
  return cachedUser?.role === 'admin' || cachedUser?.role === 'owner';
}

export function useCurrentUser() {
  const [state, setState] = useState(() => ({
    user: cachedUser,
    loading: Boolean(localStorage.getItem('token')) && !cachedUser,
    error: '',
  }));

  useEffect(() => {
    let cancelled = false;
    const token = localStorage.getItem('token') || '';
    if (!token) {
      setState({ user: null, loading: false, error: 'missing token' });
      return;
    }

    setState((prev) => ({ ...prev, loading: !cachedUser }));
    fetchCurrentUser()
      .then((user) => {
        if (!cancelled) setState({ user, loading: false, error: '' });
      })
      .catch((err) => {
        if (!cancelled) setState({ user: null, loading: false, error: err.message });
      });

    return () => { cancelled = true; };
  }, []);

  return state;
}

export function useIsAdmin() {
  const { user } = useCurrentUser();
  return user?.role === 'admin' || user?.role === 'owner';
}

export function ProtectedRoute({ children, role }) {
  const location = useLocation();
  const token = localStorage.getItem('token');
  const { user, loading } = useCurrentUser();

  if (!token) {
    return React.createElement(Navigate, {
      to: '/login',
      replace: true,
      state: { from: location },
    });
  }

  if (loading) {
    return null;
  }

  if (!user) {
    return React.createElement(Navigate, {
      to: '/login',
      replace: true,
      state: { from: location },
    });
  }

  if (role === 'admin' && !['admin', 'owner'].includes(user.role)) {
    return React.createElement(Navigate, { to: '/home', replace: true });
  }

  if (role && role !== 'admin' && user.role !== role) {
    return React.createElement(Navigate, { to: '/home', replace: true });
  }

  return children;
}
