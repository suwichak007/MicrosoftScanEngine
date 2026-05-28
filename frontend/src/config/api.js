const BACKEND_PORT = '8000';

const host = window.location.hostname;
const protocol = window.location.protocol === 'https:' ? 'https' : 'http';

export const API_BASE = `${protocol}://${host}:${BACKEND_PORT}`;

export function apiUrl(path) {
  return `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
}
