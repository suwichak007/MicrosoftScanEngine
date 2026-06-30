/* eslint-disable react-hooks/set-state-in-effect */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import {
  MetricCard,
  MetricGrid,
  ReportHeader,
  ReportShell,
  ReportTopbar,
} from './ReportUI';
import './ActivityLog.css';

function formatDate(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function actionLabel(action = '') {
  return String(action || '-').replace(/_/g, ' ');
}

function normalizeDetail(detail) {
  if (!detail || typeof detail !== 'object') return '';
  return JSON.stringify(detail, null, 2);
}

function compactDetail(detail) {
  const text = normalizeDetail(detail).replace(/\s+/g, ' ').trim();
  if (!text) return '-';
  return text.length > 180 ? `${text.slice(0, 180)}...` : text;
}

function activityTone(row) {
  const status = String(row.status || '').toLowerCase();
  if (status.includes('fail') || status.includes('error')) return 'fail';
  if (status.includes('warn')) return 'warn';
  return 'pass';
}

export default function ActivityLog() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [actionOptions, setActionOptions] = useState([]);
  const [statusFilter, setStatusFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [detailRow, setDetailRow] = useState(null);

  const loadActivity = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const query = actionFilter ? `?limit=150&action=${encodeURIComponent(actionFilter)}` : '?limit=150';
      const res = await fetch(apiUrl(`/api/admin/activity${query}`), { headers: authHeaders() });
      if (res.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || 'Unable to load activity log');
      const nextRows = Array.isArray(data) ? data : [];
      setRows(nextRows);
      setActionOptions((prev) => {
        const values = new Set(prev);
        nextRows.forEach((row) => {
          if (row.action) values.add(row.action);
        });
        if (actionFilter) values.add(actionFilter);
        return Array.from(values).sort();
      });
    } catch (err) {
      setError(err.message || 'Unable to load activity log');
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, [actionFilter, navigate]);

  useEffect(() => {
    loadActivity();
  }, [loadActivity]);

  const stats = useMemo(() => {
    const todayKey = new Date().toISOString().slice(0, 10);
    const failed = rows.filter((row) => activityTone(row) === 'fail').length;
    const adminActions = rows.filter((row) => (
      String(row.action || '').includes('user') ||
      String(row.action || '').includes('baseline') ||
      String(row.action || '').includes('schedule') ||
      String(row.action || '').includes('autofix')
    )).length;
    return {
      total: rows.length,
      today: rows.filter((row) => String(row.created_at || '').slice(0, 10) === todayKey).length,
      failed,
      adminActions,
    };
  }, [rows]);

  const filteredRows = useMemo(() => {
    const needle = searchTerm.trim().toLowerCase();
    return rows.filter((row) => {
      if (statusFilter && activityTone(row) !== statusFilter) return false;
      if (!needle) return true;
      const haystack = [
        row.actor_username,
        row.actor_role,
        row.action,
        row.target_type,
        row.target_id,
        row.status,
        compactDetail(row.detail),
      ].join(' ').toLowerCase();
      return haystack.includes(needle);
    });
  }, [rows, searchTerm, statusFilter]);

  return (
    <ReportShell active="Activity">
      <ReportTopbar />
      <div className="activityLogPage">
        <ReportHeader
          eyebrow="Audit trail"
          title="Activity Log"
          subtitle="Review administrative actions, scan activity, exports, baseline changes, schedules, and autofix events."
          context={[
            { label: 'Loaded events', value: String(rows.length) },
            { label: 'Retention view', value: 'Latest 150 events' },
          ]}
          actions={(
            <button className="reportAction primary" type="button" onClick={loadActivity} disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          )}
        />

        {error && (
          <div className="activityError">
            <span aria-hidden="true">!</span>
            {error}
          </div>
        )}

        <MetricGrid>
          <MetricCard label="Events loaded" value={stats.total} hint="Latest activity" tone="info" />
          <MetricCard label="Today" value={stats.today} hint="Current day" tone="neutral" />
          <MetricCard label="Failed/error" value={stats.failed} hint="Needs review" tone={stats.failed ? 'fail' : 'neutral'} />
          <MetricCard label="Admin actions" value={stats.adminActions} hint="User, baseline, schedule, autofix" tone="warn" />
        </MetricGrid>

        <section className="activityPanel">
          <div className="activityPanelHead">
            <div>
              <h2>Events</h2>
              <p>Filter by action, status, actor, target, or detail text.</p>
            </div>
            <span>{filteredRows.length} shown</span>
          </div>

          <div className="activityToolbar">
            <input
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search actor, action, target, or detail"
            />
            <select value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}>
              <option value="">All actions</option>
              {actionOptions.map((action) => (
                <option key={action} value={action}>{actionLabel(action)}</option>
              ))}
            </select>
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
              <option value="">All status</option>
              <option value="pass">Success</option>
              <option value="warn">Warning</option>
              <option value="fail">Failed/Error</option>
            </select>
          </div>

          {loading && <div className="activityEmpty">Loading activity...</div>}
          {!loading && !error && filteredRows.length === 0 && (
            <div className="activityEmpty">No activity matches the current filters.</div>
          )}

          {!loading && filteredRows.length > 0 && (
            <div className="activityTableWrap">
              <table className="activityTable">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Detail</th>
                    <th className="center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.map((row) => (
                    <tr key={row.id}>
                      <td>{formatDate(row.created_at)}</td>
                      <td>
                        <div className="activityStack">
                          <strong>{row.actor_username || 'system'}</strong>
                          <span>{row.actor_role || '-'}</span>
                        </div>
                      </td>
                      <td>
                        <span className="activityAction">{actionLabel(row.action)}</span>
                      </td>
                      <td>
                        <div className="activityStack">
                          <strong>{row.target_type || '-'}</strong>
                          <span>{row.target_id || '-'}</span>
                        </div>
                      </td>
                      <td>
                        <span className={`activityStatus ${activityTone(row)}`}>{row.status || 'success'}</span>
                      </td>
                      <td className="activityDetailCell">{compactDetail(row.detail)}</td>
                      <td>
                        <button className="activityBtn" type="button" onClick={() => setDetailRow(row)}>
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {detailRow && (
        <div className="activityModalBackdrop" role="presentation" onClick={() => setDetailRow(null)}>
          <div className="activityModal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="activityModalHead">
              <div>
                <h2>Activity detail</h2>
                <p>{formatDate(detailRow.created_at)} / {actionLabel(detailRow.action)}</p>
              </div>
              <button className="activityBtn" type="button" onClick={() => setDetailRow(null)}>Close</button>
            </div>
            <div className="activityModalGrid">
              <span><small>Actor</small><strong>{detailRow.actor_username || 'system'}</strong></span>
              <span><small>Role</small><strong>{detailRow.actor_role || '-'}</strong></span>
              <span><small>Target</small><strong>{detailRow.target_type || '-'} / {detailRow.target_id || '-'}</strong></span>
              <span><small>Status</small><strong>{detailRow.status || 'success'}</strong></span>
            </div>
            <pre>{normalizeDetail(detailRow.detail) || 'No detail payload'}</pre>
          </div>
        </div>
      )}
    </ReportShell>
  );
}
