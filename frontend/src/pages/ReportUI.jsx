import React from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth, useIsAdmin } from '../auth';
import ProfileMenu from './ProfileMenu';
import { formatReportDate } from './reportUtils';
import './ReportUI.css';

export function ReportShell({ children, active = 'History' }) {
  const navigate = useNavigate();
  const admin = useIsAdmin();
  const items = [
    ['Home', '/home'],
    ['Scan', '/scan/new'],
    ['History', '/history'],
    ...(admin ? [['Agents', '/admin/agents'], ['Users', '/admin/users'], ['Activity', '/admin/activity']] : []),
  ];

  return (
    <div className="reportShell">
      <aside className="reportSidebar">
        <div>
          <button className="reportBrand" type="button" onClick={() => navigate('/home')}>
            <span className="reportBrandMark" aria-hidden="true">S</span>
            <span>SecureScan</span>
          </button>
          <nav className="reportNav" aria-label="Primary navigation">
            {items.map(([label, path]) => (
              <button
                type="button"
                key={path}
                className={active === label ? 'active' : ''}
                onClick={() => navigate(path)}
              >
                <span className="reportNavMark" />
                {label}
              </button>
            ))}
          </nav>
        </div>
        <button
          type="button"
          className="reportLogout"
          onClick={() => {
            clearAuth();
            navigate('/login');
          }}
        >
          Log out
        </button>
      </aside>
      <main className="reportMain">
        {children}
      </main>
    </div>
  );
}

export function ReportTopbar() {
  return (
    <header className="reportTopbar">
      <span>{formatReportDate()}</span>
      <ProfileMenu />
    </header>
  );
}

export function ReportHeader({
  eyebrow = 'Security report',
  title,
  subtitle,
  context = [],
  actions,
  score,
  scoreLabel = 'Compliance score',
}) {
  const numericScore = Math.max(0, Math.min(100, Number(score || 0)));
  return (
    <section className="reportHero">
      <div className="reportHeroMain">
        <span className="reportEyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
        {!!context.length && (
          <div className="reportContextRow">
            {context.filter((item) => item?.value).map((item) => (
              <span key={item.label}>
                <small>{item.label}</small>
                <strong>{item.value}</strong>
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="reportHeroSide">
        {score !== undefined && (
          <div className="reportScore" style={{ '--report-score': numericScore }}>
            <div>
              <strong>{Math.round(numericScore)}%</strong>
              <span>{scoreLabel}</span>
            </div>
          </div>
        )}
        {actions && <div className="reportActions">{actions}</div>}
      </div>
    </section>
  );
}

export function MetricGrid({ children }) {
  return <div className="reportMetricGrid">{children}</div>;
}

export function MetricCard({ label, value, hint, tone = 'neutral' }) {
  return (
    <div className={`reportMetric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </div>
  );
}

export function ReportPanel({ children, className = '' }) {
  return <section className={`reportPanel ${className}`}>{children}</section>;
}

export function PanelHeader({ title, subtitle, action }) {
  return (
    <div className="reportPanelHead">
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function StatusBadge({ children, tone = 'neutral' }) {
  return <span className={`reportBadge ${tone}`}>{children}</span>;
}
