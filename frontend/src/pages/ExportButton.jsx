/**
 * ExportButton.jsx
 * 
 * Export PDF / Excel button used by Result.jsx and History.jsx
 *
 * Props:
 *   scanId   {number}   scan ID in database
 *   label    {string}   button label (optional, default "Export")
 *   variant  {string}   "icon" | "full" (default "full")
 *
 * Usage in Result.jsx when scanId is available:
 *   <ExportButton scanId={scanData.scan_id} />
 *
 * Usage in History.jsx rows:
 *   <ExportButton scanId={h.id} variant="icon" />
 */

import React, { useState, useRef, useEffect } from 'react';
import { apiUrl } from '../config/api';

// Inline styles
const S = {
  wrap: {
    position: 'relative',
    display:  'inline-block',
  },
  btn: {
    display:        'inline-flex',
    alignItems:     'center',
    gap:            '6px',
    padding:        '7px 14px',
    borderRadius:   '8px',
    border:         '1px solid rgba(200,129,58,0.35)',
    background:     'rgba(200,129,58,0.08)',
    color:          '#c8813a',
    fontSize:       '13px',
    fontWeight:     600,
    cursor:         'pointer',
    whiteSpace:     'nowrap',
    transition:     'background 0.15s',
  },
  btnHover: {
    background: 'rgba(200,129,58,0.18)',
  },
  btnIcon: {
    padding:    '6px 8px',
    fontSize:   '12px',
  },
  btnLoading: {
    opacity: 0.65,
    cursor:  'not-allowed',
  },
  dropdown: {
    position:     'absolute',
    top:          'calc(100% + 4px)',
    right:        0,
    minWidth:     '140px',
    background:   '#fff',
    border:       '1px solid #e5e7eb',
    borderRadius: '8px',
    boxShadow:    '0 4px 16px rgba(0,0,0,0.10)',
    zIndex:       1000,
    overflow:     'hidden',
  },
  dropItem: {
    display:        'flex',
    alignItems:     'center',
    gap:            '8px',
    padding:        '9px 14px',
    fontSize:       '13px',
    color:          '#374151',
    cursor:         'pointer',
    transition:     'background 0.12s',
    border:         'none',
    background:     'transparent',
    width:          '100%',
    textAlign:      'left',
  },
  dropItemHover: {
    background: '#f3f4f6',
  },
  dropDivider: {
    height:     '1px',
    background: '#f3f4f6',
    margin:     '2px 0',
  },
  errorToast: {
    position:     'fixed',
    bottom:       '20px',
    right:        '20px',
    background:   '#dc2626',
    color:        '#fff',
    padding:      '10px 16px',
    borderRadius: '8px',
    fontSize:     '13px',
    zIndex:       9999,
    boxShadow:    '0 4px 12px rgba(0,0,0,0.15)',
  },
};

//  Icon components 
const IconChevron = () => (
  <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.8">
    <path d="M2 3.5l3 3 3-3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const IconPDF = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
    <rect x="2" y="1" width="10" height="12" rx="1.5" />
    <path d="M4 5h6M4 7.5h4M4 10h3" strokeLinecap="round" />
  </svg>
);

const IconExcel = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
    <rect x="2" y="1" width="10" height="12" rx="1.5" />
    <path d="M4 5h6M4 7.5h6M4 10h6" strokeLinecap="round" />
  </svg>
);

const IconSpinner = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.8"
    style={{ animation: 'spin 0.8s linear infinite' }}>
    <circle cx="6.5" cy="6.5" r="5" strokeOpacity="0.3" />
    <path d="M6.5 1.5a5 5 0 0 1 5 5" strokeLinecap="round" />
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
  </svg>
);

//  Main Component 
export default function ExportButton({ scanId, label = 'Export', variant = 'full', appearance = 'default' }) {
  const [open,        setOpen]        = useState(false);
  const [loading,     setLoading]     = useState(null); // 'pdf' | 'xlsx' | null
  const [hover,       setHover]       = useState(false);
  const [hoverItem,   setHoverItem]   = useState(null);
  const [errorMsg,    setErrorMsg]    = useState('');
  const wrapRef = useRef(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handler = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleExport = async (format) => {
    if (!scanId) {
      setErrorMsg('Missing scan ID. Please open a scan report before exporting.');
      setTimeout(() => setErrorMsg(''), 4000);
      return;
    }

    setOpen(false);
    setLoading(format);

    try {
      const token = localStorage.getItem('token') || '';
      const res   = await fetch(
        apiUrl(`/api/scan/history/${scanId}/export/${format}`),
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Export failed' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      // trigger download
      const blob     = await res.blob();
      const url      = URL.createObjectURL(blob);
      const a        = document.createElement('a');
      const ext      = format === 'pdf' ? 'pdf' : 'xlsx';
      a.href         = url;
      a.download     = `scan-report-${scanId}-${new Date().toISOString().slice(0, 10)}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

    } catch (err) {
      setErrorMsg(`Export ${format.toUpperCase()} failed: ${err.message}`);
      setTimeout(() => setErrorMsg(''), 5000);
    } finally {
      setLoading(null);
    }
  };

  const isLoading = loading !== null;

  const btnStyle = {
    ...S.btn,
    ...(appearance === 'report' ? {
      minHeight: '34px',
      padding: '7px 12px',
      borderRadius: '6px',
      border: '1px solid #dfe4ec',
      background: '#fff',
      color: '#172033',
      fontSize: '11px',
      fontWeight: 700,
    } : {}),
    ...(variant === 'icon' ? S.btnIcon : {}),
    ...(hover && !isLoading
      ? appearance === 'report'
        ? { background: '#eff6ff', borderColor: '#2563eb', color: '#2563eb' }
        : S.btnHover
      : {}),
    ...(isLoading ? S.btnLoading : {}),
  };

  return (
    <>
      <div style={S.wrap} ref={wrapRef}>
        <button
          style={btnStyle}
          onClick={() => !isLoading && setOpen((o) => !o)}
          onMouseEnter={() => setHover(true)}
          onMouseLeave={() => setHover(false)}
          disabled={isLoading}
          title="Export report"
        >
          {isLoading ? (
            <>
              <IconSpinner />
              {variant === 'full' && `Exporting ${loading.toUpperCase()}...`}
            </>
          ) : (
            <>
              {variant === 'full' && label}
              <IconChevron />
            </>
          )}
        </button>

        {open && !isLoading && (
          <div style={S.dropdown}>
            {/* PDF */}
            <button
              style={{
                ...S.dropItem,
                ...(hoverItem === 'pdf' ? S.dropItemHover : {}),
              }}
              onMouseEnter={() => setHoverItem('pdf')}
              onMouseLeave={() => setHoverItem(null)}
              onClick={() => handleExport('pdf')}
            >
              <IconPDF />
              Export as PDF
            </button>

            <div style={S.dropDivider} />

            {/* Excel */}
            <button
              style={{
                ...S.dropItem,
                ...(hoverItem === 'xlsx' ? S.dropItemHover : {}),
              }}
              onMouseEnter={() => setHoverItem('xlsx')}
              onMouseLeave={() => setHoverItem(null)}
              onClick={() => handleExport('xlsx')}
            >
              <IconExcel />
              Export as Excel
            </button>
          </div>
        )}
      </div>

      {/* Error toast */}
      {errorMsg && (
        <div style={S.errorToast} onClick={() => setErrorMsg('')}>
           {errorMsg}
        </div>
      )}
    </>
  );
}


