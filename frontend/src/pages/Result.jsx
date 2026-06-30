import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import './Result.css';
import { authHeaders, clearAuth } from '../auth';
import { apiUrl } from '../config/api';
import ExportButton from './ExportButton';
import {
  MetricCard,
  MetricGrid,
  ReportHeader,
  ReportShell,
  ReportTopbar,
  StatusBadge,
} from './ReportUI';
import { formatReportDate } from './reportUtils';

// -----------------------------------------------------------------------
// Severity classification
// -----------------------------------------------------------------------
const CRITICAL_KEYWORDS = ['remote desktop','lsa protection','credential','ntlm','kerberos','bitlocker'];
const HIGH_KEYWORDS = [
  'network access', 'network security', 'user rights', 'privilege',
  'logon', 'encryption', 'tls', 'ssl', 'rdp', 'rpc',
  'anonymous', 'guest', 'sam', 'domain member', 'impersonate',
  'user account control', 'restrict', 'audit', 'signing',
  'inactivity', 'force shutdown',
];
const MEDIUM_KEYWORDS = [
  'autoplay', 'autorun', 'internet explorer', 'smartscreen', 'activex',
  'printer', 'bluetooth', 'wifi', 'hotspot', 'ink workspace', 'xbox',
  'cortana', 'spotlight', 'toast', 'netbios', 'icmp', 'multicast',
];

function getSeverity(key) {
  const lower = key.toLowerCase();
  if (lower.includes('remote desktop')) return 'critical';
  if (lower.includes('bitlocker'))      return 'critical';
  if (lower.includes('lsa protection')) return 'critical';
  if (lower.includes('credential'))     return 'critical';
  if (lower.includes('account lockout')) return 'high';
  if (lower.includes('logon'))           return 'high';
  if (lower.startsWith('[advanced audit]')) return 'medium';
  if (lower.startsWith('[services]'))       return 'low';
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k)))     return 'high';
  if (MEDIUM_KEYWORDS.some(k => lower.includes(k)))   return 'medium';
  return 'low';
}

const SOLUTION_MAP = {
  'account lockout': { text: 'Open secpol.msc > Account Policies > Account Lockout Policy and update the setting to match the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy' },
  'password':        { text: 'Open secpol.msc > Account Policies > Password Policy and update the setting to match the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy' },
  'uac':             { text: 'Open secpol.msc > Local Policies > Security Options and review User Account Control settings.', link: 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/' },
  'firewall':        { text: 'Open Windows Defender Firewall (wf.msc) or Group Policy and update firewall settings.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/' },
  'audit':           { text: 'Open secpol.msc > Advanced Audit Policy Configuration and align audit settings with the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings' },
  'defender':        { text: 'Review Microsoft Defender settings in Group Policy or Windows Security.', link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows' },
  'ntlm':            { text: 'Open secpol.msc > Local Policies > Security Options and configure LAN Manager authentication level.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' },
  'smb':             { text: 'Review SMBv1 and SMB signing settings in Registry or Group Policy.', link: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' },
  'lsa':             { text: 'Enable LSA Protection in Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa > RunAsPPL = 1.', link: 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' },
  'remote desktop':  { text: 'Review RDP security in Group Policy > Remote Desktop Services.', link: 'https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-desktop-services' },
  'bitlocker':       { text: 'Open BitLocker Drive Encryption and align encryption settings with the baseline.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/' },
  'attack surface':  { text: 'Review Attack Surface Reduction rules in Microsoft Defender or Group Policy.', link: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference' },
  'smartscreen':     { text: 'Review Windows Defender SmartScreen settings in Group Policy.', link: 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/' },
  'autoplay':        { text: 'Open Group Policy > AutoPlay Policies and disable AutoPlay as required.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/turn-off-autoplay' },
  'user rights':     { text: 'Open secpol.msc > Local Policies > User Rights Assignment and update permissions.', link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment' },
};

function getSolution(key) {
  const lower = key.toLowerCase();
  for (const [keyword, sol] of Object.entries(SOLUTION_MAP)) {
    if (lower.includes(keyword)) return sol;
  }
  return {
    text: 'Review the setting in Group Policy Editor (gpedit.msc) or Local Security Policy (secpol.msc)',
    link: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings',
  };
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'var(--sev-critical)',    bg: 'var(--sev-critical-bg)',    bd: 'var(--sev-critical-bd)' },
  high:     { label: 'High',     color: 'var(--sev-high)',        bg: 'var(--sev-high-bg)',        bd: 'var(--sev-high-bd)' },
  medium:   { label: 'Medium',   color: 'var(--sev-medium)',      bg: 'var(--sev-medium-bg)',      bd: 'var(--sev-medium-bd)' },
  low:      { label: 'Low',      color: 'var(--sev-low)',         bg: 'var(--sev-low-bg)',         bd: 'var(--sev-low-bd)' },
};

const SCAN_STEPS = [
  'Preparing target connection...',
  'Loading Security Baseline...',
  'Checking Security Policy...',
  'Checking Audit Policy...',
  'Checking Registry Settings...',
  'Checking Firewall Rules...',
  'Checking Windows Defender...',
  'Checking Services...',
  'Calculating compliance score...',
  'Completed',
];

const SESSION_KEY = 'scanResult';

function normalizeSeverity(value) {
  const sev = String(value || 'low').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(sev) ? sev : 'low';
}

function normalizeText(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function comparisonKeyFromParts(item) {
  const settingParts = [
    item.policy_path ?? item.policyPath,
    item.registry_path ?? item.registryPath,
    item.check_name ?? item.name,
    item.category ?? item.section,
  ].map(normalizeText).filter(Boolean);
  if (settingParts.length) return settingParts.join('|');

  return [
    item.check_id ?? item.checkId,
    item.source_key ?? item.key,
    item.check_name ?? item.name,
    item.category ?? item.section,
  ].map(normalizeText).filter(Boolean).join('|');
}

function isNotConfigured(value) {
  const text = normalizeText(value);
  return text === 'not configured' || text.includes('not configured');
}

function isDisabledBaseline(value) {
  const text = normalizeText(value).replace(/[\s\]})>]+$/g, '').replace(/[.,;:]+$/g, '');
  return /^(disabled|disable|off|0|false|no|n\/a)(\b|$)/.test(text);
}

function classifyStatus(rawStatus, targetValue = '', actualValue = '', rawResult = '') {
  const raw = normalizeText(rawStatus);
  const target = normalizeText(targetValue);
  const actual = normalizeText(actualValue);
  const result = normalizeText(rawResult);

  if (raw.includes('manual') || result.includes('manual')) return 'manual';

  if (isNotConfigured(actual) || result.includes('not configured')) {
    return isDisabledBaseline(target) ? 'pass' : 'fail';
  }

  if (raw === 'pass' || raw.includes('pass')) return 'pass';

  if (target && actual && target === actual) return 'pass';

  return 'fail';
}

function parseFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.map((item) => {
    const targetValue = item.expected_value || '';
    const actualValue = item.current_value || 'Not Configured';
    
    // Prefer status from backend when available
    const rawStatus = String(item.status || '').toLowerCase();
    let status;
    if (rawStatus === 'pass') {
      status = 'pass';
    } else if (rawStatus.startsWith('fail')) {
      status = 'fail';
    } else if (rawStatus.includes('manual')) {
      status = 'manual';
    } else {
      status = 'fail';
    }

    const solutionKey = `${item.category || ''} ${item.check_name || ''} ${item.source_key || ''}`.trim();
    const fallbackSolution = getSolution(solutionKey);
    return {
      key: item.source_key || item.check_id || item.check_name,
      checkId: item.check_id || '',
      name: item.check_name || item.source_key || 'Unknown check',
      section: item.category || 'General',
      severity: normalizeSeverity(item.severity),
      solution: {
        text: item.remediation || fallbackSolution.text,
        link: fallbackSolution.link,
      },
      target: targetValue,
      actual: actualValue,
      status,
      raw: item.raw_result || '',
      policyPath: item.policy_path || '',
      registryPath: item.registry_path || '',
      comparisonKey: item.comparison_key || comparisonKeyFromParts(item),
      autofixSupported: Boolean(item.autofix_supported),
      autofixReason: item.autofix_reason || '',
      autofixAction: item.autofix_action || '',
      autofixNeedsInput: Boolean(item.autofix_needs_input),
      autofixAllowedValues: Array.isArray(item.autofix_allowed_values) ? item.autofix_allowed_values : [],
      autofixDefaultValue: item.autofix_default_value || '',
      autofixSubcategory: item.autofix_subcategory || '',
      autofixServiceName: item.autofix_service_name || '',
      autofixFirewallProfile: item.autofix_firewall_profile || '',
      autofixSecurityPolicyKey: item.autofix_security_policy_key || '',
      autofixPrivilegeName: item.autofix_privilege_name || '',
      autofixPrivilegeAccounts: Array.isArray(item.autofix_privilege_accounts) ? item.autofix_privilege_accounts : [],
      autofixRegistryEntries: Array.isArray(item.autofix_registry_entries) ? item.autofix_registry_entries : [],
      autofixTool: item.autofix_tool || '',
      autofixGroup: item.autofix_group || '',
      autofixGroupLabel: item.autofix_group_label || '',
      autofixStep: Number(item.autofix_step || 0),
      autofixDependsOn: Array.isArray(item.autofix_depends_on) ? item.autofix_depends_on : [],
      autofixDependencyNote: item.autofix_dependency_note || '',
      source: item.source || {},
    };
  });
}

function isSimpleAutofixValue(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  const lower = text.toLowerCase();
  if (text.includes('\n') || text.includes('\r') || text.includes(';')) return false;
  if (lower.startsWith('enabled:') || lower.startsWith('disabled:')) return false;
  if (/[{}\[\]]/.test(text)) return false;
  return true;
}

function inferAutofixSupport(item) {
  if (!item || item.status !== 'fail') return { supported: false, reason: 'not a failed check' };
  const haystack = `${item.section || ''} ${item.policyPath || ''} ${item.name || ''} ${item.key || ''}`.toLowerCase();
  const startupValues = ['Automatic', 'Manual', 'Disabled'];
  const firewallTarget = normalizeText(item.target);
  if (
    haystack.includes('firewall')
    && normalizeText(item.name) === 'firewall state'
    && ['on', 'off', 'enabled', 'disabled'].includes(firewallTarget)
  ) {
    const profileName = String(item.policyPath || '').split('\\')[0].trim().toLowerCase();
    const profile = profileName.includes('domain') ? 'domain'
      : profileName.includes('private') ? 'private'
      : profileName.includes('public') ? 'public'
      : '';
    if (profile) {
      return {
        supported: true,
        reason: '',
        action: 'firewall_profile',
        needsInput: !['on', 'off', 'enabled', 'disabled'].includes(firewallTarget),
        allowedValues: ['on', 'off', 'enabled', 'disabled'].includes(firewallTarget) ? [] : ['On', 'Off'],
        defaultValue: ['on', 'enabled'].includes(firewallTarget) ? 'On' : 'Off',
        firewallProfile: profile,
      };
    }
  }
  if (haystack.includes('advanced audit') || haystack.includes('audit policy') || haystack.includes('audit policies')) {
    const auditValues = ['Success', 'Failure', 'Success and Failure', 'No Auditing'];
    const auditDefault = auditValues.find((value) => value.toLowerCase() === String(item.target || '').trim().toLowerCase()) || '';
    return {
      supported: true,
      reason: '',
      action: 'audit_policy',
      needsInput: !auditDefault,
      allowedValues: auditDefault ? [] : auditValues,
      defaultValue: auditDefault || 'Success',
    };
  }
  const source = item.source || {};
  const serviceDefault = startupValues.find((value) => value.toLowerCase() === String(item.target || '').trim().toLowerCase()) || '';
  if (
    serviceDefault
    && (
      String(source.sheet_type || '').toLowerCase() === 'services'
      || (
        !item.registryPath
        && String(item.section || '').toLowerCase() === 'services & features'
        && ['', 'system services'].includes(String(item.policyPath || '').toLowerCase())
      )
    )
  ) {
    return {
      supported: true,
      reason: '',
      action: 'service_startup',
      needsInput: true,
      allowedValues: startupValues,
      defaultValue: serviceDefault,
    };
  }
  if ((haystack.includes('password policy') || haystack.includes('account lockout')) && isSimpleAutofixValue(item.target)) {
    return {
      supported: true,
      reason: '',
      action: 'security_policy',
      needsInput: false,
      allowedValues: [],
      defaultValue: item.target,
    };
  }
  const unsupported = [
    'user rights',
    'user rights assignment',
    'windows defender',
    'defender',
    'service',
    'services',
  ];
  if (unsupported.some((keyword) => haystack.includes(keyword))) return { supported: false, reason: 'unsupported policy type' };
  if (!item.registryPath) return { supported: false, reason: 'no registry path' };
  if (!parseRegistryLocationEntries(item.registryPath).length) return { supported: false, reason: 'unsupported registry path' };
  if (!isSimpleAutofixValue(item.target)) return { supported: false, reason: 'ambiguous expected value' };
  return { supported: true, reason: '', action: 'registry', needsInput: false, allowedValues: [], defaultValue: '' };
}

function firewallProfileLabel(item) {
  const profile = String(item?.autofixFirewallProfile || '').trim().toLowerCase();
  if (profile) return `${profile.charAt(0).toUpperCase()}${profile.slice(1)} Profile`;
  const pathProfile = String(item?.policyPath || '').split('\\')[0].trim();
  if (/^(domain|private|public) profile$/i.test(pathProfile)) return pathProfile;
  return '';
}

function displayCheckName(item) {
  if ((item?.autofixAction === 'firewall_profile' || normalizeText(item?.name) === 'firewall state')) {
    const profile = firewallProfileLabel(item);
    if (profile) return `${profile} - ${item.name}`;
  }
  return item?.name || 'Unknown check';
}

function formatAutofixReason(reason, item = {}) {
  const normalized = String(reason || '').toLowerCase();
  if (!normalized) return 'Manual fix required.';
  if (normalized.includes('no registry path')) {
    return 'Manual fix required: this baseline check does not include a registry location that the agent can change safely.';
  }
  if (normalized.includes('defender command')) {
    return 'Manual fix required: this Defender setting needs a command-based allowlist before it can be automated safely.';
  }
  if (normalized.includes('complex multi-value') || normalized.includes('multi-line') || normalized.includes('multi-value')) {
    return 'Manual fix required: this setting contains complex multi-value policy data that is not safely mapped to individual values yet.';
  }
  if (normalized.includes('unsupported registry')) {
    return 'Manual fix required: the registry location is not in a supported key/value format.';
  }
  if (normalized.includes('ambiguous') || normalized.includes('expected value')) {
    return 'Manual fix required: the required value is complex or ambiguous, so the agent will not guess the setting.';
  }
  if (normalized.includes('account cannot be resolved')) {
    return `Manual fix required: ${reason}. Use a supported local group/SID or update the baseline value.`;
  }
  if (normalized.includes('security policy value') || normalized.includes('security policy key')) {
    return 'Manual fix required: this password/account policy is outside the current secedit allowlist.';
  }
  if (normalized.includes('user-right') || normalized.includes('user right')) {
    return 'Manual fix required: this user-right assignment is complex or outside the safe account allowlist.';
  }
  if (normalized.includes('unsupported policy')) {
    const section = String(item.section || '').toLowerCase();
    if (section.includes('password') || section.includes('account')) {
      return 'Manual fix required: password and account policy changes need Windows security policy tooling and safer rollback handling.';
    }
    if (section.includes('user rights')) {
      return 'Manual fix required: user-right assignments require security template handling and are not enabled for v1 autofix.';
    }
    if (section.includes('defender')) {
      return 'Manual fix required: Defender command-based changes are intentionally allowlisted later to avoid changing the wrong protection setting.';
    }
    return 'Manual fix required: this policy type needs a dedicated Windows tool or a curated handler before it can be safely automated.';
  }
  return `Manual fix required: ${reason}.`;
}

function parseResults(details, findings = null) {
  const enriched = parseFindings(findings);
  if (enriched.length > 0) return enriched;
  if (!details) return [];
  return Object.entries(details)
    .filter(([key]) => !String(key).startsWith('_'))
    .map(([key, value]) => {
      const sectionMatch = key.match(/^\[([^\]]+)\]/);
      const section  = sectionMatch ? sectionMatch[1] : 'General';
      const name     = key.replace(/^\[[^\]]+\]\s*/, '');
      const severity = getSeverity(key);
      const solution = getSolution(key);

      const raw = String(value);
      let target = '', actual = '';

      const targetMatch = raw.match(/Target:\s*([^,)]+?)(?:\s*,|\s*\)|$)/);
      if (targetMatch) target = targetMatch[1].trim();

      const actualMatch = raw.match(/Actual:\s*(.+?)(?:\s*\)\s*$|\s*$)/);
      if (actualMatch) actual = actualMatch[1].trim().replace(/\)\s*$/, '');

      const status = classifyStatus(raw, target, actual, raw);

      return {
        key,
        name,
        section,
        severity,
        solution,
        target,
        actual,
        status,
        raw,
        comparisonKey: comparisonKeyFromParts({ key, name, section }),
      };
    });
}

function parseRegistryLocationEntries(registryPath) {
  return String(registryPath || '')
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const bangIndex = entry.indexOf('!');
      if (bangIndex === -1) return { keyPath: entry, valueName: '' };
      return {
        keyPath: entry.slice(0, bangIndex).trim(),
        valueName: entry.slice(bangIndex + 1).trim(),
      };
    });
}

function getPolicyTool(policyPath = '', section = '', name = '') {
  const text = `${policyPath} ${section} ${name}`.toLowerCase();
  if (
    text.includes('password policy') ||
    text.includes('account lockout') ||
    text.includes('user rights') ||
    text.includes('security options') ||
    text.includes('audit policy') ||
    text.includes('local policies')
  ) {
    return 'secpol.msc';
  }
  if (text.includes('firewall')) return 'wf.msc';
  return 'gpedit.msc';
}

function buildSettingLocationGuide(item, context = {}) {
  if (!item || item.status !== 'fail') return { available: false };

  const policyPath = String(item.policyPath || '').trim();
  const registryEntries = parseRegistryLocationEntries(item.registryPath);
  const hasRegistry = registryEntries.length > 0;
  if (!policyPath && !hasRegistry) return { available: false };

  const openTool = policyPath ? getPolicyTool(policyPath, item.section, item.name) : 'regedit.exe';
  const lines = [
    `Target: ${context.hostname || context.targetName || 'Target machine'}`,
    `Check ID: ${item.checkId || item.key || '-'}`,
    `Check Name: ${item.name || '-'}`,
    `Open Tool: ${openTool}`,
  ];

  if (policyPath) lines.push(`Policy Path: ${policyPath}`);
  registryEntries.forEach((entry, index) => {
    const label = registryEntries.length > 1 ? `Registry ${index + 1}` : 'Registry';
    lines.push(`${label} Key: ${entry.keyPath}`);
    if (entry.valueName) lines.push(`${label} Value: ${entry.valueName}`);
  });
  lines.push(`Required Value: ${item.target || '-'}`);
  lines.push(`Current Value: ${item.actual || 'Not Configured'}`);
  lines.push(`Solution: ${item.solution?.text || '-'}`);

  return {
    available: true,
    openTool,
    policyPath,
    registryEntries,
    copyText: lines.join('\n'),
  };
}

// -----------------------------------------------------------------------
// Layout  matches Home sidebar exactly
// -----------------------------------------------------------------------
function Layout({ children }) {
  return <ReportShell active="History">{children}</ReportShell>;
}

// -----------------------------------------------------------------------
// Topbar  matches Home topbar
// -----------------------------------------------------------------------
function Topbar() {
  return <ReportTopbar />;
}

// -----------------------------------------------------------------------
// ScanProgress
// -----------------------------------------------------------------------
function ScanProgress({ scanParams, onScanComplete, onError }) {
  const navigate   = useNavigate();
  const hasFetched = useRef(false);

  const [progress,  setProgress]  = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const [statusMessage, setStatusMessage] = useState(SCAN_STEPS[0]);
  const pollRef = useRef(null);

  useEffect(() => {
    if (hasFetched.current) return;
    hasFetched.current = true;
    const endpoint = scanParams._mode === 'agent'
      ? apiUrl('/api/scan/agent')
      : scanParams._mode === 'agent-subnet'
      ? apiUrl('/api/scan/agent-subnet')
      : scanParams._mode === 'subnet'
      ? apiUrl('/api/scan/subnet')
      : apiUrl('/api/scan/remote');

    fetch(endpoint, {
      method:  'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(
        scanParams._mode === 'agent'
          ? { agent_id: scanParams.agent_id, version: scanParams.version, role: scanParams.role }
          : scanParams._mode === 'agent-subnet'
          ? { subnet: scanParams.subnet, version: scanParams.version, role: scanParams.role }
          : scanParams._mode === 'subnet'
          ? {
              subnet:        scanParams.subnet,
              username:      scanParams.username,
              password:      scanParams.password,
              version:       scanParams.version,
              role:          scanParams.role,
              use_ssl:       scanParams.use_ssl,
              skip_ca_check: scanParams.skip_ca_check,
              max_parallel:  scanParams.max_parallel,
            }
          : scanParams
      ),
    })
      .then((r) => {
        if (r.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || 'Scan failed'));
        return r.json();
      })
      .then(({ job_id }) => {
        pollRef.current = setInterval(async () => {
          try {
            const res = await fetch(apiUrl(`/api/scan/status/${job_id}`), {
              headers: authHeaders(),
            });

            if (res.status === 401) {
              clearInterval(pollRef.current);
              clearAuth();
              navigate('/login');
              return;
            }

            if (res.status === 404) {
              clearInterval(pollRef.current);
              onError('Job or scan no longer exists');
              return;
            }

            if (!res.ok) throw new Error('Status check failed');
            const data = await res.json();
            const status = data.status;

            if (data.message) {
              setStatusMessage(data.message);
            }

            if (typeof data.progress === 'number') {
              const nextProgress = Math.max(0, Math.min(100, data.progress));
              setProgress(nextProgress);
              if (status === 'done') {
                setStepIndex(SCAN_STEPS.length - 1);
              } else {
                const maxIdx = SCAN_STEPS.length - 2;
                const idx = Math.min(maxIdx, Math.floor((nextProgress / 100) * (SCAN_STEPS.length - 1)));
                setStepIndex(idx);
              }
            } else if (status === 'done') {
              setStepIndex(SCAN_STEPS.length - 1);
            }

            if (status === 'done') {
              clearInterval(pollRef.current);
              setProgress(100);
              setStepIndex(SCAN_STEPS.length - 1);
              setStatusMessage(data.message || SCAN_STEPS[SCAN_STEPS.length - 1]);

              const r = data.result;

              if (scanParams._mode === 'subnet' || scanParams._mode === 'agent-subnet') {
                const subnetResult = {
                  isSubnet:    true,
                  subnet:      r.subnet,
                  total:       r.total,
                  discovered_hosts: r.discovered_hosts,
                  success_count: r.success_count,
                  failed_count:  r.failed_count,
                  results:     r.results || [],
                  version:     scanParams.version,
                  targetName:  scanParams.target_name,
                  scan_id:     r.scan_id,
                };
                sessionStorage.setItem(SESSION_KEY, JSON.stringify(subnetResult));
                onScanComplete(subnetResult);
                return;
              }

              if (!r || !r.details) { onError('Scan result is incomplete'); return; }

              const result = {
                score:      r.score,
                details:    r.details || {},
                findings:   r.findings || [],
                summary:    r.summary || null,
                score_breakdown: r.score_breakdown || r.details?._score_breakdown || null,
                targetName: r.target_name || scanParams.target_name,
                hostname:   scanParams.host,
                agent_id:   r.agent_id || scanParams.agent_id || '',
                version:    r.version || scanParams.version,
                scan_id:    r.scan_id,
                scan_date:  r.scan_date || new Date().toISOString(),
              };
              sessionStorage.setItem(SESSION_KEY, JSON.stringify(result));
              setTimeout(() => onScanComplete(result), 600);

            } else if (status === 'error') {
              clearInterval(pollRef.current);
              setStatusMessage(data.message || data.error || 'Scan failed');
              onError(data.error || 'Scan failed');
            }
          } catch (e) {
            clearInterval(pollRef.current);
            onError('Unable to connect to server');
          }
        }, 2000);
      })
      .catch((err) => {
        onError(typeof err === 'string' ? err : 'Unable to start scan');
      });

    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const circumference = 2 * Math.PI * 42; // r=42

  return (
    <div className="scanProgressWrap">
      <div className="scoreCircleWrap">
        <svg viewBox="0 0 100 100" className="scoreCircleSvg">
          <circle cx="50" cy="50" r="42" className="scoreTrack" />
          <circle
            cx="50" cy="50" r="42"
            className="scoreArc"
            strokeDasharray={`${(progress / 100) * circumference} ${circumference}`}
            transform="rotate(-90 50 50)"
            style={{ stroke: 'var(--amber)' }}
          />
        </svg>
        <div className="scoreText">{progress}%</div>
      </div>
      <div className="scanStepMsg">{statusMessage || SCAN_STEPS[stepIndex]}</div>
      <div className="scanBarWrap">
        <div className="scanBar" style={{ width: `${progress}%` }} />
      </div>
      <div className="scanDots">
        {SCAN_STEPS.slice(0, -1).map((_, i) => (
          <div
            key={i}
            className="scanDot"
            style={{ background: i <= stepIndex ? 'var(--amber)' : undefined }}
          />
        ))}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Main Result component
// -----------------------------------------------------------------------
export default function Result() {
  const navigate = useNavigate();
  const location = useLocation();
  const { id: routeScanId } = useParams();

  const scanParamsRef = useRef(null);

  const [phase, setPhase] = useState(() => {
    if (location.state?.scanParams) {
      scanParamsRef.current = location.state.scanParams;
      window.history.replaceState({}, document.title);
      return 'scanning';
    }
    if (location.state?.fromHistory) return 'done';
    
    // Always load history route from backend when opening /scan/:id/report
    if (routeScanId && location.pathname.toLowerCase().endsWith('/report')) {
      return 'loading-history';
    }
    
    if (sessionStorage.getItem(SESSION_KEY)) return 'done';
    return 'redirect';
  });

  const [scanData, setScanData] = useState(() => {
    if (location.state?.fromHistory) return location.state.fromHistory;
    // Do not use sessionStorage for direct history route
    if (routeScanId && location.pathname.toLowerCase().endsWith('/report')) return null;
    const saved = sessionStorage.getItem(SESSION_KEY);
    return saved ? JSON.parse(saved) : null;
  });

  const [errorMsg,      setErrorMsg]      = useState('');
  const [activeTab,     setActiveTab]     = useState('ALL');
  const [searchInput,   setSearchInput]   = useState('');
  const [search,        setSearch]        = useState('');
  const [expanded,      setExpanded]      = useState(null);
  const [sectionFilter, setSectionFilter] = useState('ALL');
  const [statusFilter,  setStatusFilter]  = useState('ALL');
  const [autofixFilter, setAutofixFilter] = useState('ALL');
  const [copiedLocation, setCopiedLocation] = useState('');
  const [selectedAutofix, setSelectedAutofix] = useState(new Set());
  const [autofixModalOpen, setAutofixModalOpen] = useState(false);
  const [autofixStatus, setAutofixStatus] = useState(null);
  const [autofixSubmitting, setAutofixSubmitting] = useState(false);
  const [autofixInputs, setAutofixInputs] = useState({});
  const [autofixJobs, setAutofixJobs] = useState([]);
  const [autofixHistoryOpen, setAutofixHistoryOpen] = useState(false);
  const [autofixCoverageOpen, setAutofixCoverageOpen] = useState(false);
  const [detailTabs, setDetailTabs] = useState({});
  const [rollbackJob, setRollbackJob] = useState(null);
  const [rollbackSubmitting, setRollbackSubmitting] = useState(false);

  useEffect(() => {
    if (phase === 'redirect') navigate('/home', { replace: true });
  }, [phase]);

  useEffect(() => {
    if (!routeScanId || !location.pathname.toLowerCase().endsWith('/report')) return;
    if (location.state?.fromHistory) return;
    setScanData(null);
    setPhase('loading-history');
  }, [routeScanId, location.pathname, location.state]);

  useEffect(() => {
    if (phase !== 'loading-history' || !routeScanId) return;

    fetch(apiUrl(`/api/scan/history/${routeScanId}`), {
      headers: authHeaders(),
    })
      .then((res) => {
        if (res.status === 401) {
          clearAuth();
          navigate('/login');
          return Promise.reject('Not authenticated');
        }
        if (!res.ok) return res.json().then((e) => Promise.reject(e.detail || 'Report not found'));
        return res.json();
      })
      .then((data) => {
        const details = data.details || {};
        const subnetResults = Array.isArray(details.results) ? details.results : [];
        if (data.scan_type === 'subnet') {
          setScanData({
            isSubnet: true,
            subnet: details.subnet || data.hostname || data.target_name,
            total: subnetResults.length,
            discovered_hosts: details.discovered_hosts,
            success_count: subnetResults.filter((r) => r.status === 'done').length,
            failed_count: subnetResults.filter((r) => r.status === 'error').length,
            results: subnetResults,
            targetName: data.target_name,
            hostname: data.hostname || '',
            version: data.version || '',
            scan_id: data.id,
          });
          setPhase('done');
          return;
        }

        setScanData({
          score:      data.score,
          details,
          findings:   data.findings || [],
          summary:    data.summary || null,
          score_breakdown: data.score_breakdown || details?._score_breakdown || null,
          targetName: data.target_name,
          hostname:   data.hostname || '',
          agent_id:   data.agent_id || '',
          version:    data.version || '',
          scan_id:    data.id,
          scan_date:  data.scan_date || '',
          parent_scan_id: data.parent_scan_id,
        });
        setPhase('done');
      })
      .catch((err) => {
        setErrorMsg(typeof err === 'string' ? err : 'Unable to load report');
        setPhase('error');
      });
  }, [phase, routeScanId, navigate]);

  const tabs = ['ALL', 'critical', 'high', 'medium', 'low'];
  const handleSearch = () => setSearch(searchInput);
  const handleClear  = () => { setSearchInput(''); setSearch(''); };
  const copyTextToClipboard = async (text) => {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  };

  const handleCopyLocation = async (key, text) => {
    try {
      await copyTextToClipboard(text);
      setCopiedLocation(key);
      setTimeout(() => setCopiedLocation(''), 1800);
    } catch (err) {
      setErrorMsg(`Unable to copy location: ${err.message}`);
    }
  };

  const loadAutofixJobs = async (scanId) => {
    if (!scanId) return;
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${scanId}/autofix-jobs`), {
        headers: authHeaders(),
      });
      if (res.status === 401) {
        clearAuth();
        navigate('/login');
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      setAutofixJobs(Array.isArray(data) ? data : []);
    } catch {
      // Autofix history is helpful, but it should not block report rendering.
    }
  };

  const {
    score      = 0,
    details    = {},
    findings   = [],
    hostname   = '',
    targetName = '',
    version    = '',
    scan_date: scanDate = '',
    score_breakdown: scoreBreakdown = null,
  } = scanData || {};

  useEffect(() => {
    const scanId = scanData?.scan_id || routeScanId;
    if (phase === 'done' && scanId) {
      loadAutofixJobs(scanId);
    }
  }, [phase, scanData?.scan_id, routeScanId]);

  const allItems = useMemo(() => parseResults(details, findings).map((item) => {
    const fallback = inferAutofixSupport(item);
    const hasBackendFlag = typeof item.autofixSupported === 'boolean' && item.autofixSupported;
    const allowedValues = item.autofixAllowedValues?.length ? item.autofixAllowedValues : (fallback.allowedValues || []);
    const defaultValue = item.autofixDefaultValue || fallback.defaultValue || '';
    return {
      ...item,
      autofixSupported: hasBackendFlag || fallback.supported,
      autofixReason: hasBackendFlag ? '' : (item.autofixReason || fallback.reason),
      autofixAction: item.autofixAction || fallback.action || '',
      autofixNeedsInput: Boolean(item.autofixNeedsInput || fallback.needsInput),
      autofixAllowedValues: allowedValues,
      autofixDefaultValue: defaultValue,
      autofixFirewallProfile: item.autofixFirewallProfile || fallback.firewallProfile || '',
      autofixSecurityPolicyKey: item.autofixSecurityPolicyKey || '',
      autofixPrivilegeName: item.autofixPrivilegeName || '',
      autofixPrivilegeAccounts: item.autofixPrivilegeAccounts || [],
      autofixRegistryEntries: item.autofixRegistryEntries || [],
      autofixTool: item.autofixTool || '',
      autofixGroup: item.autofixGroup || '',
      autofixGroupLabel: item.autofixGroupLabel || '',
      autofixStep: item.autofixStep || 0,
      autofixDependsOn: item.autofixDependsOn || [],
      autofixDependencyNote: item.autofixDependencyNote || '',
      displayName: displayCheckName({
        ...item,
        autofixAction: item.autofixAction || fallback.action || '',
        autofixFirewallProfile: item.autofixFirewallProfile || fallback.firewallProfile || '',
      }),
    };
  }), [details, findings]);

  useEffect(() => {
    if (!allItems.length) return;
    const requestedCheck = new URLSearchParams(location.search).get('check');
    if (!requestedCheck) return;
    const normalizedCheck = normalizeText(requestedCheck);
    const item = allItems.find((row) => (
      String(row.checkId || '') === requestedCheck
      || String(row.key || '') === requestedCheck
      || normalizeText(row.comparisonKey) === normalizedCheck
      || normalizeText(row.checkId) === normalizedCheck
      || normalizeText(row.key) === normalizedCheck
    ));
    if (!item) return;
    setActiveTab('ALL');
    setStatusFilter('ALL');
    setSectionFilter('ALL');
    setAutofixFilter('ALL');
    setSearchInput('');
    setSearch('');
    setExpanded(item.key);
    setDetailTabs((current) => ({ ...current, [item.key]: 'details' }));
    window.setTimeout(() => {
      document.getElementById(`finding-${item.key}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 120);
  }, [allItems, location.search]);

  useEffect(() => {
    setSelectedAutofix((prev) => {
      if (!prev.size) return prev;
      const valid = new Set(allItems.filter((item) => item.autofixSupported).map((item) => item.checkId || item.key));
      const next = new Set([...prev].filter((key) => valid.has(key)));
      return next.size === prev.size ? prev : next;
    });
  }, [allItems]);

  const sections = useMemo(() => {
    const s = new Set(allItems.map((i) => i.section));
    return ['ALL', ...Array.from(s)];
  }, [allItems]);

  const filtered = useMemo(() => allItems.filter((item) => {
    const matchTab     = activeTab === 'ALL' || item.severity === activeTab;
    const matchSection = sectionFilter === 'ALL' || item.section === sectionFilter;
    const matchStatus  = statusFilter === 'ALL' || item.status === statusFilter;
    const reviewRequiredActions = ['service_startup', 'firewall_profile', 'security_policy', 'user_rights', 'registry_multi', 'defender_registry'];
    const matchAutofix = autofixFilter === 'ALL'
      || (autofixFilter === 'available' && item.autofixSupported)
      || (autofixFilter === 'needs-input' && item.autofixSupported && item.autofixNeedsInput)
      || (autofixFilter === 'review' && item.autofixSupported && reviewRequiredActions.includes(item.autofixAction))
      || (autofixFilter === 'manual' && item.status === 'fail' && !item.autofixSupported);
    const matchSearch  = !search
      || (item.displayName || item.name).toLowerCase().includes(search.toLowerCase())
      || item.name.toLowerCase().includes(search.toLowerCase())
      || item.section.toLowerCase().includes(search.toLowerCase());
    return matchTab && matchSection && matchStatus && matchAutofix && matchSearch;
  }), [allItems, activeTab, sectionFilter, statusFilter, autofixFilter, search]);

  const counts = useMemo(() => {
    const c = { ALL: allItems.length, critical: 0, high: 0, medium: 0, low: 0 };
    allItems.forEach((i) => c[i.severity]++);
    return c;
  }, [allItems]);

  const passCount  = allItems.filter((v) => v.status === 'pass').length;
  const failCount  = allItems.filter((v) => v.status === 'fail').length;
  const manualCount = allItems.filter((v) => v.status === 'manual').length;
  const failedSeverityCounts = allItems.reduce((result, item) => {
    if (item.status === 'fail') result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
  const totalCount = allItems.length || Object.values(details).length;
  const autofixableItems = allItems.filter((item) => item.autofixSupported);
  const selectedAutofixItems = autofixableItems.filter((item) => selectedAutofix.has(item.checkId || item.key));
  const autofixItemByKey = useMemo(() => {
    const map = new Map();
    allItems.forEach((item) => {
      [item.checkId, item.key, item.name].filter(Boolean).forEach((key) => map.set(String(key), item));
    });
    return map;
  }, [allItems]);
  const missingAutofixDependencies = useMemo(() => {
    const missing = [];
    const seen = new Set();
    selectedAutofixItems.forEach((item) => {
      (item.autofixDependsOn || []).forEach((depKey) => {
        const dependency = autofixItemByKey.get(String(depKey));
        const selectedKey = dependency ? (dependency.checkId || dependency.key) : depKey;
        if (!dependency || selectedAutofix.has(selectedKey)) return;
        if (dependency.status !== 'fail') return;
        const stableKey = String(selectedKey);
        if (seen.has(stableKey)) return;
        seen.add(stableKey);
        missing.push({
          dependency,
          dependent: item,
          key: stableKey,
        });
      });
    });
    return missing;
  }, [autofixItemByKey, selectedAutofix, selectedAutofixItems]);
  const orderedSelectedAutofixItems = useMemo(() => {
    return [...selectedAutofixItems].sort((a, b) => {
      const groupCompare = String(a.autofixGroup || '').localeCompare(String(b.autofixGroup || ''));
      if (groupCompare) return groupCompare;
      const stepCompare = (a.autofixStep || 99) - (b.autofixStep || 99);
      if (stepCompare) return stepCompare;
      return String(a.displayName || a.name).localeCompare(String(b.displayName || b.name));
    });
  }, [selectedAutofixItems]);
  const hasFailingAutofixDependency = (item) => {
    return (item.autofixDependsOn || []).some((depKey) => {
      const dependency = autofixItemByKey.get(String(depKey));
      return dependency?.status === 'fail';
    });
  };
  const autofixCoverage = useMemo(() => {
    const failed = allItems.filter((item) => item.status === 'fail');
    const byType = {
      registry: 0,
      security_policy: 0,
      user_rights: 0,
      registry_multi: 0,
      defender_registry: 0,
      audit_policy: 0,
      service_startup: 0,
      firewall_profile: 0,
      manual: 0,
    };
    failed.forEach((item) => {
      if (!item.autofixSupported) {
        byType.manual += 1;
        return;
      }
      const action = item.autofixAction || 'registry';
      byType[action] = (byType[action] || 0) + 1;
    });
    return {
      failedCount: failed.length,
      availableCount: failed.filter((item) => item.autofixSupported).length,
      needsInputCount: failed.filter((item) => item.autofixSupported && item.autofixNeedsInput).length,
      reviewRequiredCount: failed.filter((item) => item.autofixSupported && ['service_startup', 'firewall_profile', 'security_policy', 'user_rights', 'registry_multi', 'defender_registry'].includes(item.autofixAction)).length,
      manualCount: failed.filter((item) => !item.autofixSupported).length,
      byType,
    };
  }, [allItems]);
  const completedAutofixJobs = autofixJobs.filter((job) => (job.success_count || 0) > 0 || job.job_type === 'rollback');
  const failedAutofixJobs = autofixJobs.filter((job) => (job.success_count || 0) === 0 && job.job_type !== 'rollback');

  const toggleAutofixSelection = (item) => {
    const key = item.checkId || item.key;
    if (!item.autofixSupported || !key) return;
    setSelectedAutofix((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
        if (item.autofixNeedsInput && item.autofixDefaultValue) {
          setAutofixInputs((current) => ({ ...current, [key]: current[key] || item.autofixDefaultValue }));
        }
      }
      return next;
    });
  };

  const selectRequiredAutofixDependencies = () => {
    if (!missingAutofixDependencies.length) return;
    setSelectedAutofix((prev) => {
      const next = new Set(prev);
      missingAutofixDependencies.forEach(({ dependency, key }) => {
        if (!dependency?.autofixSupported) return;
        next.add(key);
        if (dependency.autofixNeedsInput && dependency.autofixDefaultValue) {
          setAutofixInputs((current) => ({
            ...current,
            [key]: current[key] || dependency.autofixDefaultValue,
          }));
        }
      });
      return next;
    });
  };

  const getAutofixApplyValue = (item) => {
    const key = item.checkId || item.key;
    return item.autofixNeedsInput
      ? (autofixInputs[key] || item.autofixDefaultValue || item.target || '')
      : (item.autofixDefaultValue || item.target || '');
  };

  const describeAutofixPlan = (item) => {
    const action = item.autofixAction || 'registry';
    const value = getAutofixApplyValue(item);
    if (action === 'audit_policy') {
      return {
        type: 'Audit policy',
        target: item.autofixSubcategory || item.displayName || item.name,
        apply: value,
        rollback: 'Previous audit setting will be captured when the agent runs.',
      };
    }
    if (action === 'service_startup') {
      return {
        type: 'Service startup',
        target: item.autofixServiceName || item.displayName || item.name,
        apply: value,
        rollback: 'Previous service startup type will be captured when the agent runs.',
      };
    }
    if (action === 'firewall_profile') {
      const profile = item.autofixFirewallProfile
        ? `${item.autofixFirewallProfile.charAt(0).toUpperCase()}${item.autofixFirewallProfile.slice(1)} profile`
        : item.policyPath || item.displayName || item.name;
      return {
        type: 'Firewall profile',
        target: profile,
        apply: value,
        rollback: 'Previous firewall state will be captured when the agent runs.',
      };
    }
    if (action === 'security_policy') {
      const tool = item.autofixTool || 'secedit';
      return {
        type: `Security policy (${tool})`,
        target: item.autofixSecurityPolicyKey || item.displayName || item.name,
        apply: value,
        rollback: tool === 'net accounts'
          ? 'Previous account policy value will be captured from net accounts.'
          : 'Previous security policy value will be captured from secedit export.',
      };
    }
    if (action === 'user_rights') {
      return {
        type: 'User rights assignment (secedit)',
        target: item.autofixPrivilegeName || item.displayName || item.name,
        apply: item.autofixPrivilegeAccounts?.length ? item.autofixPrivilegeAccounts.join(', ') : value || '(blank)',
        rollback: 'Previous user-right assignment will be captured from secedit export.',
      };
    }
    if (action === 'registry_multi' || action === 'defender_registry') {
      return {
        type: action === 'defender_registry' ? 'Defender registry-backed policy' : 'Multi-registry policy',
        target: item.autofixRegistryEntries?.length
          ? `${item.autofixRegistryEntries.length} registry values`
          : item.registryPath || item.displayName || item.name,
        apply: item.autofixRegistryEntries?.length
          ? item.autofixRegistryEntries.map((entry) => `${entry.value_name || entry.path}=${entry.value}`).join(' | ')
          : value,
        rollback: 'Previous registry values will be captured value-by-value when the agent runs.',
      };
    }
    return {
      type: 'Registry value',
      target: item.registryPath || item.displayName || item.name,
      apply: value,
      rollback: 'Previous registry value will be captured when the agent runs.',
    };
  };

  const submitAutofix = async () => {
    const scanId = scanData?.scan_id || routeScanId;
    if (!scanId || selectedAutofixItems.length === 0) return;
    setAutofixSubmitting(true);
    setErrorMsg('');
    try {
      const itemsToSubmit = orderedSelectedAutofixItems;
      const res = await fetch(apiUrl(`/api/scan/history/${scanId}/autofix`), {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          check_ids: itemsToSubmit.map((item) => item.checkId || item.key),
          autofix_values: itemsToSubmit.reduce((values, item) => {
            const key = item.checkId || item.key;
            if (item.autofixNeedsInput && key) {
              values[key] = autofixInputs[key] || item.autofixDefaultValue || item.target || '';
            }
            return values;
          }, {}),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        const detail = data.detail;
        const rejected = Array.isArray(detail?.rejected) ? detail.rejected : [];
        const rejectedReason = rejected.map((row) => row.reason).filter(Boolean).join(' ');
        const message = typeof detail === 'object'
          ? (rejectedReason || detail.message || 'Autofix failed')
          : (detail || 'Autofix failed');
        throw new Error(message);
      }
      setAutofixModalOpen(false);
      setAutofixStatus({ job_id: data.job_id, status: 'pending', message: 'Autofix job queued', result: null, rejected: data.rejected || [] });
      setSelectedAutofix(new Set());
      setAutofixHistoryOpen(true);
      loadAutofixJobs(scanId);
    } catch (err) {
      setErrorMsg(err.message || 'Unable to queue autofix job');
    } finally {
      setAutofixSubmitting(false);
    }
  };

  const submitRollback = async () => {
    const scanId = scanData?.scan_id || routeScanId;
    if (!scanId || !rollbackJob?.job_id) return;
    setRollbackSubmitting(true);
    setErrorMsg('');
    try {
      const res = await fetch(apiUrl(`/api/scan/history/${scanId}/autofix/${rollbackJob.job_id}/rollback`), {
        method: 'POST',
        headers: authHeaders(),
      });
      const data = await res.json();
      if (!res.ok) {
        const detail = data.detail;
        const message = typeof detail === 'object' ? (detail.message || 'Rollback failed') : (detail || 'Rollback failed');
        throw new Error(message);
      }
      setRollbackJob(null);
      setAutofixStatus({
        job_id: data.job_id,
        status: 'pending',
        message: 'Rollback job queued',
        result: null,
        rejected: data.rejected || [],
      });
      setAutofixHistoryOpen(true);
      loadAutofixJobs(scanId);
    } catch (err) {
      setErrorMsg(err.message || 'Unable to queue rollback job');
    } finally {
      setRollbackSubmitting(false);
    }
  };

  const rescanAgent = () => {
    const agentId = scanData?.agent_id;
    if (!agentId) {
      setErrorMsg('Unable to rescan: this report is not linked to an agent.');
      return;
    }
    const nextScanParams = {
      agent_id: agentId,
      host: scanData?.hostname || agentId,
      version: scanData?.version || 'auto',
      role: 'Member Server',
      _mode: 'agent',
      target_name: `${agentId} (${scanData?.version || 'Auto detect baseline'})`,
    };
    sessionStorage.removeItem(SESSION_KEY);
    scanParamsRef.current = nextScanParams;
    setAutofixStatus(null);
    setSelectedAutofix(new Set());
    setScanData(null);
    setErrorMsg('');
    setPhase('scanning');
    navigate('/result', { replace: false, state: { scanParams: nextScanParams } });
  };

  useEffect(() => {
    if (!autofixStatus?.job_id || ['done', 'error'].includes(autofixStatus.status)) return;
    const timer = setInterval(() => {
      fetch(apiUrl(`/api/scan/status/${autofixStatus.job_id}`), { headers: authHeaders() })
        .then((res) => {
          if (res.status === 401) {
            clearAuth();
            navigate('/login');
            return Promise.reject('Not authenticated');
          }
          if (!res.ok) return res.json().then((e) => Promise.reject(e.detail || 'Unable to load autofix status'));
          return res.json();
        })
        .then((data) => {
          setAutofixStatus((prev) => ({
            ...(prev || {}),
            status: data.status,
            message: data.message || data.status,
            result: data.result || null,
            error: data.error || '',
          }));
          if (['done', 'error'].includes(data.status)) {
            loadAutofixJobs(scanData?.scan_id || routeScanId);
          }
        })
        .catch((err) => {
          setAutofixStatus((prev) => ({ ...(prev || {}), status: 'error', error: String(err) }));
        });
    }, 2500);
    return () => clearInterval(timer);
  }, [autofixStatus?.job_id, autofixStatus?.status, navigate]);

  // Score colour using ink/amber/green palette
  const scoreColor = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--amber)' : 'var(--red)';
  const circumference = 2 * Math.PI * 42;

  if (phase === 'redirect') return null;

  if (phase === 'loading-history') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="scanProgressWrap">
          <div className="scanStepMsg">Loading report...</div>
          <div className="scanBarWrap">
            <div className="scanBar" style={{ width: '35%' }} />
          </div>
        </div>
      </Layout>
    );
  }

  if (phase === 'scanning') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Scanning</h1>
          <p className="pageDesc">Running security assessment. Please wait.</p>
        </div>
        <ScanProgress
          scanParams={scanParamsRef.current}
          onScanComplete={(data) => {
            setScanData(data);
            setPhase('done');
            if (data.scan_id) {
              navigate(
                data.isSubnet ? `/scan/${data.scan_id}/subnet` : `/scan/${data.scan_id}/report`,
                { replace: true, state: { fromHistory: data } },
              );
            }
          }}
          onError={(msg)         => { setErrorMsg(msg);  setPhase('error'); }}
        />
      </Layout>
    );
  }

  if (phase === 'error') {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Scan Failed</h1>
        </div>
        <div className="idleWrap">
          <div className="idleCard">
            <div className="idleIcon">!</div>
            <h2 className="idleTitle" style={{ color: 'var(--red)' }}>Error</h2>
            <p className="idleDesc">{errorMsg}</p>
            <button className="idleScanBtn" onClick={() => navigate('/home')}>Back to Home</button>
          </div>
        </div>
      </Layout>
    );
  }
  // Subnet result block
  if (phase === 'done' && scanData?.isSubnet) {
    return (
      <Layout navigate={navigate}>
        <Topbar />
        <div className="pageHead">
          <h1 className="pageTitle">Subnet Scan Result</h1>
          <p className="pageDesc">{scanData.subnet}  {scanData.version}</p>
        </div>

        <div className="scoreSummary" style={{ marginBottom: 24 }}>
          <div className="scoreDetail">
            <div className="scoreLabel">{scanData.subnet}</div>
            <div className="scoreVersion">{scanData.version}</div>
            <div className="scoreCounts" style={{ marginTop: 8 }}>
              <span className="countBadge pass"> {scanData.success_count} successful</span>
              <span className="countBadge fail"> {scanData.failed_count} failed</span>
            </div>
          </div>
        </div>

        <div className="resultCard">
          <div className="colHeaders" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
            <div>Host</div>
            <div>Score</div>
            <div>Status</div>
            <div>Detail</div>
          </div>
          <div className="itemList">
            {scanData.results.map((r) => (
              <div key={r.host} className="resultRow">
                <div className="rowSummary" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
                  <div>
                    <div className="itemName">{r.hostname || r.host}</div>
                    <div className="sectionTag">{r.host}</div>
                  </div>
                  <div>
                    <span style={{
                      fontFamily: 'DM Mono, monospace',
                      fontSize: 14,
                      fontWeight: 500,
                      color: r.score >= 70 ? 'var(--green)' : r.score >= 40 ? 'var(--amber)' : 'var(--red)',
                    }}>
                      {r.score}%
                    </span>
                  </div>
                  <div>
                    <span className={`badge ${r.status === 'done' ? 'on' : 'off'}`}>
                      {r.status === 'done' ? 'Done' : 'Error'}
                    </span>
                    {r.error && <div className="sectionTag" style={{ color: 'var(--red)', marginTop: 4 }}>{r.error}</div>}
                  </div>
                  <div>
                    {r.scan_id && (
                      <button
                        className="connBtn"
                        style={{ padding: '4px 12px', fontSize: 12 }}
                        onClick={() => navigate(`/scan/${r.scan_id}/report`)}
                      >
                        View 
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="resultFooter">
            <div />
            <button className="finishButton" onClick={() => navigate('/home')}>
              Finish
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout navigate={navigate}>
      <Topbar />

      <ReportHeader
        title={targetName || hostname || 'Scan result'}
        subtitle="Review compliance findings, remediation guidance, and available Autofix actions."
        score={score}
        context={[
          { label: 'Baseline', value: version || 'Unknown baseline' },
          { label: 'Scan ID', value: scanData?.scan_id || routeScanId || '-' },
          { label: 'Scanned', value: scanDate ? formatReportDate(scanDate) : 'Current report' },
          {
            label: 'Assessed',
            value: scoreBreakdown
              ? `${scoreBreakdown.passed_assessed_count ?? scoreBreakdown.passed_weight}/${scoreBreakdown.total_assessed_count ?? scoreBreakdown.assessed_weight}`
              : `${passCount}/${passCount + failCount}`,
          },
        ]}
        actions={(
          <>
            <button
              type="button"
              className="reportAction secondary"
              onClick={() => navigate(scanData?.scan_id ? `/history?compare=${scanData.scan_id}` : '/history')}
            >
              Compare
            </button>
            <ExportButton scanId={scanData?.scan_id || routeScanId} appearance="report" />
            <button
              type="button"
              className="reportAction primary"
              onClick={() => navigate('/summary', { state: { scanData: { ...scanData, scan_id: scanData?.scan_id } } })}
            >
              Summary
            </button>
          </>
        )}
      />

      <MetricGrid>
        <MetricCard label="Passed" value={passCount} hint="Assessed checks" tone="pass" />
        <MetricCard label="Failed" value={failCount} hint="Require remediation" tone="fail" />
        <MetricCard label="Manual / excluded" value={manualCount} hint="Not scored automatically" />
        <MetricCard label="Critical failures" value={failedSeverityCounts.critical} hint="Highest priority" tone="critical" />
        <MetricCard label="High failures" value={failedSeverityCounts.high} hint="Review next" tone="warn" />
      </MetricGrid>

      <div className="pageHead legacyReportIntro">
        <h1 className="pageTitle">Scan Result</h1>
        <p className="pageDesc">Security scan result and remediation guidance</p>
      </div>

      {/* Score Summary */}
      <div className="scoreSummary legacyReportIntro">
        <div className="scoreCircleWrap">
          <svg viewBox="0 0 100 100" className="scoreCircleSvg">
            <circle cx="50" cy="50" r="42" className="scoreTrack" />
            <circle
              cx="50" cy="50" r="42"
              className="scoreArc"
              strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
              transform="rotate(-90 50 50)"
              style={{ stroke: scoreColor }}
            />
          </svg>
          <div className="scoreText" style={{ color: scoreColor }}>{score}%</div>
        </div>

        <div className="scoreDetail">
          <div className="scoreLabel">{targetName || hostname}</div>
          <div className="scoreVersion">{version}</div>
          <div className="scoreVersion">Compliance Score</div>
          {scoreBreakdown && (
            <div className="scoreVersion">
              Assessed pass rate {scoreBreakdown.passed_assessed_count ?? scoreBreakdown.passed_weight}/{scoreBreakdown.total_assessed_count ?? scoreBreakdown.assessed_weight}
              {scoreBreakdown.excluded_manual_count ? ` · ${scoreBreakdown.excluded_manual_count} manual excluded` : ''}
              {scoreBreakdown.excluded_na_count ? ` · ${scoreBreakdown.excluded_na_count} N/A excluded` : ''}
            </div>
          )}
          <div className="scoreCounts">
            <span className="countBadge pass"> {passCount} Pass</span>
            <span className="countBadge fail"> {failCount} Fail</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: 4 }}>
            {tabs.slice(1).map((sev) => (
              <div key={sev} className="severityCount" style={{ color: SEVERITY_CONFIG[sev].color }}>
                <span className="sevDot" style={{ background: SEVERITY_CONFIG[sev].color }} />
                {SEVERITY_CONFIG[sev].label}: {counts[sev]}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Result Card */}
      <div className="resultCard productionResultCard">

        {/* Tab Row */}
        <div className="tabRow reportFilterToolbar">
          {tabs.map((tab) => (
            <button
              key={tab}
              className={`tabBtn ${activeTab === tab ? 'active' : ''}`}
              style={
                activeTab === tab && tab !== 'ALL'
                  ? { borderBottomColor: SEVERITY_CONFIG[tab].color, color: SEVERITY_CONFIG[tab].color }
                  : {}
              }
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              <span className="tabCount">{counts[tab]}</span>
            </button>
          ))}

          <div className="tabRowRight">
            <select
              className="sectionSelect"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Status</option>
              <option value="pass">Pass</option>
              <option value="fail">Fail</option>
              <option value="na">N/A</option>
            </select>

            <select
              className="sectionSelect"
              value={autofixFilter}
              onChange={(e) => setAutofixFilter(e.target.value)}
            >
              <option value="ALL">All Fix Types</option>
              <option value="available">Autofix Available</option>
              <option value="needs-input">Needs Input</option>
              <option value="review">Review Required</option>
              <option value="manual">Manual Fix Required</option>
            </select>

            <select
              className="sectionSelect"
              value={sectionFilter}
              onChange={(e) => setSectionFilter(e.target.value)}
            >
              {sections.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>

            <div className="searchWrap">
              <input
                className="searchInput"
                placeholder="Search"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
              {searchInput && (
                <button className="clearBtn" onClick={handleClear}></button>
              )}
              <button className="searchBtn" onClick={handleSearch}>
                <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="5.5" cy="5.5" r="4.5" />
                  <path d="M9 9l2.5 2.5" strokeLinecap="round" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div className="autofixCoveragePanel compact">
          <div>
            <strong>Autofix Coverage</strong>
            <span>Selected checks only. Manual items still need guided remediation.</span>
          </div>
          <div className="autofixCoverageGrid">
            <div><b>{autofixCoverage.failedCount}</b><span>failed checks</span></div>
            <div><b>{autofixCoverage.availableCount}</b><span>autofix available</span></div>
            <div><b>{autofixCoverage.needsInputCount}</b><span>need input</span></div>
            <div><b>{autofixCoverage.reviewRequiredCount}</b><span>review required</span></div>
            <div><b>{autofixCoverage.manualCount}</b><span>manual</span></div>
          </div>
          <button
            type="button"
            className="coverageToggle"
            onClick={() => setAutofixCoverageOpen((open) => !open)}
          >
            {autofixCoverageOpen ? 'Hide types' : 'View types'}
          </button>
          {autofixCoverageOpen && (
            <div className="autofixTypeBreakdown">
              <span>Registry {autofixCoverage.byType.registry || 0}</span>
              <span>Multi-registry {autofixCoverage.byType.registry_multi || 0}</span>
              <span>Defender registry {autofixCoverage.byType.defender_registry || 0}</span>
              <span>Security Policy {autofixCoverage.byType.security_policy || 0}</span>
              <span>User Rights {autofixCoverage.byType.user_rights || 0}</span>
              <span>Audit {autofixCoverage.byType.audit_policy || 0}</span>
              <span>Services {autofixCoverage.byType.service_startup || 0}</span>
              <span>Firewall {autofixCoverage.byType.firewall_profile || 0}</span>
            </div>
          )}
        </div>

        <div className="autofixToolbar">
          <div>
            <strong>Autofix</strong>
            <span>
              {autofixableItems.length} fixes available · {selectedAutofixItems.filter((item) => item.autofixNeedsInput).length} need input · {selectedAutofixItems.length} selected
            </span>
          </div>
          <button
            type="button"
            className="autofixButton"
            disabled={selectedAutofixItems.length === 0}
            onClick={() => setAutofixModalOpen(true)}
          >
            Autofix Selected
          </button>
        </div>

        {missingAutofixDependencies.length > 0 && (
          <div className="autofixDependencyWarning">
            <div>
              <strong>Required order missing</strong>
              <span>
                {missingAutofixDependencies.map(({ dependency, dependent }) => (
                  `${dependent.displayName || dependent.name} requires ${dependency?.displayName || dependency?.name || 'a prerequisite check'} first`
                )).join(' · ')}
              </span>
            </div>
            <button type="button" className="autofixDependencyBtn" onClick={selectRequiredAutofixDependencies}>
              Select required checks
            </button>
          </div>
        )}

        {autofixStatus && (
          <div className={`autofixStatus ${autofixStatus.status === 'error' ? 'error' : autofixStatus.status === 'done' ? 'done' : ''}`}>
            <div>
              <strong>Autofix job: {autofixStatus.status}</strong>
              <span>{autofixStatus.message || autofixStatus.error || 'Waiting for agent...'}</span>
              {autofixStatus.rejected?.length > 0 && (
                <span>{autofixStatus.rejected.length} selected checks were rejected by validation.</span>
              )}
            </div>
            {autofixStatus.result?.autofix_results && (
              <div className="autofixResultList">
                {autofixStatus.result.autofix_results.map((row) => (
                  <div className="autofixResultRow" key={row.check_id}>
                    <span className={`countBadge ${row.status === 'done' ? 'pass' : 'fail'}`}>
                      {row.status === 'done' ? 'Fixed' : 'Failed'}
                    </span>
                    <strong>{row.check_name || row.check_id}</strong>
                    {row.error && <span>{row.error}</span>}
                  </div>
                ))}
                {autofixStatus.status === 'done' && (
                  <div className="autofixVerifyHint">
                    <span>
                      Last verified scan: report #{scanData?.scan_id || routeScanId || '-'}. Run a new scan to verify the updated compliance result.
                    </span>
                    <button type="button" className="autofixRescanBtn" onClick={rescanAgent} disabled={!scanData?.agent_id}>
                      Rescan Agent
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        <div className="autofixHistoryPanel">
          <div className="autofixHistoryHead">
            <div>
              <strong>Autofix History</strong>
              <span>{completedAutofixJobs.length} successful/rollback jobs · {failedAutofixJobs.length} failed test jobs</span>
            </div>
            <div className="autofixHistoryActions">
              <button type="button" className="copyLocationBtn" onClick={() => loadAutofixJobs(scanData?.scan_id || routeScanId)}>
                Refresh
              </button>
              <button type="button" className="copyLocationBtn primary" onClick={() => setAutofixHistoryOpen((open) => !open)}>
                {autofixHistoryOpen ? 'Hide History' : 'View Autofix History'}
              </button>
            </div>
          </div>
          {!autofixHistoryOpen && autofixJobs[0] && (
            <div className="autofixLatestJob">
              <StatusBadge tone={autofixJobs[0].status === 'done' ? 'pass' : autofixJobs[0].status === 'error' ? 'fail' : 'warn'}>
                {autofixJobs[0].status}
              </StatusBadge>
              <div>
                <strong>Latest {autofixJobs[0].job_type === 'rollback' ? 'rollback' : 'Autofix'} job</strong>
                <span>
                  {autofixJobs[0].success_count || 0}/{autofixJobs[0].total || 0} succeeded · {formatReportDate(autofixJobs[0].completed_at || autofixJobs[0].created_at)}
                </span>
              </div>
            </div>
          )}
          {autofixHistoryOpen && (
            <div className="autofixHistoryList">
              {autofixJobs.length === 0 && <div className="emptyMsg compact">No autofix jobs recorded yet</div>}
              {completedAutofixJobs.map((job) => (
                <div className="autofixHistoryJob" key={job.job_id}>
                  <div className="autofixHistoryJobTop">
                    <div>
                      <strong>{job.job_type === 'rollback' ? 'Rollback' : 'Autofix'} job</strong>
                      <span>{job.completed_at || job.created_at || job.job_id}</span>
                      <span>{job.requested_by ? `Requested by ${job.requested_by}` : 'Requester unknown'}</span>
                    </div>
                    <div className="autofixHistoryMeta">
                      <span className={`countBadge ${job.status === 'done' ? 'pass' : job.status === 'error' ? 'fail' : 'warn'}`}>{job.status}</span>
                      <span>{job.success_count || 0}/{job.total || 0} succeeded</span>
                    </div>
                  </div>
                  <div className="autofixHistoryChecks">
                    {(job.results || []).map((row) => (
                      <div className="autofixHistoryCheck" key={`${job.job_id}-${row.check_id}`}>
                        <span className={`countBadge ${row.status === 'done' ? 'pass' : 'fail'}`}>{row.status === 'done' ? 'OK' : 'Fail'}</span>
                        <div>
                          <strong>{row.check_name || row.check_id}</strong>
                          <span>{row.fix_type || 'registry'} · old: {row.old_value || '-'} · new: {row.new_value || '-'}</span>
                          {row.error && <span className="autofixErrorText">{row.error}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                  {job.rollback_supported && (
                    <div className="autofixHistoryFooter">
                      <button type="button" className="autofixRollbackBtn" onClick={() => setRollbackJob(job)}>
                        Rollback
                      </button>
                    </div>
                  )}
                  {!job.rollback_supported && job.job_type === 'autofix' && job.rollback_reason && (
                    <div className="autofixRollbackNote">Rollback unavailable: {job.rollback_reason}</div>
                  )}
                </div>
              ))}
              {failedAutofixJobs.length > 0 && (
                <div className="autofixFailedJobs">
                  <strong>Failed test jobs</strong>
                  <span>Kept for audit trail, separated from successful remediation history.</span>
                  {failedAutofixJobs.map((job) => (
                    <div className="autofixHistoryJob failed" key={job.job_id}>
                      <div className="autofixHistoryJobTop">
                        <div>
                          <strong>{job.job_type === 'rollback' ? 'Rollback' : 'Autofix'} job</strong>
                          <span>{job.completed_at || job.created_at || job.job_id}</span>
                          <span>{job.requested_by ? `Requested by ${job.requested_by}` : 'Requester unknown'}</span>
                        </div>
                        <div className="autofixHistoryMeta">
                          <span className="countBadge fail">{job.status}</span>
                          <span>{job.success_count || 0}/{job.total || 0} succeeded</span>
                        </div>
                      </div>
                      <div className="autofixHistoryChecks">
                        {(job.results || []).map((row) => (
                          <div className="autofixHistoryCheck" key={`${job.job_id}-${row.check_id}`}>
                            <span className="countBadge fail">Fail</span>
                            <div>
                              <strong>{row.check_name || row.check_id}</strong>
                              <span>{row.fix_type || 'registry'} · old: {row.old_value || '-'} · new: {row.new_value || '-'}</span>
                              {row.error && <span className="autofixErrorText">{row.error}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Column Headers */}
        <div className="colHeaders">
          <div>Finding</div>
          <div>Current value</div>
          <div>Required value</div>
          <div>Remediation</div>
        </div>

        {/* Item List */}
        <div className="itemList">
          {filtered.length === 0 && (
            <div className="emptyMsg">No matching items found</div>
          )}
          {filtered.map((item) => {
            const sev    = SEVERITY_CONFIG[item.severity];
            const isOpen = expanded === item.key;
            const detailTab = detailTabs[item.key] || 'details';
            const locationGuide = buildSettingLocationGuide(item, { hostname, targetName });
            return (
              <div
                id={`finding-${item.key}`}
                key={item.key}
                className={`resultRow ${isOpen ? 'open' : ''}`}
              >
                <div className="rowSummary" onClick={() => setExpanded(isOpen ? null : item.key)}>

                  <div className="findingIdentity">
                    {item.status === 'fail' && (
                      <input
                        type="checkbox"
                        className="autofixCheck"
                        checked={selectedAutofix.has(item.checkId || item.key)}
                        disabled={!item.autofixSupported}
                        title={item.autofixSupported
                          ? item.autofixNeedsInput ? 'Select for autofix, then choose a value' : 'Select for autofix'
                          : formatAutofixReason(item.autofixReason, item)}
                        onChange={(event) => {
                          event.stopPropagation();
                          toggleAutofixSelection(item);
                        }}
                        onClick={(event) => event.stopPropagation()}
                      />
                    )}
                    <div className="findingContent">
                      <div className="findingTitleLine">
                        <span className="itemName">{item.displayName || item.name}</span>
                        <span
                          className="sevBadge"
                          style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.bd}` }}
                        >
                          {sev.label}
                        </span>
                      </div>
                      <div className="findingMetaLine">
                        <span className="sectionTag">{item.section}</span>
                        {item.autofixGroupLabel && (
                          <span className="autofixOrderTag">Chain: {item.autofixGroupLabel}</span>
                        )}
                        {item.autofixStep > 0 && (
                          <span className="autofixOrderTag step">Step {item.autofixStep}</span>
                        )}
                        {hasFailingAutofixDependency(item) && (
                          <span className="autofixOrderTag depends">Depends on threshold</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="findingValue current">
                    {item.actual || 'Not Configured'}
                  </div>

                  <div className="findingValue required">
                    {item.target || '-'}
                  </div>

                  <div className="findingRemediation">
                    <div className={`solutionChip ${item.status} ${item.autofixNeedsInput ? 'needsInput' : item.autofixSupported ? 'autofixReady' : ''}`}>
                      {item.status === 'pass' ? 'Compliant'
                     : item.status === 'fail' && item.autofixNeedsInput ? 'Needs Input'
                     : item.status === 'fail' && item.autofixSupported ? 'Autofix'
                     : item.status === 'fail' ? 'Manual Fix'
                     : 'N/A'}
                    </div>
                    {item.status === 'fail' && item.autofixNeedsInput && (
                      <div className="solutionSubtext">Choose value before apply</div>
                    )}
                  </div>
                </div>

                {/* Expanded Detail */}
                {isOpen && (
                  <div className="rowDetail" data-active-tab={detailTab}>
                    <div className="findingDetailTabs">
                      {[
                        ['details', 'Details'],
                        ['remediation', 'Remediation'],
                        ...(item.status === 'fail' ? [['autofix', 'Autofix']] : []),
                      ].map(([key, label]) => (
                        <button
                          type="button"
                          key={key}
                          className={detailTab === key ? 'active' : ''}
                          onClick={() => setDetailTabs((current) => ({ ...current, [item.key]: key }))}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                    <div className="detailGrid">
                      <div className="detailBlock detailSection details">
                        <div className="detailLabel">Current Value</div>
                        <div className="detailValue currentValue">
                          {item.actual || 'Not Configured'}
                        </div>
                      </div>
                      <div className="detailBlock detailSection details">
                        <div className="detailLabel">Required Value</div>
                        <div className="detailValue requiredValue">{item.target || ''}</div>
                      </div>
                      {item.autofixAction === 'firewall_profile' && (
                        <div className="detailBlock detailSection details">
                          <div className="detailLabel">Firewall Profile</div>
                          <div className="detailValue">{firewallProfileLabel(item) || 'Unknown profile'}</div>
                        </div>
                      )}
                      <div className="detailBlock full detailSection remediation">
                        <div className="detailLabel">Solution</div>
                        <div className="detailValue">{item.solution.text}</div>
                        {item.solution.link && (
                          <a className="msLink" href={item.solution.link} target="_blank" rel="noreferrer">
                             Microsoft Documentation 
                          </a>
                        )}
                      </div>
                      {item.status === 'fail' && (
                        <div className={`detailBlock full detailSection autofix autofixInfo ${item.autofixSupported ? 'available' : 'manual'}`}>
                          <div className="detailLabel">Autofix</div>
                          <div className="detailValue">
                            {item.autofixSupported && item.autofixNeedsInput
                              ? 'Autofix needs input. Select this check and choose the value in the confirmation popup.'
                              : item.autofixSupported
                              ? 'Autofix available for this check.'
                              : formatAutofixReason(item.autofixReason, item)}
                          </div>
                        </div>
                      )}
                      {item.status === 'fail' && item.autofixGroup && (
                        <div className="detailBlock full detailSection autofix autofixOrderPanel">
                          <div className="detailLabel">Autofix Order</div>
                          <div className="autofixOrderList">
                            {allItems
                              .filter((row) => row.autofixGroup === item.autofixGroup)
                              .sort((a, b) => (a.autofixStep || 99) - (b.autofixStep || 99))
                              .map((row) => (
                                <div
                                  className={`autofixOrderItem ${(row.checkId || row.key) === (item.checkId || item.key) ? 'current' : ''}`}
                                  key={row.checkId || row.key}
                                >
                                  <span>Step {row.autofixStep || '-'}</span>
                                  <strong>{row.displayName || row.name}</strong>
                                  <em>{row.status === 'fail' ? 'Needs remediation' : 'Already compliant'}</em>
                                </div>
                              ))}
                          </div>
                          {item.autofixDependencyNote && (
                            <div className="autofixOrderNote">{item.autofixDependencyNote}</div>
                          )}
                        </div>
                      )}
                      {item.status === 'fail' && locationGuide.available && (
                        <div className="detailBlock full detailSection remediation settingLocationPanel">
                          <div className="detailHeaderRow">
                            <div>
                              <div className="detailLabel">Setting Location</div>
                              <div className="settingLocationHint">
                                Windows policy tools usually cannot deep-link to an exact setting. Use this location to navigate or search for the setting.
                              </div>
                            </div>
                            <div className="locationActions">
                              {locationGuide.registryEntries.length > 0 && (
                                <button
                                  type="button"
                                  className="copyLocationBtn"
                                  onClick={() => handleCopyLocation(`${item.key}:registry`, locationGuide.registryEntries.map((entry) => (
                                    entry.valueName ? `${entry.keyPath}!${entry.valueName}` : entry.keyPath
                                  )).join('\n'))}
                                >
                                  {copiedLocation === `${item.key}:registry` ? 'Copied' : 'Copy Registry Path'}
                                </button>
                              )}
                              <button
                                type="button"
                                className="copyLocationBtn primary"
                                onClick={() => handleCopyLocation(`${item.key}:location`, locationGuide.copyText)}
                              >
                                {copiedLocation === `${item.key}:location` ? 'Copied' : 'Copy Location'}
                              </button>
                            </div>
                          </div>

                          <div className="settingLocationGrid">
                            <div className="settingLocationItem">
                              <span>Open Tool</span>
                              <strong>{locationGuide.openTool}</strong>
                            </div>
                            {locationGuide.policyPath && (
                              <div className="settingLocationItem wide">
                                <span>Security Policy Location</span>
                                <strong>{locationGuide.policyPath}</strong>
                              </div>
                            )}
                            {locationGuide.registryEntries.map((entry, index) => (
                              <React.Fragment key={`${entry.keyPath}-${entry.valueName}-${index}`}>
                                <div className="settingLocationItem wide">
                                  <span>{locationGuide.registryEntries.length > 1 ? `Registry Key ${index + 1}` : 'Registry Key'}</span>
                                  <strong>{entry.keyPath}</strong>
                                </div>
                                {entry.valueName && (
                                  <div className="settingLocationItem">
                                    <span>{locationGuide.registryEntries.length > 1 ? `Registry Value ${index + 1}` : 'Registry Value'}</span>
                                    <strong>{entry.valueName}</strong>
                                  </div>
                                )}
                              </React.Fragment>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="resultFooter">
          <button
            className="statButton"
            onClick={() => navigate('/history')}
          >
            Back to History
          </button>
          <button
            className="finishButton"
            onClick={() => {
              sessionStorage.removeItem(SESSION_KEY);
              navigate('/home');
            }}
          >
            Finish
          </button>
        </div>
      </div>

      {autofixModalOpen && (
        <div className="autofixModalBackdrop" role="presentation" onClick={() => !autofixSubmitting && setAutofixModalOpen(false)}>
          <div className="autofixModal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="autofixModalHead">
              <div>
                <h2>Confirm Autofix</h2>
                <p>
                  This will change settings on {hostname || targetName || 'the target agent'}.
                  Run a new scan after completion to verify compliance.
                </p>
              </div>
              <button type="button" className="subnetModalClose" onClick={() => setAutofixModalOpen(false)} disabled={autofixSubmitting}>
                Close
              </button>
            </div>
            <div className="autofixWarning">
              Review the selected checks carefully. Items marked Needs Input will use the value you choose here.
            </div>
            {selectedAutofixItems.some((item) => item.autofixAction === 'firewall_profile') && (
              <div className="autofixWarning firewall">
                Firewall changes can affect backend, RDP, WinRM, and agent callback connectivity. Verify allow rules before turning profiles on.
              </div>
            )}
            {selectedAutofixItems.some((item) => ['security_policy', 'user_rights'].includes(item.autofixAction)) && (
              <div className="autofixWarning">
                Security policy fixes modify local policy through net accounts or secedit. The agent captures previous values for rollback, but you should rescan after every change.
              </div>
            )}
            <div className="autofixExecutionOrder">
              <strong>Execution order</strong>
              <div>
                {orderedSelectedAutofixItems.map((item, index) => {
                  const plan = describeAutofixPlan(item);
                  return (
                    <span key={item.checkId || item.key}>
                      {index + 1}. {item.displayName || item.name}
                      {item.autofixStep ? ` (Step ${item.autofixStep})` : ''}
                      {' · '}{plan.type}
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="autofixModalList">
              {orderedSelectedAutofixItems.map((item) => {
                const plan = describeAutofixPlan(item);
                return (
                  <div className="autofixModalRow" key={item.checkId || item.key}>
                    <div>
                      <strong>{item.displayName || item.name}</strong>
                      <span>{item.checkId || item.key}</span>
                      {item.autofixNeedsInput && (
                        <label className="autofixInputField">
                          Value to apply
                          <select
                            value={autofixInputs[item.checkId || item.key] || item.autofixDefaultValue || item.target || ''}
                            onChange={(event) => {
                              const key = item.checkId || item.key;
                              setAutofixInputs((current) => ({ ...current, [key]: event.target.value }));
                            }}
                            disabled={autofixSubmitting}
                          >
                            {(item.autofixAllowedValues || []).map((value) => (
                              <option key={value} value={value}>{value}</option>
                            ))}
                          </select>
                        </label>
                      )}
                      <div className="autofixPlan">
                        <div><b>Type</b><span>{plan.type}</span></div>
                        <div><b>Target</b><span>{plan.target || 'Target setting'}</span></div>
                        <div><b>Apply</b><span>{plan.apply || 'Baseline value'}</span></div>
                        <div><b>Current</b><span>{item.actual || 'Unknown'}</span></div>
                        <div><b>Rollback</b><span>{plan.rollback}</span></div>
                      </div>
                    </div>
                    <span className={`countBadge ${item.autofixNeedsInput ? 'warn' : 'fail'}`}>
                      {item.autofixNeedsInput ? 'Needs Input' : item.severity}
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="autofixModalActions">
              <button type="button" className="statButton" onClick={() => setAutofixModalOpen(false)} disabled={autofixSubmitting}>
                Cancel
              </button>
              <button type="button" className="finishButton" onClick={submitAutofix} disabled={autofixSubmitting}>
                {autofixSubmitting ? 'Queuing...' : `Autofix ${selectedAutofixItems.length} selected`}
              </button>
            </div>
          </div>
        </div>
      )}

      {rollbackJob && (
        <div className="autofixModalBackdrop" role="presentation" onClick={() => !rollbackSubmitting && setRollbackJob(null)}>
          <div className="autofixModal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="autofixModalHead">
              <div>
                <h2>Confirm Rollback</h2>
                <p>
                  This will restore the previous values from autofix job {rollbackJob.job_id} on {hostname || targetName || 'the target agent'}.
                  Run a new scan after completion to verify compliance.
                </p>
              </div>
              <button type="button" className="subnetModalClose" onClick={() => setRollbackJob(null)} disabled={rollbackSubmitting}>
                Close
              </button>
            </div>
            <div className="autofixWarning">
              Rollback changes real settings on the target machine. Review the old/new values before continuing.
            </div>
            <div className="autofixModalList">
              {(rollbackJob.results || []).filter((row) => row.rollback_supported).map((row) => (
                <div className="autofixModalRow" key={`${rollbackJob.job_id}-rollback-${row.check_id}`}>
                  <div>
                    <strong>{row.check_name || row.check_id}</strong>
                    <span>{row.fix_type || 'registry'}</span>
                    <span>Restore to: {row.old_value || '-'}</span>
                  </div>
                  <span className="countBadge warn">Rollback</span>
                </div>
              ))}
            </div>
            <div className="autofixModalActions">
              <button type="button" className="statButton" onClick={() => setRollbackJob(null)} disabled={rollbackSubmitting}>
                Cancel
              </button>
              <button type="button" className="finishButton" onClick={submitRollback} disabled={rollbackSubmitting}>
                {rollbackSubmitting ? 'Queuing...' : 'Rollback'}
              </button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}



