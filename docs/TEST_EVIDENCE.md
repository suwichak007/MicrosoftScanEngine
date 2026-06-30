# Test Evidence

Use this page to record the latest validation run before demo or handoff.

## Build Checks

| Check | Result | Notes |
| --- | --- | --- |
| `python -m py_compile backend/main.py backend/app/core/agent_routes.py backend/app/core/export_routes.py agent/agent.py agent/setup.py` | Pass | Completed June 24, 2026, including backend and agent scanner modules. |
| `npm run build` from `frontend/` | Pass | Vite production build completed June 24, 2026. |
| Agent installer/build verification | Pending | |

## Smoke Checks

| Check | Result | Notes |
| --- | --- | --- |
| `tools/demo_smoke_check.ps1` unauthenticated | Pending | |
| `tools/demo_smoke_check.ps1` with `SMOKE_ADMIN_TOKEN` | Pending | |
| Viewer blocked from admin endpoints | Pending | |
| Viewer blocked from Autofix endpoints | Pass | LDAP viewer received HTTP 403 from Autofix history endpoint. |

## Functional Checks

| Flow | Result | Notes |
| --- | --- | --- |
| Login/logout/profile menu | Pending | |
| Home latest scan overview | Pending | |
| Agent scan | Pass | Canary `agent-WIN-50F5TDGIP70`; final verification scan `#202`. |
| Agent subnet scan | Pending | |
| History opens latest scan | Pending | |
| Result/Summary open from new scan | Pass | Result payload from scan `#202` contained no blank current values for passed checks. |
| PDF export opens | Pending | |
| Excel export opens | Pending | |
| Baseline upload success | Pending | |
| Baseline delete success | Pending | |
| Schedule create/update/delete | Pending | |
| Autofix selected-only queue | Pass | Audit, registry, multi-registry, Defender registry, account policy, firewall profile, and user rights validated individually. |
| Autofix history visible | Pass | Jobs were recorded against the source scan and returned by the history API. |
| Rollback queue | Pass | Defender, firewall, user rights, audit, registry, and multi-registry values restored. |
| Rescan after Autofix/Rollback | Pass | Apply verification scans included `#199`, `#200`, and `#201`; final restored-state scan was `#202`. |
| Activity Log records major actions | Pending | |

## Environment Snapshot

- Frontend URL: `http://192.168.105.11:5173`
- Backend URL: `http://192.168.105.11:8000`
- Database mode: PostgreSQL
- Agent ID: `agent-WIN-50F5TDGIP70`
- Agent version/build: See Agent Management runtime value
- Latest scan ID: `202`
- Tester: Boat / Codex
- Date: June 24, 2026

## Autofix E2E Evidence

| Fix type | Apply evidence | Verification | Rollback evidence |
| --- | --- | --- | --- |
| Audit policy | `Audit PNP Activity` changed from `No Auditing` to `Success` | Scan `#183` passed | Returned to `No Auditing` |
| Registry | Lock-screen camera DWORD changed from missing to `1` | Scan `#184` passed | Registry value removed |
| Multi-registry | Three FeatureControl values changed from missing to `1` | All three values read directly from Windows | All three values removed |
| Defender registry | Job `4e92bfc6-4999-42b3-bfc3-69aea5a511db` | Scan `#199` passed and displayed `Enabled (1)` | Job `3cebc5e6-fa39-40c0-82a5-c801d3ebab7a`; value removed |
| Security policy | Account Lockout chain applied in prerequisite order | Scan `#190` showed `15 / 10 / 15` as compliant | Current desired values retained |
| Firewall profile | Job `f03799c3-fca8-4165-a7c9-b4516fa50444` enabled inactive Domain profile | Scan `#200` passed | Job `ae9677eb-0526-4c7f-9b9b-f2cf4eed51b3`; Domain profile returned Off |
| User rights | Job `a6de9aae-0b4b-43db-94cb-bb505c3cc4ac` set `SeDenyNetworkLogonRight` | Scan `#201` passed | Job `318d9f29-ad8d-4be3-b5e9-ada8d41fb01a`; assignment returned to missing |
| Service startup | Handler validation/no-op only; no failed service candidate existed | Automatic/Manual/Disabled accepted; invalid value rejected | No setting change required |

Final restored-state scan `#202` confirmed:

- `96` passed checks
- `0` passed checks with blank `current_value`
- `0` passed checks displaying an unexplained raw Boolean `0` or `1`
- Restored Defender, firewall, audit, multi-registry, and user-right checks returned to their original failed state
