# Demo-Ready Checklist

This checklist captures the minimum release and demo checks for MicrosoftScanEngine.

## Runtime Configuration

- Frontend: `http://<server>:5173`
- Backend API: `http://<server>:8000`
- Database: use `DATABASE_URL` from `.env` when PostgreSQL is ready.
- SQLite fallback: `sqlite:///C:/MicrosoftScanEngine/runtime/sql_app.db`
- Runtime folder: `C:\MicrosoftScanEngine\runtime`
- Installed agent executable: `C:\MicrosoftScanEngine\MicrosoftScanAgent.exe`
- Agent installer output: `agent\dist\ScanAgentSetup.exe`

PostgreSQL example:

```env
DATABASE_URL=postgresql+psycopg://scan_user:<password>@host.docker.internal:5432/scanner_db
```

Use `host.docker.internal` or a reachable host IP from inside the backend container. Do not use `localhost` for a host PostgreSQL service from a container.

## Release Hygiene

Commit source and configuration examples:

- `backend/`, `frontend/src/`, `agent/`, `tools/`
- `.env.example`
- `.gitignore`, `.dockerignore`, `frontend/.dockerignore`
- `docs/`

Do not commit runtime or generated files:

- `.env`
- `runtime/`
- `*.db`, `*.sqlite*`
- `packages/`
- `baselines/uploads/`
- uploaded root-level Excel files
- `agent/dist/`, `agent/build/`
- generated `*.exe`
- logs and local agent config files

## Demo Smoke Test

1. Login as admin or owner.
2. Confirm viewer users cannot see `Agents` or `Users`.
3. Open Home and verify the latest scan overview or `No data` state.
4. Start a new agent scan.
5. Start an agent subnet scan if multiple agents are available.
6. Open History and verify the latest scan appears.
7. Open Result and Summary reports.
8. Export PDF and Excel, then verify files open and show `Compliance Score`.
9. Upload a valid baseline Excel and verify baseline ID, name, and check count.
10. Delete a test baseline and confirm the UI warns that agents use the new package on the next job.
11. Create, disable, edit, and delete a scan schedule.
12. Confirm Agent Management shows agent version/build, for example `1.0.0+build...`.
13. Run a selected-only Autofix no-op where possible.
14. View Autofix History.
15. Run Rollback for the Autofix job.
16. Rescan the agent to verify compliance after Autofix or Rollback.
17. Open Activity Log and verify recent login, scan, export, baseline, schedule, Autofix, or Rollback actions.

## Autofix Safety Rules

- Autofix is selected-only. There is no Fix All in this release.
- Supported categories are limited to registry-backed settings, multi-registry FeatureControl style policies, registry-backed Defender allowlist items, allowlisted password/account policy, allowlisted user-right assignment, audit policy, service startup type, and firewall profile state.
- User-right assignment supports common well-known SIDs such as Authenticated Users, Administrators, and Enterprise Domain Controllers.
- Complex multi-line policies such as Hardened UNC Paths, VBS bundles, ASR rule bundles, or ambiguous user/browser template values stay manual unless a deterministic value mapping exists.
- `secedit`-backed fixes must show previous value capture and rollback support before demo use.
- Unsupported checks remain manual and should explain why they cannot be safely automated.
- Firewall Autofix can affect management ports, backend access, or RDP. Confirm access before applying.
- After Autofix or Rollback, always run a new scan to verify the final compliance result.

## Build Verification

Run these before a demo or handoff:

```powershell
python -m py_compile backend/main.py backend/app/core/agent_routes.py backend/app/core/export_routes.py agent/agent.py agent/setup.py
cd frontend
npm run build
```

For low-disk deploys, prefer targeted deployment:

```powershell
.\deploy.ps1 -BackendOnly
.\deploy.ps1 -FrontendOnly
```

Use a full rebuild only when base dependencies, Dockerfiles, or multi-stage build inputs change.
