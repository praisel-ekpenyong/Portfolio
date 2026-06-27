# Live Attack Simulation Guides

Step-by-step instructions to execute **all six portfolio cases** as **live** lab activity. Every run must produce real logs in your SIEM/EDR — not mock modes or log replay.

**Related docs:** [`../lab-architecture.md`](../lab-architecture.md) · [`../caldera-setup.md`](../caldera-setup.md) · [`../live-evidence-ledger.md`](../live-evidence-ledger.md) · [`../../caldera/adversary-profiles.md`](../../caldera/adversary-profiles.md)

---

## Case guides

| Day | Guide | Incident | Ticket |
|-----|-------|----------|--------|
| 1 | [INC-2026-005 — Phishing](INC-2026-005-phishing.md) | Phishing + endpoint correlation | #48340 |
| 2 | [INC-2026-002 — Entra spray](INC-2026-002-entra-password-spray.md) | Entra password spray | #48305 |
| 3 | [INC-2026-001 — BITS](INC-2026-001-bits-download.md) | BITS LOLBin download | #48291 |
| 4 | [INC-2026-003 — Scheduled task](INC-2026-003-scheduled-task.md) | Scheduled task persistence | #48318 |
| 5 | [INC-2026-004 — VPN FP](INC-2026-004-vpn-false-positive.md) | VPN false positive | #48322 |
| 6 | [INC-2026-006 — RDP lateral](INC-2026-006-rdp-lateral.md) | RDP lateral + sniffing | #48370 |

Run on **separate days** to avoid alert overlap on `WKSTN-042` / `jsmith`, or reset between cases (password reset, de-isolate hosts, stop Caldera ops).

---

## Before you start

### Safety and scope

- Run only in the isolated `corp.lab.local` / `pe-soc-lab` lab.
- Use test accounts (`jsmith`) and lab hosts (`WKSTN-042`, `WKSTN-099`) only.
- Red team (attack execution) and blue team (triage) can be the same person for portfolio work; for candidate assessment, hide the adversary profile name from the analyst.

### One-time lab prerequisites

| Component | Required for | Verify |
|-----------|--------------|--------|
| Caldera server `10.10.30.10:8888` | INC-001, 003, 005, 006 | UI login; plugins `stockpile`, `sandcat` enabled |
| Sandcat agents **ALIVE** on targets | Caldera cases | Group `blue-team-lab` |
| Sysmon + Wazuh agent on Windows hosts | INC-001, 003, 005, 006 | Test event appears in Wazuh |
| Splunk / Suricata on pfSense | INC-001, 005, 006 | `index=suricata` or syslog receiving |
| Sentinel + Defender + Entra connector | INC-001–006 (hybrid) | Data in Log Analytics |
| Wazuh rules `180001`–`180004` deployed | Endpoint detections | `detections/wazuh/local_rules.xml` |
| Sentinel analytics rules deployed | INC-002, 004, 005 | `detections/sentinel/` |
| Test user `jsmith@corp.lab` / `CORP\jsmith` | Most cases | Can log on to WKSTN-042 |
| Phishing `.eml` artifact | INC-005 | `artifacts/phishing-invoice.eml` |
| pfSense OpenVPN + syslog → Sentinel | INC-004 | `VPNLogs` table receives events |

### Create Caldera adversary profiles (one time)

In Caldera UI → **Campaigns → Adversaries**, create four profiles per [`caldera/adversary-profiles.md`](../../caldera/adversary-profiles.md):

| Profile | Abilities (order) | Default agent |
|---------|-------------------|---------------|
| `T1-Windows-Download-Exec` | BITS download → save payload → execute | WKSTN-042 |
| `T1-Scheduled-Task` | Create `ChromeUpdate` task → run script → cleanup on stop | WKSTN-042 |
| `T1-Phish-to-Host` | PowerShell cradle → write `%TEMP%` → HTTP beacon | WKSTN-042 |
| `T1-Windows-Lateral` | RDP lateral → registry port 8443 → `tcpdump.exe` | WKSTN-099 |

**Operation settings:** Autonomous ON · Jitter 20% · Planner `atomic` (or `batch` for assessment randomization within profile).

---

## Universal procedure (every case)

### Pre-run (red + blue)

1. Record **UTC start time** in a notepad and osTicket draft.
2. Confirm target host/agent is **ALIVE** (Caldera) or connector is healthy (Entra/VPN).
3. Confirm SIEM ingestion: run a benign test query (e.g. recent Sysmon EID 1 on target host).
4. Open the linked incident doc and ticket template [`templates/ticket-triage.md`](../../templates/ticket-triage.md).

### Post-run (evidence export — before cleanup)

1. Export Caldera operation JSON → `artifacts/caldera-operation-INC00X.json` (Caldera cases).
2. Export sample Wazuh alert + Sysmon JSON → `artifacts/logs/`.
3. Screenshot Sentinel/Wazuh/Defender with **UTC visible**.
4. Copy operation log template from [`caldera/operations-runbook.md`](../../caldera/operations-runbook.md) into osTicket internal note.
5. Update [`live-evidence-ledger.md`](../live-evidence-ledger.md) with actual run times.
6. Run `.\build.ps1` and `python -m pytest tests/`.

### Success criteria (all cases)

```text
Live action time  ≈  Source log time  ≈  SIEM alert time  (within ~5 min)
```

---

## Quick reference

| Incident | Tool | Profile / method | Host | Ticket |
|----------|------|------------------|------|--------|
| INC-2026-005 | Email + Caldera | `T1-Phish-to-Host` | WKSTN-042 | #48340 |
| INC-2026-002 | `emulate_o365spray.py` | Live API, 18+1 attempts | Entra cloud | #48305 |
| INC-2026-001 | Caldera | `T1-Windows-Download-Exec` | WKSTN-042 | #48291 |
| INC-2026-003 | Caldera | `T1-Scheduled-Task` | WKSTN-042 | #48318 |
| INC-2026-004 | Scanner / VPN client | Live `AUTH_FAILED` | pfSense VPN | #48322 |
| INC-2026-006 | Caldera | `T1-Windows-Lateral` | WKSTN-099 | #48370 |

---

## Optional — blind / randomized assessment mode

For candidates who must **not** know which attack is coming:

1. Build a **red-only** pool file (do not give to candidate):

   ```text
   T1-Windows-Download-Exec
   T1-Scheduled-Task
   T1-Phish-to-Host
   T1-Windows-Lateral
   LIVE_ENTRA_SPRAY
   LIVE_VPN_NOISE
   ```

2. Red team randomly picks one entry per session.
3. Caldera cases: start op with random profile; **do not** name the operation `INC-2026-00X` in the UI.
4. Entra/VPN: run live spray or live scanner per [INC-2026-002](INC-2026-002-entra-password-spray.md) and [INC-2026-004](INC-2026-004-vpn-false-positive.md).
5. Candidate receives **only** SIEM alerts + osTicket queue.
6. After debrief, map run to incident template and update ledger.

---

## Troubleshooting

| Problem | Check |
|---------|--------|
| No Caldera agent | Redeploy sandcat; verify `http://10.10.30.10:8888` from host |
| Ability fails | Agent privilege; ability command matches OS path |
| No Wazuh alert | Agent connected; rules 18000x loaded; `wazuh-logtest` |
| No Sentinel alert | Connector delay; wrong workspace; rule disabled |
| Spray no SigninLogs | Used `--mock` by mistake; tenant policy blocks ROPC |
| RDP lateral fails | Firewall; RDP disabled; wrong creds |
| Too many alerts on WKSTN-042 | Space cases by day; complete cleanup between ops |

---

## After all six cases

1. Complete all rows in [`live-evidence-ledger.md`](../live-evidence-ledger.md).
2. Close tickets in [`tickets/sample-tickets.md`](../../tickets/sample-tickets.md).
3. Run full validation:
   ```powershell
   .\build.ps1
   python -m pytest tests/
   ```
4. Optional: walk through [`tickets/high-volume-shift-example.md`](../../tickets/high-volume-shift-example.md) as a **prioritization debrief** (not a live replay).