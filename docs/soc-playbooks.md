# Tier 1 SOC Playbooks

Operational procedures used across all scenarios in this portfolio (Caldera, lab-script, and organic alerts).

## Alert Triage (First 15 Minutes)

```
Alert fires → Acknowledge in SIEM/osTicket → Check duplicate → Assign severity
     │
     ├─► Gather: hostname, user, timestamp, rule name, MITRE ID
     ├─► Validate: Is activity expected? (patch window, admin task, scanner)
     ├─► Enrich: Asset owner, criticality, recent related alerts, IOC lookup
     └─► Decide: Close (FP) │ Monitor │ Contain │ Escalate to T2/IR
```

### Severity Matrix (Lab / Production-aligned)

| Level | Criteria | Tier 1 Action |
|-------|----------|---------------|
| P1 — Critical | Active C2, domain admin compromise, ransomware | Contain immediately, call IR on-call |
| P2 — High | Confirmed malware execution, credential dumping | Isolate host, escalate within 30 min |
| P3 — Medium | Suspicious but unconfirmed (single beacon, odd DNS) | Investigate 1 hr, enrich IOCs |
| P4 — Low | Policy violation, reconnaissance | Document, monitor 24 hr |
| P5 — Informational | Honeypot, known scanner | Close with note |

## False Positive Analysis Checklist

1. **Business context** — Was there a change ticket? VPN vendor IP? Vulnerability scan?
2. **User confirmation** — Did the named user perform the action?
3. **Frequency** — One-off vs. recurring pattern
4. **Parent process** — Legitimate updater vs. `cmd.exe` → `powershell.exe`
5. **Network destination** — Known SaaS vs. young domain / bulletproof host
6. **Tune vs. close** — If FP repeats, propose rule exception with expiration date

Documented example: `incidents/INC-2026-004-false-positive-vpn.md`

## Escalation Criteria (Tier 1 → Tier 2 / IR)

Escalate when any of the following are true:

- Confirmed malware or C2 on a server or privileged workstation
- Multiple hosts with same IOC within 1 hour
- Domain Admin or service account involved in suspicious logon
- Data exfiltration indicators (large egress, DNS tunneling score high)
- Ransomware precursors (vssadmin delete shadows, bcdedit recovery off)
- Unable to contain within Tier 1 authority (no EDR isolate permission)

Use template: `templates/escalation-template.md`

## Containment Actions (Tier 1 Authorized)

| Action | Windows / Cloud | Ticket Note |
|--------|----------------|-------------|
| Network isolate | MDE / Sentinel isolate | "Host isolated per IR-####" |
| Disable user | Entra block sign-in / ADUC | Link to account alerts |
| Revoke sessions | Entra revoke refresh tokens | Required after identity compromise |
| Block IOC | Firewall / proxy / CA policy | Include TTL and review date |
| Kill process | taskkill / EDR | Capture PID and hash first |

## Evidence Preservation

Before eradication:

1. Export SIEM events (±30 min window) to case folder
2. Collect EDR timeline / process tree screenshot
3. Hash suspicious files: `Get-FileHash` / `sha256sum`
4. Optional: full memory capture (escalate to T2 if required)
5. Record Caldera operation ID if lab validation

## Post-Incident Documentation

Required fields (see `templates/incident-report.md`):

- Incident ID, detection source, MITRE mapping
- UTC timeline (detection → containment → recovery)
- Affected assets and accounts
- Evidence table (IOCs, log snippets, screenshots)
- Actions taken and who approved them
- Root cause (for lab: which Caldera ability triggered alerts)
- Recommendations (detection tune, hardening, training)