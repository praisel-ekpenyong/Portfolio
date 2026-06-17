# Caldera Operations Runbook

Step-by-step procedure to execute portfolio scenarios and produce SIEM-ready incidents.

## Standard Operation Workflow

### 1. Plan

| Field | Example |
|-------|---------|
| Operation name | `2026-06-17-INC001-BITS-LAB` |
| Adversary | T1-Windows-Download-Exec |
| Group | blue-team-lab |
| Target | Single agent WKSTN-042 |

### 2. Execute

1. Log in to Caldera → **Operations** → **New Operation**
2. Select adversary profile and agent group
3. Click **Start** — record UTC start time
4. Monitor **Operations graph** for ability completion (green = success)
5. Open SIEM — wait for correlated alerts (typically 1–5 minutes)

### 3. Validate (Tier 1)

Cross-check three data points:

```
Caldera ability finished time  ≈  SIEM alert time  ≈  Sysmon EventRecordID time
```

If mismatch > 5 minutes, check agent clock sync (NTP) and ingestion delay.

### 4. Investigate

Follow linked incident report playbook. Example for BITS scenario:

- Splunk: `index=sysmon EventCode=1 CommandLine=*bitsadmin*`
- Wazuh: filter rule.id `180001`
- Sentinel: `AlertName == "Suspicious BITS transfer"`

### 5. Stop & Cleanup

1. **Stop** operation in Caldera
2. Confirm cleanup abilities executed
3. Re-run health check on agent (still ALIVE = expected; sandcat remains until manual removal for next op)

## Operation Log Template

Copy into osTicket internal note:

```
Caldera Operation ID: [UUID from UI]
Adversary Profile: [name]
Start (UTC): [timestamp]
End (UTC): [timestamp]
Agents: [hostname / paw]
Abilities completed: [list]
Abilities failed: [list]
SIEM alerts generated: [IDs]
Analyst: Praisel Ekpenyong
```

## Scenario Execution Order (Portfolio Interview Order)

| Day | Operation | Incident Doc | Skill Highlight |
|-----|-----------|--------------|-----------------|
| 1 | T1-Phish-to-Host + email triage | INC-2026-005 | Staged conclusions, headers, endpoint link |
| 2 | Entra password spray (lab script) | INC-2026-002 | Identity triage, post-auth checks |
| 3 | T1-Windows-Download-Exec | INC-2026-001 | LOLBin, benign vs malicious comparator |
| 4 | T1-Scheduled-Task | INC-2026-003 | Persistence baseline, task XML |
| 5 | VPN FP exercise | INC-2026-004 | False positive discipline, rule tuning |

**Supplemental (stretch):** `T1-Windows-Lateral` — see [`network/supplemental-rdp-lateral-case.md`](../network/supplemental-rdp-lateral-case.md).

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Agent not checking in | Verify `app.contact.http` in Caldera config matches agent `-server` URL |
| Ability stuck pending | Check agent privilege (some abilities need elevated sandcat) |
| No SIEM alert | Confirm Sysmon/Wazuh agent running; test with benign logon event |
| Duplicate alerts | Expected — practice dedup and parent ticket linking |