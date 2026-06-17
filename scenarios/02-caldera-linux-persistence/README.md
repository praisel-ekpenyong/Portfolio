# Scenario 02 — Linux Persistence (Caldera)

## Objective

Practice Linux log analysis, account abuse detection, and cron persistence identification.

## Caldera Setup

| Setting | Value |
|---------|-------|
| Adversary | `T1-Linux-Persistence` |
| Agent | SRV-LNX-01 |
| Abilities | useradd → crontab → cleanup userdel |

## Expected Alerts

| Source | Identifier |
|--------|------------|
| Wazuh | 5902 (user add), 180010 (cron C2 pattern) |
| auth.log | `useradd` entries |
| auditd | execve `/usr/sbin/useradd` |

## Tier 1 Tasks

- [ ] Correlate auth.log + auditd timestamps
- [ ] Run Sentinel KQL `detections/sentinel/linux_account_cron.kql`
- [ ] Block egress to Caldera IP at firewall
- [ ] Document in `incidents/INC-2026-002-linux-account-creation.md`
- [ ] Escalate to Linux SME

## MITRE Mapping

| Technique | Name |
|-----------|------|
| T1136.001 | Create Account: Local Account |
| T1053.003 | Cron |
| T1531 | Account Access Removal (cleanup) |

## Skills Practiced

Linux authentication logs, auditd, server-tier escalation, firewall containment.