# INC-2026-002 — Unauthorized Local Account & Cron Persistence (Caldera T1-Linux-Persistence)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-002 |
| **osTicket** | #48305 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh Rule 5902, 2832 |
| **Caldera Operation** | `2026-06-18-LNX-PERSIST-LAB` |
| **MITRE ATT&CK** | T1136.001, T1053.003, T1531 (cleanup) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 1 — On-Premises SOC (`corp.lab.local`) |

---

## 1. Detection

**2026-06-18 09:14:22 UTC** — Wazuh:

```
Rule 5902 — New user added to the system
Host: SRV-LNX-01 (10.10.20.15)
User added: caldera_svc
```

**09:14:55 UTC** — Wazuh Rule 2832 — Crontab change detected.

---

## 2. Validation

| Check | Result |
|-------|--------|
| Change ticket for new service account? | None found |
| Naming convention match? | No — `caldera_svc` not in CMDB |
| Crontab entry | `*/5 * * * * curl -s http://10.10.30.10:8888/beacon` |
| SSH source for useradd | Local session (not authorized admin IP) |
| Caldera correlation | T1136.001 ability finished 09:14:20 UTC |

**Determination:** True positive — unauthorized persistence on production-adjacent app server.

---

## 3. Enrichment

### Asset

| Attribute | Value |
|-----------|-------|
| Hostname | SRV-LNX-01 |
| Role | Internal web application server |
| Criticality | High |
| Exposure | Internal only, no direct internet |

### Linux Log Correlation

```bash
# auth.log
Jun 18 09:14:20 SRV-LNX-01 useradd[8842]: new group: name=caldera_svc
Jun 18 09:14:21 SRV-LNX-01 useradd[8842]: new user: name=caldera_svc UID=1003 GID=1003

# audit.log (execve)
type=SYSCALL ... exe="/usr/sbin/useradd" ... a0="caldera_svc"
```

### IOC Table

| IOC | Type | Notes |
|-----|------|-------|
| `caldera_svc` | Linux account | UID 1003 — unauthorized |
| `10.10.30.10:8888/beacon` | URL | Caldera C2 (lab) |
| `/var/spool/cron/crontabs/root` modified | File | Malicious cron |

---

## 4. Containment

| Time (UTC) | Action |
|------------|--------|
| 09:25:00 | Blocked egress from SRV-LNX-01 to 10.10.30.10 via pfSense |
| 09:27:00 | Disabled cron for root: `systemctl stop cron` (temporary) |
| 09:30:00 | Notified app owner — maintenance window for investigation |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 09:45:00 | Removed malicious crontab lines; restored from backup |
| 09:50:00 | `userdel -r caldera_svc` |
| 09:55:00 | Killed sandcat agent process (PID 9012) |
| 10:00:00 | Caldera operation stopped — T1531 cleanup ability confirmed account removal |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 10:15:00 | Restarted cron; verified legitimate jobs only |
| 10:20:00 | Re-enabled egress after C2 block no longer needed |
| 10:30:00 | Full rootkit check — `rkhunter --check` — clean |

---

## 7. Escalation

Escalated to **Linux SME / Tier 2** at 09:35 UTC due to high-criticality server and persistence mechanism.

Tier 2 confirmed no web shell or additional backdoors.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 09:12:00 | Caldera op started on SRV-LNX-01 |
| 09:14:20 | useradd executed |
| 09:14:22 | Wazuh 5902 alert |
| 09:14:50 | Crontab modified |
| 09:14:55 | Wazuh 2832 alert |
| 09:20:00 | Tier 1 investigation began |
| 09:25:00 | Network containment |
| 10:00:00 | Eradication complete |
| 10:30:00 | Incident closed |

---

## 9. Evidence — Splunk SPL

```spl
index=linux host=SRV-LNX-01
| search "useradd" OR "crontab" OR "caldera_svc"
| sort _time
| table _time source sourcetype _raw
```

## Sentinel (Syslog Forwarder)

```kql
Syslog
| where Computer == "SRV-LNX-01"
| where SyslogMessage has_any ("useradd", "crontab", "caldera_svc")
| project TimeGenerated, SyslogMessage
```

---

## 10. Recommendations

1. Restrict `useradd` to sudoers group monitored by auditd (already partially in place — tune alert threshold).
2. File integrity monitoring on `/var/spool/cron/crontabs/`.
3. Require break-glass approval for root crontab edits on tier-1 servers.
4. Quarterly Caldera replay of T1-Linux-Persistence profile.

---

## 11. Post-Incident Summary

Unauthorized local account and cron-based beaconing detected within 3 minutes of Caldera ability execution. Containment limited blast radius to single Linux host. Demonstrates Tier 1 competency in Linux auth log analysis, cron investigation, and coordination with server owners.