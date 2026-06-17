# Phishing → Endpoint Compromise (Caldera T1-Phish-to-Host)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-005 |
| **Ticket** | SEC-48340 |
| **Severity** | P2 |
| **MITRE** | T1566.001, T1204.002, T1059.001, T1071.001 |
| **Caldera Profile** | T1-Phish-to-Host |
| **Related** | Email analysis: `email-header-analysis.md` |
| **Analyst** | Praisel Ekpenyong |

---

## 1. Detection

Dual detection path:

1. **13:57 UTC** — User reported suspicious email (ServiceDesk → SOC)
2. **14:01 UTC** — Sentinel: PowerShell download cradle on WKSTN-042

---

## 2. Validation

| Email indicators | Endpoint indicators |
|------------------|---------------------|
| SPF/DKIM/DMARC fail | `powershell.exe -enc ...` parent `outlook.exe` |
| Spoofed vendor domain | File write to `%TEMP%\update.ps1` |
| Reply-To ProtonMail | Outbound HTTP to 10.10.30.10:8888 (Caldera lab C2) |

**True positive** — phishing led to code execution.

---

## 3. Enrichment

### Email IOCs

| IOC | Type |
|-----|------|
| `login-update.tk` | Domain |
| `203.0.113.88` | Sending IP |
| `attacker-drop@protonmail.com` | Reply-To |

### Endpoint IOCs

| IOC | Type |
|-----|------|
| `%TEMP%\update.ps1` | File |
| `10.10.30.10:8888` | C2 URL |
| SHA256 `b7e2...4f91` | Script hash |

---

## 4. Containment

| Time | Action |
|------|--------|
| 14:05 | Reset `jsmith` password |
| 14:06 | Isolate WKSTN-042 |
| 14:08 | Block `login-update.tk` on proxy |
| 14:10 | Mail trace — 3 other recipients; no other clicks |

---

## 5. Eradication

- Quarantine `update.ps1`
- Remove persistence (none beyond Caldera sandcat)
- Stop Caldera operation

---

## 6. Recovery

- Reimage not required — clean scan
- User training scheduled
- Host returned 16:30 UTC

---

## 7. Escalation

Tier 2 for mail gateway policy review (DMARC `p=none` on lookalike domain).

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 13:55 | Phishing email delivered |
| 13:58 | User clicked link |
| 13:59 | PowerShell cradle executed |
| 14:00 | Caldera T1-Phish-to-Host abilities complete |
| 14:01 | Sentinel alert |
| 14:05 | Containment |
| 16:30 | Closed |

---

## 9. Recommendations

1. Move DMARC to `p=quarantine` for vendor domains category
2. Attack simulation training — report phish button
3. ASR rule: block Office child process PowerShell
4. Annual Caldera phishing chain regression test