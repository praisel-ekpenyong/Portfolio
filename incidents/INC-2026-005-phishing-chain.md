# INC-2026-005 — Phishing Email Triage with Endpoint Correlation (Case #1)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-005 |
| **Portfolio order** | **1 — Anchor case** |
| **osTicket** | #48340 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | User report + Sentinel PowerShell rule |
| **Caldera Operation** | `2026-06-20-PHISH-LAB` |
| **MITRE ATT&CK** | T1566.001, T1204.002, T1059.001, T1071.001 |
| **Related** | [`phishing/email-header-analysis.md`](../phishing/email-header-analysis.md) · [`artifacts/phishing-invoice.eml`](../artifacts/phishing-invoice.eml) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Cloud SOC (Sentinel, Defender, Entra ID) |

---

## 1. Detection

1. **13:57 UTC** — Employee reported suspicious email (ServiceDesk → SOC)
2. **14:01 UTC** — Sentinel: PowerShell from `outlook.exe` parent on WKSTN-042

**Subject reported:** `URGENT: Invoice #88421 — password inside email body`  
**Attachment:** `Invoice_June2026.zip` (password-protected) containing `Invoice.lnk` shortcut.

---

## 2. Staged Conclusion (do not collapse)

| Stage | Status | Evidence |
|-------|--------|----------|
| **Email delivered** | Yes | Mail gateway accepted; `.eml` preserved |
| **Email opened** | Yes | User confirmed reading body for ZIP password |
| **Attachment opened** | Yes | `Invoice.lnk` executed — Sysmon EID 1, user `jsmith` |
| **Payload executed** | Yes | `powershell.exe -enc ...` → `%TEMP%\update.ps1` |
| **Credentials submitted** | **No** | No form POST, no Entra failed/success auth to phish domain |
| **Account/device compromised** | **Contained** | Execution confirmed; isolation before mailbox rules or lateral movement |

**Tier 1 takeaway:** Delivery ≠ execution ≠ compromise. This case stopped at execution with no credential theft.

---

## 3. Email Validation

| Check | Result |
|-------|--------|
| SPF | **fail** — 203.0.113.88 not authorized |
| DKIM | **none** |
| DMARC | **fail** |
| Display vs envelope | `payable@vendor-secure.com` vs `bounce+xyz@mail.vendor-secure.com` |
| Reply-To | `attacker-drop@protonmail.com` (mismatch) |

### Attachment analysis

| Field | Value |
|-------|-------|
| File | `Invoice_June2026.zip` |
| SHA256 | `9c4e...a1f2` |
| Inner file | `Invoice.lnk` → launches `powershell.exe -enc ...` |
| Static analysis | Shortcut target obfuscated; no legitimate invoice PDF |

---

## 4. Endpoint Correlation

| Email IOC | Endpoint match |
|-----------|----------------|
| `login-update.tk` | Proxy deny at 13:59 UTC |
| `203.0.113.88` | Sending IP in headers |
| LNK → PowerShell | Defender: `outlook.exe` → `powershell.exe` at 13:59 UTC |
| C2 `10.10.30.10:8888` | Outbound HTTP post-execution (lab Caldera) |

```kql
DeviceProcessEvents
| where DeviceName == "WKSTN-042"
| where Timestamp between (datetime(2026-06-20 13:55:00) .. datetime(2026-06-20 14:10:00))
| where FileName =~ "powershell.exe" or InitiatingProcessFileName =~ "outlook.exe"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Mailbox scope

Mail trace: **3 other recipients** received same message — **no other clicks** in proxy/EDR telemetry.

---

## 5. Containment

| Time (UTC) | Action |
|------------|--------|
| 14:05 | Reset `jsmith` password (precaution — no cred theft confirmed) |
| 14:06 | Isolate WKSTN-042 |
| 14:08 | Block `login-update.tk` at proxy |
| 14:10 | Notify 3 other recipients — delete without opening |

---

## 6. Eradication & Recovery

Quarantined `update.ps1` and `Invoice.lnk`; stopped Caldera op. Host returned 16:30 UTC after clean scan.

---

## 7. Escalation

Tier 2 at 14:15 — DMARC `p=none` on lookalike vendor domain; policy change filed.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 13:55 | Email delivered |
| 13:57 | User report |
| 13:58 | User opened ZIP, executed LNK |
| 13:59 | PowerShell cradle |
| 14:01 | Sentinel alert |
| 14:06 | Host isolated |
| 16:30 | Closed |

---

## 9. Skills Demonstrated

- Header analysis without relying on reputation alone
- Delivery vs execution distinction
- Email + endpoint + proxy correlation
- Recipient scoping
- IOC extraction and documentation
- Proportionate containment (no overreaction on cred reset when no creds submitted)

---

## 10. Evidence

| Artifact | Path |
|----------|------|
| Sanitized .eml | `artifacts/phishing-invoice.eml` |
| Header walkthrough | `phishing/email-header-analysis.md` |
| Screenshots | `artifacts/screenshots/sentinel-inc005.png`, `defender-inc005.png`, `osticket-48340.png` |