# Scenario 04 — Phishing to Host (Caldera)

**Incident Record:** [`INC-2026-005`](../../incidents/INC-2026-005-phishing-chain.md)

## Objective

End-to-end chain: email header analysis → user report → endpoint execution via Caldera.

## Phases

### Phase A — Email (Manual / Documented)

Simulate user report using headers in `phishing/email-header-analysis.md`.

Tier 1 completes SPF/DKIM/DMARC analysis and extracts URLs.

### Phase B — Endpoint (Caldera)

| Setting | Value |
|---------|-------|
| Adversary | `T1-Phish-to-Host` |
| Agent | WKSTN-042 |
| Trigger | Run 2 min after documenting "user click" time |

## Expected Alerts

| Source | Signal |
|--------|--------|
| Sentinel | PowerShell download cradle |
| Sysmon | EID 1, 4104 (if script logging on) |
| Proxy | Blocked or allowed URL to malicious domain |

## Lab Replay Checklist

- [ ] Document email headers in ticket
- [ ] Mail trace for other recipients
- [ ] Correlate click time with Caldera ability finish time
- [ ] Complete [`incidents/INC-2026-005-phishing-chain.md`](../../incidents/INC-2026-005-phishing-chain.md)
- [ ] Block domain at proxy

## MITRE Mapping

| Technique | Name |
|-----------|------|
| T1566.001 | Phishing: Spearphishing Attachment/Link |
| T1204.002 | User Execution: Malicious File |
| T1059.001 | PowerShell |
| T1071.001 | Web Protocols (C2) |

## Skills Practiced

Email header forensics, user interaction, cross-source correlation, phishing containment.