# Part 3 of 8: INC-2026-005 (Phishing Chain)

**Scope:** [`incidents/INC-2026-005-phishing-chain.md`](../../incidents/INC-2026-005-phishing-chain.md) and supporting artifacts.

**Role in portfolio:** Anchor case — hiring managers are directed here first.

---

## Verdict: Interview-ready anchor case

Shows Tier 1 thinking (staged conclusions, proportionate response) and multi-layer correlation (email → EDR → firewall → PCAP). Most junior candidates cannot connect these layers in one narrative.

**Overall case grade: A / A-**

---

## What works exceptionally well

1. **Staged conclusion model** — Delivery ≠ execution ≠ compromise; quotable in interviews
2. **Multi-source correlation** — Headers, Defender/KQL, pfSense syslog, Wireshark frame numbers
3. **SEG bypass analysis** — Password-protected ZIP evasion is production-relevant
4. **Proportionate containment** — Password reset as precaution without overstating cred theft
5. **Supporting ecosystem** — `.eml`, `phishing/email-header-analysis.md`, `parse_email.py`, ticket #48340, shift doc rows, screenshots

### Ticket metrics

Ticket #48340: **4 min acknowledge**, **9 min contain** — aligns with incident timeline (13:57 report → 14:06 isolation).

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Medium | SHA256 mismatch: incident shows `9c4e...a1f2`; `artifacts/phishing_analysis.md` has full hash | Use script output hash in incident doc |
| Low | Source port inconsistency: Suricata `50412` vs firewall/PCAP `49811` | Align or annotate |
| Low | Suricata rule cites “SSL Blacklist” for HTTP `:8888` | Clarify Caldera C2 fingerprint context |
| Low | No inline link to ticket #48340 | Add `tickets/sample-tickets.md#L109` |
| Low | `phishing_analysis.md` not in Evidence table | Link as machine-generated triage |
| Low | KQL blocks lack sample result rows | Add anonymized result table |

---

## Section assessment

| Section | Score | Notes |
|---------|-------|-------|
| Executive summary | Strong | Clear P2; MITRE map tied to artifacts |
| Detection | Strong | User report before automated alerts |
| Email validation | Good | Thin on hash — expand from script |
| Endpoint correlation | Excellent | Best section; dual KQL + PCAP frames |
| Containment → escalation | Strong | DMARC policy escalation is a nice touch |
| Skills demonstrated | Accurate | Could add `parse_email.py` automation |

---

## Interview talking points

1. Walk through staged conclusion table
2. How you ruled out credential theft
3. Email-to-endpoint IOC correlation
4. Production deltas (DMARC enforcement, SEG sandbox)
5. Demo: `python scripts/parse_email.py --input artifacts/phishing-invoice.eml`

---

## Scorecard

| Criterion | Score |
|-----------|-------|
| Investigation methodology | 10/10 |
| Technical depth | 9/10 |
| Documentation clarity | 9/10 |
| IR process adherence | 9/10 |
| Differentiation vs peers | 10/10 |

---

## Highest-impact fix

Update Section 3 attachment hash from `artifacts/phishing_analysis.md` and cross-link that file in Section 10.

---

[Previous: Part 2](02-website.md) · [Next: Part 4](04-inc-2026-002-entra-spray.md) · [Index](README.md)