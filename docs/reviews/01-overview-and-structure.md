# Part 1 of 8: Overview & Structure

**Scope:** Root `README.md`, navigation, lab architecture, build/test validation.

---

## Verdict: Strong foundation

This reads like a deliberate SOC analyst portfolio, not a generic GitHub dump. The README gives hiring managers a clear path, incidents are evidence-backed, and automation is testable.

**Tests:** 61 passed (~1.7s).

---

## What works well

### 1. Hiring-manager UX

The **10-Minute Hiring Manager Path** is one of the strongest parts of the repo:

- Anchor case (phishing)
- Prioritization under volume (shift triage)
- Automation (`parse_email.py`)
- Reproducible validation (`pytest`)

### 2. Honest framing

Timeline disclaimers and lab-sanitized IPs (`203.0.113.0/24`) show integrity. Pedagogical narrative order differs from execution order — and you say so.

### 3. Skill-to-evidence mapping

README tables tie domains (phishing, identity, endpoint, tuning, PCAP) to concrete artifacts. Interviewers can ask “show me your KQL” and land on real files immediately.

### 4. Dual-lab architecture

On-prem (Wazuh, Suricata, Splunk, AD) plus Azure (Sentinel, Defender, Entra) mirrors hybrid SOC environments.

### 5. Reproducibility

`build.ps1`, local IOC enrichment (no API keys required), and pytest make claims verifiable.

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Medium | Folder name `poert` vs public repo `Portfolio` | Resolved — Recommend user rename local folder to match GitHub 'Portfolio' repository name |
| Medium | Incident IDs (001–006) ≠ walk-through order (005 first) | Add a “Start here” badge on INC-005 in the cases table |
| Low | Cert verify URLs on website are generic | Add direct credential URLs if available |
| Low | `archive/` duplicates resume content | Keep `docs/master_resume_bullets.md` as single source of truth |
| Low | No CI badge in README | Add “61 tests passing” badge or GitHub Actions workflow |

---

## Anchor case spot-check (INC-2026-005)

The flagship incident holds up: staged conclusions, multi-layer correlation, proportionate containment, SEG bypass note on password-protected ZIPs.

**Minor nit:** SHA256 shown as truncated (`9c4e...a1f2`) — ensure full hash exists in `artifacts/phishing_analysis.md`.

---

## Scorecard (Part 1)

| Criterion | Score | Notes |
|-----------|-------|-------|
| First impression / navigation | 9/10 | Clear paths for busy reviewers |
| Technical credibility | 9/10 | Evidence chains, not buzzwords |
| Honesty / lab transparency | 10/10 | Disclaimers done right |
| Reproducibility | 9/10 | Tests + build script |
| Breadth | 9/10 | 6 incidents + supplemental network modules |

---

[Next: Part 2 — Website](02-website.md) · [Index](README.md)