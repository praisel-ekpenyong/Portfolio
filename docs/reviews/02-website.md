# Part 2 of 8: Website

**Scope:** `website/index.html`, `styles.css`, `script.js`, SEO assets.

---

## Verdict: Polished and professional

The site looks intentional, not templated. Dark SOC aesthetic, strong copy, and incident cards linking to real write-ups. For a zero-build static site, this is above the bar for junior SOC portfolios.

---

## What works well

### Visual design & branding

- Cohesive dark theme with documented contrast ratios
- Syne + DM Mono typography fits security/ops
- ID badge / lanyard hero is memorable and on-brand
- Animated background adds depth without hurting readability

### Content strategy

- Hero copy names real tools (Splunk, Sentinel, Defender, Wazuh, Suricata, Wireshark)
- **“What I can do on day one”** panel sets honest expectations for hiring managers
- Project cards surface MITRE tags and incident IDs
- Default “See More” shows 3 of 6 cases; INC-2026-005 is first in the array

### Technical implementation

- No framework, no build step — easy GitHub Pages deploy
- IntersectionObserver for scroll spy, reveal animations, navbar tint
- Contact form: Formspree primary + clipboard/mailto fallback
- Mobile menu: `aria-expanded`, Escape key, focusout handling

### SEO & discoverability

- Open Graph, canonical URL, Person schema.org JSON-LD
- `sitemap.xml` and `robots.txt` configured

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Medium | Welcome screen runs **3.2s on every visit** | Skip on return visits or add “Skip intro” |
| Medium | `snippet` fields in `PROJECTS` never rendered; `.project-snippet` CSS unused | Render snippets on cards |
| Medium | Cert verify links go to generic pages | Use personal credential URLs |
| Low | No `prefers-reduced-motion` support | Disable heavy animations when requested |
| Low | Global scrollbar hidden | Consider showing on desktop |
| Low | `website/README.md` says contact is “mailto-based” | Document Formspree |
| Low | Tech stack count: README says 14, `TECH_STACKS` has 15 | Sync README |
| Low | No website links to shift triage, scripts, or detections | Add “Beyond incidents” panel or similar |

**Note:** Quick fixes for snippets and lab links were prototyped then **reverted** per author preference. Issues remain open.

---

## Section notes

| Section | Assessment |
|---------|------------|
| Welcome | Strong first impression; risky for repeat visitors |
| Hero | Clear CTAs; card visual hidden below 900px |
| About | Honest lab framing; stats tied to real data |
| Portfolio | Informative cards; missing technical snippets |
| Contact | Solid validation + fallback paths |
| Accessibility | Good `:focus-visible` and `.sr-only`; missing skip-link and tab ARIA roles |

---

## Scorecard (Part 2)

| Criterion | Score | Notes |
|-----------|-------|-------|
| Visual polish | 9/10 | Stands out among SOC portfolios |
| Clarity of role target | 10/10 | “Junior SOC Analyst” explicit |
| Evidence accessibility | 7/10 | Write-ups linked; lab depth not surfaced on site |
| Mobile experience | 8/10 | Breakpoints at 767/900/1024px |
| Trust signals | 7/10 | Generic cert verify URLs |

---

## Top 3 quick wins

1. Render query snippets on investigation cards
2. Skip welcome screen on repeat visits
3. Link shift triage doc or `parse_email.py` from the site

---

[Previous: Part 1](01-overview-and-structure.md) · [Next: Part 3](03-inc-2026-005-phishing.md) · [Index](README.md)