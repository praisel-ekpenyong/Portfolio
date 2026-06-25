# Praisel Ekpenyong — SOC Analyst Portfolio (Static HTML/CSS/JS)

A dark-themed, single-page portfolio website. **No build step, no framework, no dependencies** — just open `index.html` in a browser.

## Quick Start

```bash
# Option 1: Just open the file
open index.html          # macOS
xdg-open index.html      # Linux
start index.html         # Windows

# Option 2: Run a local server (recommended — avoids file:// CORS issues)
python3 -m http.server 8000
# Then open http://localhost:8000
```

## What's Included

- **6 incident case studies** linking to real write-ups on GitHub
- **14 tech-stack logos** (Splunk, Sentinel, Defender, Entra ID, Wazuh, Sysmon, Active Directory, PowerShell, Wireshark, pfSense, VirusTotal, Python, Caldera, osTicket)
- **3 certifications** (CompTIA Security+, Microsoft SC-200, Google Cybersecurity)
- **Contact form** with validation (mailto-based)
- **Welcome screen** with hero animation (GSAP card-drop + typewriter)
- **Responsive design** (mobile, tablet, desktop)

## File Structure

```
website/
├── index.html        — full page markup (all 4 sections)
├── styles.css        — all styling (1200 lines, dark theme)
├── script.js         — all logic (data, animations, interactions)
└── assets/
    ├── card-photo.webp              — profile photo
    ├── Praisel_Ekpenyong_CV.pdf     — downloadable CV
    └── techstack/                   — 14 brand logos (PNG + SVG)
        ├── splunk-enterprise.png
        ├── microsoft-sentinel.png
        ├── defender-endpoint.svg
        ├── entra-id.png
        ├── wazuh.png
        ├── sysmon.png
        ├── active-directory.png
        ├── powershell-logs.png
        ├── wireshark.png
        ├── pfsense.svg
        ├── virustotal.png
        ├── python-automation.png
        ├── caldera.png
        └── osticket.png
```

## Customization

Edit `script.js` to change:
- `PROJECTS` array — investigation cards (line ~10)
- `CERTIFICATES` array — certification cards (line ~75)
- `TECH_STACKS` array — tech stack logos (line ~85)
- `CONTACT_EMAIL` — where the contact form sends mail (line ~3)
- `TYPEWRITER_PHRASES` — hero typewriter text (line ~105)

## External Dependencies

- **Google Fonts** (Syne + DM Mono) — loaded via `<link>` in `index.html`
- **GSAP 3.12** — loaded via CDN in `index.html` (for the card-drop animation only)

Everything else is self-contained. No npm, no bundler, no build step.

## Deploy

Upload the entire `website/` folder to any static host:
- GitHub Pages
- Netlify
- Vercel
- Cloudflare Pages
- Any web server (Apache, Nginx, Caddy)

---

© 2026 Praisel Ekpenyong
