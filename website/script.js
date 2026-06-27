// ── DATA ──────────────────────────────────────────────────
const GITHUB_BASE = 'https://github.com/praisel-ekpenyong/Portfolio/blob/main';
const CONTACT_EMAIL = 'ekpenyongpraisel@gmail.com';

const PROJECTS = [
  {
    id: 1,
    incident_id: 'INC-2026-005',
    title: 'Phishing Email Triage with Endpoint Correlation',
    description:
      'User-reported invoice phish correlated with Outlook spawning PowerShell on WKSTN-042, triggering a Suricata NIDS alert on outbound C2. SPF/DKIM/DMARC header analysis, phishing investigation across SIEM (Microsoft Sentinel), EDR (Microsoft Defender for Endpoint), and network layers, with proportionate containment before credential theft.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-005-phishing-chain.md`,
    mitre: ['T1566.001', 'T1059.001'],
  },
  {
    id: 2,
    incident_id: 'INC-2026-002',
    title: 'Password Spray & Successful Azure/Entra Sign-in',
    description:
      'Microsoft Sentinel (SIEM) detected 18 failed Entra sign-ins from a single Microsoft Azure IP followed by one success for a valid finance user. Validated account context via threat intelligence lookup, checked post-auth abuse (mailbox rules, OAuth consent, MFA changes), revoked sessions, and escalated as account-takeover risk.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-002-entra-password-spray.md`,
    mitre: ['T1110.003', 'T1078'],
  },
  {
    id: 3,
    incident_id: 'INC-2026-001',
    title: 'LOLBin Execution: BITS Download',
    description:
      'Wazuh HIDS, Suricata NIDS, and Microsoft Defender for Endpoint (EDR) flagged bitsadmin.exe downloading a payload to WKSTN-042 over HTTP. Validated by comparing Windows Event Logs, parent process, destination, user context, and change records against a benign SCCM baseline. Contained to one host, escalated to Tier 2.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-001-bits-job-download.md`,
    mitre: ['T1197', 'T1105'],
  },
  {
    id: 4,
    incident_id: 'INC-2026-003',
    title: 'Suspicious Scheduled Task Persistence',
    description:
      'Wazuh HIDS and Microsoft Defender for Endpoint (EDR) detected a scheduled task named ChromeUpdate executing PowerShell from a user-writable Temp path. Validated against SCCM baseline using Windows Event Logs (Event ID 4698), confirmed local to WKSTN-042 via DC scope check, and ran a multi-vector persistence sweep.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-003-scheduled-task-persistence.md`,
    mitre: ['T1053.005', 'T1059.001'],
  },
  {
    id: 5,
    incident_id: 'INC-2026-004',
    title: 'False Positive & Detection Tuning — VPN',
    description:
      'Microsoft Sentinel (SIEM) created a VPN brute-force alert after 47 failed OpenVPN attempts through the pfSense firewall from a scanner source. Validated zero valid users, zero successes, and a matching CHG-8821 geo-block change ticket. Closed as false positive and tuned the KQL rule to reduce alert noise.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-004-false-positive-vpn.md`,
    mitre: ['T1110.001'],
  },
  {
    id: 6,
    incident_id: 'INC-2026-006',
    title: 'RDP Lateral Movement & Network Sniffing',
    description:
      'Wazuh HIDS and Suricata NIDS flagged an RDP port modification (3389→8443) and tcpdump.exe execution on WKSTN-099 (Linux probe host). Traced lateral movement via TCP/IP from WKSTN-042 using compromised jsmith credentials, ran Wireshark/tshark pcap (packet analysis) to confirm zero data exfiltration across the network, and isolated both hosts.',
    live_url: `${GITHUB_BASE}/incidents/INC-2026-006-rdp-lateral-movement.md`,
    mitre: ['T1021.001', 'T1040', 'T1112'],
  },
];

const CERTIFICATES = [
  { id: 1, title: 'CompTIA Security+', issuer: 'CompTIA', date: '2024', verify_url: 'https://www.comptia.org/verify' },
  { id: 2, title: 'Microsoft SC-200 Security Operations Analyst', issuer: 'Microsoft', date: '2024', verify_url: 'https://learn.microsoft.com/credentials' },
  { id: 3, title: 'Google Cybersecurity Professional Certificate', issuer: 'Google / Coursera', date: '2024', verify_url: 'https://www.coursera.org/verify' },
];

const TECH_STACKS = [
  { id: 1,  name: 'Splunk Enterprise',               logo_url: 'assets/techstack/splunk-enterprise.png' },
  { id: 2,  name: 'Microsoft Sentinel',              logo_url: 'assets/techstack/microsoft-sentinel.png', white_bg: true },
  { id: 3,  name: 'Microsoft Defender for Endpoint', logo_url: 'assets/techstack/defender-endpoint.svg' },
  { id: 4,  name: 'Microsoft Azure',                 logo_url: 'assets/techstack/microsoft-azure.png', white_bg: true },
  { id: 5,  name: 'Entra ID',                        logo_url: 'assets/techstack/entra-id.png' },
  { id: 6,  name: 'Wazuh',                           logo_url: 'assets/techstack/wazuh.png' },
  { id: 7,  name: 'Sysmon',                          logo_url: 'assets/techstack/sysmon.png' },
  { id: 8,  name: 'Active Directory',                logo_url: 'assets/techstack/active-directory.png' },
  { id: 9,  name: 'PowerShell',                      logo_url: 'assets/techstack/powershell-logs.png' },
  { id: 10, name: 'Wireshark',                       logo_url: 'assets/techstack/wireshark.png' },
  { id: 11, name: 'pfSense Firewall',                logo_url: 'assets/techstack/pfsense.svg' },
  { id: 12, name: 'VirusTotal',                      logo_url: 'assets/techstack/virustotal.png' },
  { id: 13, name: 'Python',                          logo_url: 'assets/techstack/python-automation.png' },
  { id: 14, name: 'Apache Caldera',                  logo_url: 'assets/techstack/caldera.png' },
  { id: 15, name: 'osTicket',                        logo_url: 'assets/techstack/osticket.png' },
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
const WELCOME_SEEN_KEY = 'welcomeSeen';

function revealNavbar() {
  setTimeout(() => navbar.classList.add('visible'), 50);
}

function dismissWelcome() {
  welcome.classList.add('hide');
  triggerHeroAnim();
  revealNavbar();
}

if (sessionStorage.getItem(WELCOME_SEEN_KEY)) {
  welcome.style.display = 'none';
  navbar.classList.add('visible');
  triggerHeroAnim();
} else {
  setTimeout(() => {
    sessionStorage.setItem(WELCOME_SEEN_KEY, 'true');
    dismissWelcome();
  }, 3200);
  setTimeout(revealNavbar, 4200);
}

// ── HERO ANIMATION (GSAP card-drop) ───────────────────────
function triggerHeroAnim() {
  const heroPlayed = sessionStorage.getItem('heroPlayed');
  const delay = heroPlayed ? 0 : 800;
  setTimeout(() => {
    document.querySelectorAll('#h0,#h3,#h4,#h-btns,#h6').forEach(el => el.classList.add('show'));
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
setTimeout(typeLoop, sessionStorage.getItem(WELCOME_SEEN_KEY) ? 200 : 4200);

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
    document.getElementById('hamburger').setAttribute('aria-expanded', 'false');
  });
});

const hamburger = document.getElementById('hamburger');
const mobileMenu = document.getElementById('mobile-menu');

hamburger.addEventListener('click', () => {
  const isOpen = mobileMenu.classList.toggle('open');
  hamburger.setAttribute('aria-expanded', isOpen);
});

// Close mobile menu when focus leaves it
mobileMenu.addEventListener('focusout', () => {
  setTimeout(() => {
    if (!mobileMenu.contains(document.activeElement) && document.activeElement !== hamburger) {
      mobileMenu.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    }
  }, 50);
});

// Close mobile menu on Escape key
mobileMenu.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    mobileMenu.classList.remove('open');
    hamburger.setAttribute('aria-expanded', 'false');
    hamburger.focus();
  }
});

// ── NAVBAR SCROLL SPY & TINTS (IntersectionObserver) ─────
const sections = ['home','about','portfolio','contact'];

// Scroll sentinel to toggle scrolled class on navbar
const scrollSentinel = document.createElement('div');
scrollSentinel.style.position = 'absolute';
scrollSentinel.style.top = '0';
scrollSentinel.style.height = '20px';
scrollSentinel.style.width = '100%';
scrollSentinel.style.pointerEvents = 'none';
document.body.prepend(scrollSentinel);

const sentinelObserver = new IntersectionObserver(entries => {
  const isAtTop = entries[0].isIntersecting;
  navbar.classList.toggle('scrolled', !isAtTop);
}, { threshold: 0 });
sentinelObserver.observe(scrollSentinel);

// Active section spy
const observerOptions = {
  root: null,
  rootMargin: '-50% 0px -50% 0px', // Trigger when section occupies viewport center
  threshold: 0
};

const navObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      document.querySelectorAll('[data-section]').forEach(a => {
        a.classList.toggle('active', a.dataset.section === id);
      });
    }
  });
}, observerOptions);

sections.forEach(id => {
  const el = document.getElementById(id);
  if (el) navObserver.observe(el);
});

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
    <div class="project-card-outer" style="animation-delay:${i*.06}s">
      <div class="project-card-inner">
        <div class="project-mitre">
          ${p.mitre.map(t => `<span class="mitre-tag">${t}</span>`).join('')}
        </div>
        <div class="project-title">${p.title}</div>
        <div class="project-desc">${p.description}</div>
        <div class="project-footer">
          ${p.live_url
            ? `<a href="${p.live_url}" target="_blank" rel="noopener noreferrer" class="project-live">
                View Write-up
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="7" y1="17" x2="17" y2="7"></line><polyline points="7 7 17 7 17 17"></polyline></svg>
               </a>`
            : `<span style="font-size:13px;color:var(--text-muted)">No Write-up</span>`}
          <span class="project-id-badge">${p.incident_id}</span>
        </div>
      </div>
    </div>
  `).join('');

  const wrap = document.getElementById('see-more-wrap');
  wrap.style.display = PROJECTS.length > 3 ? 'flex' : 'none';
  document.getElementById('see-more-label').textContent = showAll ? 'See Less' : 'See More';
  const seeMoreIcon = document.getElementById('see-more-icon');
  if (seeMoreIcon) {
    seeMoreIcon.classList.toggle('rotated', showAll);
  }
}
function toggleProjects() { showAll = !showAll; renderProjects(); }
renderProjects();

// ── STATS ─────────────────────────────────────────────────
const TOTAL_TRIAGE_SESSIONS = 22; // Corresponds to the shift triage queue in tickets/high-volume-shift-example.md
document.getElementById('stat-projects').textContent = PROJECTS.length;
document.getElementById('stat-certs').textContent = CERTIFICATES.length;
document.getElementById('stat-total').textContent = TOTAL_TRIAGE_SESSIONS;
document.getElementById('copyright-year').textContent = new Date().getFullYear();

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

  const status = document.getElementById('cf-status');
  const mailtoLink = document.getElementById('cf-mailto-link');
  const submitBtn = document.getElementById('cf-submit');
  const nameInput = document.getElementById('cf-name');
  const emailInput = document.getElementById('cf-email');
  const msgInput = document.getElementById('cf-message');

  // Set loading state
  status.className = 'form-status loading';
  status.innerHTML = '<span class="spinner"></span>Sending message...';
  status.style.display = 'block';
  mailtoLink.style.display = 'none';

  // Disable fields
  submitBtn.disabled = true;
  nameInput.disabled = true;
  emailInput.disabled = true;
  msgInput.disabled = true;

  fetch('https://formspree.io/f/xbdvrpdp', {
    method: 'POST',
    body: JSON.stringify({ name, email, message: msg }),
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  })
  .then(response => {
    if (response.ok) {
      status.className = 'form-status success';
      status.textContent = 'Thank you! Your message has been sent successfully.';
      
      // Clear values
      nameInput.value = '';
      emailInput.value = '';
      msgInput.value = '';

      // Re-enable fields
      submitBtn.disabled = false;
      nameInput.disabled = false;
      emailInput.disabled = false;
      msgInput.disabled = false;

      // Auto-hide success status after 5 seconds
      setTimeout(() => {
        status.style.transition = 'opacity 0.5s ease';
        status.style.opacity = '0';
        setTimeout(() => {
          status.style.display = 'none';
          status.style.opacity = '1';
        }, 500);
      }, 5000);
    } else {
      throw new Error('Server responded with an error status.');
    }
  })
  .catch(err => {
    status.className = 'form-status error';
    status.textContent = 'Sending failed. Copying message to clipboard...';
    
    // Copy to clipboard fallback
    const rawMessage = `Name: ${name}\nEmail: ${email}\n\nMessage:\n${msg}`;
    navigator.clipboard.writeText(rawMessage)
      .then(() => {
        status.textContent = 'Network error. Message copied to clipboard! Click below to send email directly.';
      })
      .catch(() => {
        status.textContent = 'Network error. Please click below to send email directly.';
      })
      .finally(() => {
        // Setup mailto fallback link
        const subject = encodeURIComponent(`Portfolio inquiry from ${name}`);
        const body = encodeURIComponent(rawMessage);
        mailtoLink.href = `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`;
        mailtoLink.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
          Open Email Client Fallback
        `;
        mailtoLink.style.display = 'inline-flex';
        
        // Re-enable fields so they can retry
        submitBtn.disabled = false;
        nameInput.disabled = false;
        emailInput.disabled = false;
        msgInput.disabled = false;
      });
  });
}
