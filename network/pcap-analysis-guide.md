# PCAP Analysis Guide (Tier 1)

Walkthrough for **RDP / lateral movement** network forensics — [INC-2026-006](../incidents/INC-2026-006-rdp-lateral-movement.md) (Caldera `2026-06-18-LATERAL-RDP-LAB`, tcpdump capture on WKSTN-099).

> **Core incident INC-2026-006** is the primary network forensics case, where RDP lateral movement is correlated with suspicious registry changes and a tcpdump process execution. Use this guide to understand how PCAP traffic was analyzed.

## When Tier 1 Reviews PCAPs

- IDS alert references flow but EDR is inconclusive
- Suspicious DNS volume from workstation
- User reports "slow network" during unknown process activity
- IR requests quick triage before full malware reverse engineering

## Wireshark Quick Start

### 1. Capture Metadata

| Field | RDP Lateral Case (INC-2026-006) |
|-------|-------------------------------|
| File | `capture.pcapng` |
| Size | 12 MB |
| Duration | 120 seconds |
| Host | WKSTN-099 |

### 2. Statistics → Protocol Hierarchy

Identify dominant protocols. Expected on corporate workstation:

- DNS, TLS, SMB, occasional HTTP

**Red flag:** ICMP tunneling ratios, SMTP from non-mail client, long DNS labels.

### 3. Display Filters (Tier 1 Toolkit)

```
# DNS queries
dns.qry.name

# Long DNS names (possible tunneling)
dns.qry.name.len > 40

# HTTP cleartext (legacy apps)
http.request

# TLS Client Hello — SNI inspection
tls.handshake.extensions_server_name

# RDP
tcp.port == 3389

# Specific host conversation
ip.addr == 10.10.20.10 && tcp
```

### 4. Follow TCP Stream

Right-click packet → **Follow → TCP Stream**

Use for:

- Cleartext HTTP headers
- FTP commands
- SMTP auth (should not see passwords in modern env)

### 5. DNS Analysis

| Check | Action |
|-------|--------|
| Query frequency | Statistics → DNS |
| NXDOMAIN rate | High = DGA or misconfig |
| Subdomain length | `dns.qry.name` filter > 50 chars |
| Resolver | Should be internal DC DNS |

**RDP Lateral case result (INC-006):** Normal AD DNS — no exfil.

### 6. HTTP/HTTPS

- **HTTP:** Export objects (File → Export Objects → HTTP) if cleartext found
- **HTTPS:** Tier 1 inspects **SNI** and **JA3** (if available via Zeek), not decrypted payload without MITM proxy logs

### 7. Firewall / IDS Correlation

Map PCAP timestamp to pfSense:

```
Jun 15 16:08:30 openvpn[...]: 10.10.10.99 -> 10.10.20.10:3389 SYN
```

### 8. Documentation in Ticket

Record:

1. Filter used
2. Packet numbers of interest (e.g., `#4521 DNS query evil.com`)
3. Bytes transferred estimate
4. Verdict: benign / suspicious / escalate

## TCP/IP Refresher (Tier 1)

| Concept | SOC relevance |
|---------|---------------|
| SYN / SYN-ACK | Connection establishment — scan detection |
| RST | Blocked port or firewall reject |
| TTL | Traceroute anomalies, spoofing hints |
| Private RFC1918 | 10.x, 172.16–31, 192.168.x — internal |
| Ephemeral ports | >49152 client-side |

## VPN False Positive (INC-2026-004)

PCAP not always available. Tier 1 relied on **firewall auth logs** + **change ticket** instead of full capture — valid workflow when evidence is sufficient without PCAP.

## Lab Extension

Re-run Caldera **T1040** ability, capture with tcpdump:

```cmd
tcpdump -i 1 -w C:\Users\Public\capture.pcapng
```

Practice filters above against known-good baseline.