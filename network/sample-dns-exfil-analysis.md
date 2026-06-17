# Sample Exercise: DNS Query Anomaly (Synthetic)

Supplementary network module — not tied to a closed incident. Use after Caldera **T1-Phish-to-Host** if HTTP beacon abilities generate periodic DNS.

## Scenario

Splunk notable: `index=dns` reports workstation `WKSTN-042` sent 200 queries in 5 minutes to `*.update-check.azureedge-live.com` with 52-character subdomains.

## Tier 1 Investigation Steps

### 1. Validate Alert

```spl
index=dns src_host=WKSTN-042
| stats count by query
| eval qlen=len(query)
| where qlen > 45
| sort - count
```

### 2. Wireshark Filter (if PCAP available)

```
dns.qry.name contains "azureedge-live"
```

### 3. Enrichment

| IOC | Type | Result |
|-----|------|--------|
| `update-check.azureedge-live.com` | Domain | Registered 3 days ago — suspicious |
| Subdomain pattern | Encoding | Base32-like labels |

Run:

```bash
python scripts/ioc_enrichment.py -i network/sample_dns_iocs.txt -o dns_enrich.json
```

### 4. MITRE Mapping

**T1071.004 — Application Layer Protocol: DNS**

### 5. Tier 1 Actions

1. Isolate host (if not already from parent incident)
2. Block domain at DNS firewall
3. Escalate to T2 for payload decode
4. Link to Caldera operation if lab

## Key Takeaway

DNS tunneling often appears as **volume + length** anomalies before threat intel catches the domain. Tier 1 job is pattern recognition and fast containment, not full decode.