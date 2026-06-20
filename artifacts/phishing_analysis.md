# Phishing Email Header Analysis & Triage Report

## Email Information
| Header | Value |
|---|---|
| **Subject** | URGENT: Invoice #88421 — password inside email body |
| **From** | `Accounts Payable <payable@vendor-secure.com>` |
| **To** | `jsmith@corp.lab` |
| **Date** | Wed, 17 Jun 2026 13:54:58 +0000 |
| **Message-ID** | `<not-random@DESKTOP-EVIL>` |
| **Return-Path**| `<bounce+xyz@mail.vendor-secure.com>` |
| **Reply-To** | `attacker-drop@protonmail.com` |
| **Ingress IP** | `203.0.113.88` |

## Authentication Triad
| Protocol | Result | Assessment |
|---|---|---|
| **SPF** | `FAIL` | FAIL |
| **DKIM** | `NONE` | UNKNOWN/NONE |
| **DMARC** | `FAIL` | FAIL |

## Security Anomalies
- **Domain Mismatch**: From header domain (`vendor-secure.com`) does not match Return-Path (`mail.vendor-secure.com`).
- **Reply-To Mismatch**: Reply-To header is set to `attacker-drop@protonmail.com`, pointing to a different address than From.

## Extracted URLs (Defanged)
- `hxxps://vendor-secure[.]com[.]login-update[.]tk/invoice?id=88421`

## Attachments
#### Attachment: Invoice_June2026.zip
- **Content-Type**: `application/zip`
- **Size**: 200 bytes
- **MD5**: `83b560239d640ab96b3070e67fe44c04`
- **SHA256**: `b94dce38a9efa578ff4dd41052daef9b1f589d08745e40dc946e19bc144a7789`


## Mail Routing Hops (Oldest to Newest)
| Hop | From | By | Hops IPs | External ingress? |
|---|---|---|---|---|
| 1 | mail-sender-unknown | mx.corp.lab | 203.0.113.88 | YES |
| 2 | mx.corp.lab | internal-relay.corp.lab.local | 10.10.20.50 | YES |

