# Vulnerability Remediation Plan

Generated: 2026-09-30 from `sample_findings.csv` (40 findings)

## Scoring model

`priority = severity_weight x asset_weight x age_factor x exploit_factor`

| Factor | Values |
|---|---|
| severity_weight | Critical=4, High=3, Medium=2, Low=1 |
| asset_weight | critical=1.5, high=1.25, medium=1.0, low=0.75 |
| age_factor | >180d=1.5, >90d=1.3, >30d=1.15, else 1.0 |
| exploit_factor | 1.5 if a public exploit exists, else 1.0 |

## SLA targets

| Severity | Remediate within |
|---|---|
| Critical | 15 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

## Ranked remediation queue

| Rank | Score | Severity | Host (IP) | Finding | CVE | Age | SLA due | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | 13.50 | Critical | web-prod-01 (10.0.1.10) | Citrix ADC path traversal RCE | CVE-2019-19781 | 181d | 2026-10-13 | due 2026-10-13 |
| 2 | 11.70 | Critical | web-prod-01 (10.0.1.10) | Apache Log4j remote code execution | CVE-2021-44228 | 110d | 2026-10-13 | due 2026-10-13 |
| 3 | 11.70 | Critical | web-prod-02 (10.0.1.11) | Spring Framework remote code execution | CVE-2022-22965 | 91d | 2026-10-13 | due 2026-10-13 |
| 4 | 11.70 | Critical | db-prod-01 (10.0.1.20) | Microsoft Exchange Server SSRF | CVE-2021-26855 | 133d | 2026-10-12 | due 2026-10-12 |
| 5 | 11.25 | Critical | file-srv-01 (10.0.1.30) | Windows Netlogon privilege escalation | CVE-2020-1472 | 204d | 2026-10-10 | due 2026-10-10 |
| 6 | 10.12 | High | web-prod-01 (10.0.1.10) | SMB remote code execution (EternalBlue) | CVE-2017-0144 | 228d | 2026-10-28 | due 2026-10-28 |
| 7 | 9.00 | Critical | web-prod-02 (10.0.1.11) | Cisco IOS XE privilege escalation | CVE-2023-20198 | 20d | 2026-10-13 | due 2026-10-13 |
| 8 | 8.62 | Critical | vpn-gw-01 (10.0.1.40) | PAN-OS command injection | CVE-2024-3400 | 46d | 2026-10-13 | due 2026-10-13 |
| 9 | 6.00 | Critical | wkst-042 (10.0.2.15) | Windows RDP remote code execution (BlueKeep) | CVE-2019-0708 | 29d | 2026-10-13 | due 2026-10-13 |
| 10 | 5.17 | High | web-prod-02 (10.0.1.11) | Apache HTTP Server outdated (2.4.49) | - | 60d | 2026-10-28 | due 2026-10-28 |
| 11 | 5.06 | High | iot-printer-01 (10.0.3.10) | Printer web interface default credentials | - | 263d | 2026-10-20 | due 2026-10-20 |
| 12 | 4.88 | High | vpn-gw-01 (10.0.1.40) | SSL VPN weak cipher suites offered | - | 121d | 2026-10-28 | due 2026-10-28 |
| 13 | 4.88 | High | file-srv-01 (10.0.1.30) | LLMNR poisoning possible (no SMB signing) | - | 148d | 2026-10-25 | due 2026-10-25 |
| 14 | 4.88 | High | vpn-gw-01 (10.0.1.40) | IKE aggressive mode with pre-shared key | - | 165d | 2026-10-28 | due 2026-10-28 |
| 15 | 4.50 | High | db-prod-01 (10.0.1.20) | libwebp heap buffer overflow | CVE-2023-4863 | 25d | 2026-10-27 | due 2026-10-27 |
| 16 | 4.50 | High | db-prod-01 (10.0.1.20) | Microsoft SQL Server weak SA password | - | 15d | 2026-10-27 | due 2026-10-27 |
| 17 | 4.50 | High | web-prod-01 (10.0.1.10) | TLS certificate expiring within 30 days | - | 10d | 2026-10-28 | due 2026-10-28 |
| 18 | 4.50 | Medium | web-prod-01 (10.0.1.10) | TLS 1.0 protocol supported | - | 213d | 2026-12-27 | due 2026-12-27 |
| 19 | 4.50 | Medium | web-prod-02 (10.0.1.11) | HTTP TRACE method enabled | - | 232d | 2026-12-27 | due 2026-12-27 |
| 20 | 4.31 | High | file-srv-01 (10.0.1.30) | Unpatched Windows Server 2019 cumulative update | - | 72d | 2026-10-26 | due 2026-10-26 |
| 21 | 3.75 | Medium | file-srv-01 (10.0.1.30) | SMBv1 protocol enabled | - | 248d | 2026-12-24 | due 2026-12-24 |
| 22 | 3.45 | High | wkst-043 (10.0.2.16) | Adobe Acrobat Reader outdated | - | 41d | 2026-10-28 | due 2026-10-28 |
| 23 | 3.45 | Medium | db-prod-01 (10.0.1.20) | Database backups stored unencrypted | - | 81d | 2026-12-26 | due 2026-12-26 |
| 24 | 3.45 | Medium | db-prod-01 (10.0.1.20) | SQL Server Browser service exposed | - | 70d | 2026-12-26 | due 2026-12-26 |
| 25 | 3.25 | Medium | file-srv-01 (10.0.1.30) | Guest account enabled | - | 179d | 2026-12-24 | due 2026-12-24 |
| 26 | 3.00 | High | wkst-042 (10.0.2.15) | Google Chrome outdated (multiple CVEs) | - | 18d | 2026-10-28 | due 2026-10-28 |
| 27 | 3.00 | Medium | web-prod-01 (10.0.1.10) | Cookie missing Secure flag | - | 29d | 2026-12-27 | due 2026-12-27 |
| 28 | 2.88 | Medium | vpn-gw-01 (10.0.1.40) | Verbose SSH banner discloses version | - | 53d | 2026-12-27 | due 2026-12-27 |
| 29 | 2.60 | Medium | wkst-042 (10.0.2.15) | USB mass storage not disabled by policy | - | 92d | 2026-12-27 | due 2026-12-27 |
| 30 | 2.60 | Medium | wkst-043 (10.0.2.16) | Local administrator password never rotated | - | 138d | 2026-12-27 | due 2026-12-27 |
| 31 | 2.25 | Medium | iot-printer-01 (10.0.3.10) | Telnet service enabled | - | 263d | 2026-12-19 | due 2026-12-19 |
| 32 | 2.25 | Low | web-prod-01 (10.0.1.10) | ICMP timestamp response | - | 241d | 2027-03-27 | due 2027-03-27 |
| 33 | 2.25 | Low | web-prod-02 (10.0.1.11) | OpenSSH version disclosure | - | 199d | 2027-03-27 | due 2027-03-27 |
| 34 | 2.00 | Medium | wkst-043 (10.0.2.16) | Windows Defender definitions outdated | - | 12d | 2026-12-27 | due 2026-12-27 |
| 35 | 1.95 | Low | db-prod-01 (10.0.1.20) | TCP idle timeout too high | - | 116d | 2027-03-26 | due 2027-03-26 |
| 36 | 1.62 | Low | file-srv-01 (10.0.1.30) | NetBIOS name disclosure | - | 134d | 2027-03-24 | due 2027-03-24 |
| 37 | 1.25 | Low | vpn-gw-01 (10.0.1.40) | NTP mode 6 query allowed | - | 28d | 2027-03-27 | due 2027-03-27 |
| 38 | 1.15 | Low | wkst-042 (10.0.2.15) | LLMNR enabled on workstation | - | 36d | 2027-03-27 | due 2027-03-27 |
| 39 | 1.15 | Low | wkst-043 (10.0.2.16) | Unquoted service path (low-privilege service) | - | 85d | 2027-03-27 | due 2027-03-27 |
| 40 | 1.12 | Low | iot-printer-01 (10.0.3.10) | SNMP public community string | - | 263d | 2027-03-19 | due 2027-03-19 |
