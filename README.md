# ARP-Spoofing

## SOC Investigation: Adversary in the Middle (ARP Cache Poisoning)

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1557.002-red.svg)](https://attack.mitre.org/techniques/T1557/002/)
[![SOC Level](https://img.shields.io/badge/SOC%20Role-L1%20%2F%20L2%20Analyst-blue.svg)](#)
[![Artifacts](https://img.shields.io/badge/Telemetry-PCAP%20%7C%20Splunk%20%7C%20Host-green.svg)](#)

This repository serves as an end-to-end incident handling demonstration of an **ARP Cache Poisoning (AiTM) attack** within a virtual lab. It establishes a threat emulation, packet forensics, custom SIEM detection, hypothesis-driven hunting, blast radius scoping, and remediation.
 
---

## Executive Incident Summary (Ticket: INC-2026-0918-NET01)

* **Incident Title:** Unauthorized Layer 2 Gateway Impersonation & Traffic Interception
* **Severity:** **High (P2)**
* **Impacted Asset:** `WS-014` (`192.168.56.10` / `00:0c:29:7b:4d:54`)
* **Attributed Attacker:** Rogue VM `kali` (`192.168.56.11` / `00:0c:29:fd:17:a1`)
* **Target Gateway:** `pfSense-GW` (`192.168.56.1` / True MAC: `00:0c:29:c8:9a:03`)
* **Blast Radius:** Single Broadcast Domain (`192.168.56.0/24`) — Contained locally.
* **Findings:** 2,912 spoofed ARP frames detected. Active IP Forwarding observed via ICMP Redirects. **No cleartext credentials or sensitive payloads were exposed (traffic remained encrypted via TLS/HTTPS).**

---

## Lab Baseline & Known Assets

| Device Role | Hostname | IP Address | Ground Truth MAC | Interface | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Default Gateway** | `pfSense-GW` | `192.168.56.1` | `00:0c:29:c8:9a:03` | `em1` | Verified Baseline |
| **Corporate Victim** | `WS-014` (Win 10) | `192.168.56.10` | `00:0c:29:7b:4d:54` | `Ethernet0` | Targeted Asset |
| **Adversary Anchor** | `kali` (Rogue) | `192.168.56.11` | `00:0c:29:fd:17:a1` | `eth0` | Isolated Threat |

---

## Investigation Artifacts & Evidence Chain

### 1. Endpoint Forensics (Host Cache Poisoning)
Execution of `arp -a` on the victim host revealed duplicate Layer 2 physical associations, proving unauthorized cache overwrite:
```text
Interface: 192.168.56.10 --- 0x4
  Internet Address      Physical Address     Type
  192.168.56.1          00-0c-29-fd-17-a1    dynamic  <-- Spoofed (Attacker MAC)
  192.168.56.11         00-0c-29-fd-17-a1    dynamic  <-- Attacker True Identity
