# INCIDENT HANDLING & INVESTIGATION REPORT
## Reference: NIST SP 800-61 Rev. 2 / Ticket #INC-2026-0918-NET01

---

### 1. Incident Overview & Administrative Metadata

| Record Field | Operational Value |
| :--- | :--- |
| **Incident Tracking ID** | `INC-2026-0918-NET01` |
| **Incident Title** | Unauthorized Layer 2 Gateway Impersonation & Active AiTM Positioning |
| **Category** | Unauthorized Network Access / Interception (Layer 2) |
| **Severity Rating** | **High (P2)** |
| **Incident Lead** | SOC L2 Incident Analyst |
| **Detection Timestamp** | 2026-09-18 00:36:00 UTC |
| **Containment Timestamp** | 2026-09-18 00:37:10 UTC |
| **Current Incident Status** | **Contained, Remediated & Closed** |
| **Compliance Standard** | NIST SP 800-61 Rev. 2 |

---

### 2. Executive Summary
On September 18, 2026, at 00:36:00 UTC, the Security Operations Center (SOC) detected an anomalous flood of unsolicited ARP replies on the corporate workstation network segment (`192.168.56.0/24`). Real-time cross-correlation between network packet telemetry and SIEM detection rules confirmed an active **ARP-Spoofing / Adversary-in-the-Middle (AiTM)** attack (MITRE ATT&CK T1557.002).

An unauthorized endpoint identifying with MAC address `00:0c:29:fd:17:a1` concurrently impersonated the corporate default gateway (`192.168.56.1`) and target workstation `WS-014` (`192.168.56.10`). The adversary enabled IP packet forwarding and issued ICMP Redirect frames to actively route and inspect endpoint network communications. Forensic deep-packet analysis of the captured streams established that the passing traffic comprised DNS resolution requests and TLS-encrypted web sessions. **No cleartext credentials, authentication tokens, or sensitive payload data were compromised during the attack window.** Rapid containment successfully neutralized the rogue host, flushed poisoned cache tables, and restored verified network baseline operations.

---

### 3. Attack Progression & Technical Evidence Breakdown

**Phase 1: Attack Attempt Confirmed**
*   **Technical Finding:** High-frequency injection of unsolicited ARP Reply frames (Opcode 2) lacking preceding broadcast ARP Request queries.
*   **Artifact:** Splunk query confirmed MAC `00:0c:29:fd:17:a1` generated 2,912 spoofed ARP reply frames in a 6-second window.

**Phase 2: Detection & Triage Confirmed**
*   **Technical Finding:** Triggered multiple independent alerting pipelines.
*   **Artifact:** Wireshark logged `[Duplicate IP address detected for 192.168.56.1 (00:0c:29:fd:17:a1) - also in use by 00:0c:29:c8:9a:03]`. SIEM triggered `CRITICAL: Unauthorized Gateway ARP Claim`.

**Phase 3: Cache Poisoning Confirmed**
*   **Technical Finding:** Targeted Windows endpoint accepted unsolicited unicast replies and updated its dynamic kernel ARP resolution table.
*   **Artifact:** Local execution of `arp -a` on `WS-014` revealed identical physical MAC mappings for `.1` and `.11`.

**Phase 4: MITM Traffic Interception Confirmed**
*   **Technical Finding:** Adversary assumed an inline position by enabling kernel IP forwarding, avoiding DoS, and routing traffic bidirectionally.
*   **Artifact:** Ingestion of 198 ICMP Redirect frames (123 to WS-014, 75 to gateway) instructing endpoints to route through `192.168.56.11`.

**Phase 5: Confidentiality & Data Exposure (NOT OBSERVED)**
*   **Technical Finding:** Telemetry analysis of intercepted sessions revealed no evidence of payload exfiltration.
*   **Artifact:** Inspected packets consisted strictly of DNS queries and outbound HTTPS (TLS) streams. No plaintext HTTP POST/GET requests were present.

---

### 4. Incident Scoping Matrix (Blast Radius)

| Scope Dimension | Assessed Value | Technical Justification |
| :--- | :--- | :--- |
| **Compromised Endpoints** | 1 Host (`WS-014`) | Threat hunting query confirmed all spoofed gateway replies targeted MAC `00:0c:29:7b:4d:54`. |
| **Adversary Anchor** | 1 Host (`kali`) | Source MAC `00:0c:29:fd:17:a1` / IP `192.168.56.11`. |
| **Network Scope** | Single Subnet (`192.168.56.0/24`) | ARP frames are non-routable Layer 2 broadcasts; bounded by the local VLAN. |
| **Incident Duration** | 6 Seconds | Start: 00:36:00 UTC / End: 00:36:06 UTC. |
| **Lateral Spread** | None Observed | No ARP queries or spoofed frames observed crossing to server or management subnets. |

---

### 5. Containment, Eradication & Recovery (NIST Lifecycle)

1. **Immediate Containment (00:37:10 UTC):**
   * Issued an administrative shutdown on the switch access port mapped to MAC `00:0c:29:fd:17:a1`. Network isolation validated.
2. **Short-Term Containment & Cache Cleansing:**
   * Executed local cache invalidation on workstation `WS-014` (`arp -d *`).
   * Flushed ARP and state translation tables on the default gateway (`pfSense.home.arpa`).
3. **Eradication:**
   * Traced and sequestered unauthorized virtual host `kali`. Revoked and blacklisted associated DHCP lease.
4. **Recovery & Post-Incident Verification:**
   * Verified workstation ARP cache via `arp -a`; confirmed `192.168.56.1` correctly resolved to authentic gateway MAC `00:0c:29:c8:9a:03`.

---

### 6. Defensible Conclusion Statement
"Forensic investigation confirms that an active Layer 2 Man-in-the-Middle (AiTM) intrusion occurred against workstation `WS-014` via ARP Cache Poisoning, initiated by unauthorized device `00:0c:29:fd:17:a1`. The attack succeeded in redirecting local segment traffic through the adversary's machine. Based upon comprehensive packet and SIEM telemetry available throughout the incident timeline, all intercepted application traffic remained encrypted under TLS; no plaintext credentials, session tokens, or sensitive internal data were observed compromised. The incident has been completely contained, baseline operations are restored, and long-term switch hardening controls have been submitted for deployment."

---

### 7. Strategic Corrective Actions (Prevent Recurrence)
* **Deploy Dynamic ARP Inspection (DAI):** Enforce hardware-level ARP validation on all access switch ports.
* **Mandate DHCP Snooping:** Activate across all corporate access VLANs to establish an authoritative Layer 2 IP-to-MAC-to-Port binding database.
* **Static ARP for Critical Infrastructure:** Implement static ARP mappings on domain controllers for the default gateway.
* **Enforce 802.1X Port Security:** Require certificate-based authentication for all physical switch ports.
