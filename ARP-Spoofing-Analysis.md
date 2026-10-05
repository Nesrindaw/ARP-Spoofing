#  ARP SPOOFING ANALYSIS

###  Attack Card

| Record Field | Operational Value |
| :--- | :--- |
| **Attack Name** | ARP Spoofing |
| **Alternative Names** | ARP Poisoning, ARP Cache Poisoning |
| **Category** | Network & Protocol Attacks |
| **MITRE ATT&CK Technique** | T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning) |
| **Tactic** | Credential Access (TA0006), Collection (TA0009) |
| **Severity** | **High** (P2) |
| **Attack Prerequisites** | Local Layer 2 Network Adjacency (Same Broadcast Domain / VLAN) |
| **Target Platforms** | Any IPv4-enabled OS (Windows, Linux, macOS, Network Appliances) |
| **Required Access** | Unprivileged Local Network Access |
| **Typical Attacker Objective** | Traffic Interception, Man-in-the-Middle (MITM), Session Hijacking, DoS |
| **SOC Relevance** | For Network Packet Forensics, Telemetry Triaging, and SIEM Rule Logic |
| **Difficulty** | Low (Automated open-source tooling readily available) |
| **Estimated Reading Time** | 25 Minutes |

---

### What Is It?

The **Address Resolution Protocol (ARP)** is a critical Layer 2 (Data Link Layer) mechanism responsible for mapping logical IPv4 addresses to physical MAC addresses, enabling devices to communicate across a local area network (LAN).

#### The Underlying Weakness:
ARP was originally designed with zero built-in security considerations. It suffers from two fundamental flaws:
1. **Stateless Nature:** Devices will accept and process ARP replies-updating their local ARP cache-even if they never sent a corresponding ARP request (Unsolicited ARP Reply).
2. **Lack of Authentication:** There is no mechanism to verify the sender's identity or encrypt the exchange. A target device will blindly trust the IP-to-MAC mapping provided in the packet.

#### Attacker Objectives:
* Establish an inline position between a corporate workstation and the default gateway, acting as an **Adversary-in-the-Middle (AiTM)**.
* Intercept, inspect, and potentially modify unencrypted network traffic ( HTTP, DNS).
* Trigger a localized Denial of Service (DoS) by dropping intercepted packets instead of forwarding them.

#### Endpoint/User Experience:
In a well-executed attack, the end-user will not experience a network disconnect. As long as the attacker enables **IP Forwarding** on their machine, traffic continues to flow normally, though the user might experience slight latency due to packet retransmissions and ICMP Redirects.

---

### How It Works

#### 1. Normal Operational Behavior:
* **ARP Request (Broadcast):** The workstation asks the entire network: *"Who has `192.168.56.1`? Tell `192.168.56.10`."*
* **ARP Reply (Unicast):** Only the legitimate gateway responds: *"I have `192.168.56.1`, and my MAC is `00:0c:29:c8:9a:03`."*
* The workstation saves this mapping dynamically in its ARP cache.

#### 2. Malicious Behavior:
* The attacker floods both the victim and the gateway with unsolicited, forged ARP replies:
  * To the victim: *"I am the gateway (`192.168.56.1`), my MAC is `00:0c:29:fd:17:a1`."*
  * To the gateway: *"I am the workstation (`192.168.56.10`), my MAC is `00:0c:29:fd:17:a1`."*
* This bidirectional poisoning forces all outbound and inbound Layer 2 traffic to route directly through the attacker's network interface.


![ARP Spoofing Data Flow](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Malicious%20Behavior.png)


### Attack Lifecycle (MITRE ATT&CK Mapping)

* **Initial Access:** Securing physical access to an Ethernet port or joining a corporate Wi-Fi network.
* **Collection (TA0009) & Credential Access (TA0006):** Executing T1557.002 to route traffic and capture sensitive packets.
* **Defense Evasion (TA0005):** Utilizing ICMP Redirects to optimize routing and avoid service interruptions that might alert the user.
* **Impact (TA0040):** Manipulating unencrypted web responses or causing selective network denial of service.

### Hands-on Lab & Baseline Validation

All emulation steps were executed within an isolated host-only subnet (`192.168.56.0/24`).

**Verified Enterprise Baseline:**

| Device Role | Hostname | IP Address | Authentic MAC Address | Interface |
| --- | --- | --- | --- | --- |
| Default Gateway | pfSense.home.arpa | 192.168.56.1 | 00:0c:29:c8:9a:03 | em1 |
| Corporate Victim | Windows 10 | 192.168.56.10 | 00:0c:29:7b:4d:54 | Ethernet0 |
| Adversary Host | kali | 192.168.56.11 | 00:0c:29:fd:17:a1 | eth0 |

**Baseline Configuration (Pre-Attack):**

![pfSense Gateway Baseline](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/MAC%20Address%20pfSense%20Corporate%20Gateway.png)
![Windows 10 Victim Baseline](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Corporate%20Victim%20Windows%2010%20MAC%20Address.png)
![Kali Attacker Baseline](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Suspected%20Attacker%20kali%20.png)
![Windows Normal ARP Table](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Windows%20arp%20a.png)

**Attacker Execution Commands (Kali Linux):**

```bash
# Enable kernel IP forwarding to maintain the connection (Core MITM Requirement)
sudo sysctl -w net.ipv4.ip_forward=1

# Execute bidirectional poisoning targeting the victim and the gateway
sudo arpspoof -i eth0 -t 192.168.56.10 192.168.56.1
sudo arpspoof -i eth0 -t 192.168.56.1 192.168.56.10

```

### Attack Evidence Map

| Telemetry Source | Evidence Classification | Observed Artifacts in Lab |
| --- | --- | --- |
| Endpoint (`arp -a`) | Direct Evidence | Both `192.168.56.1` and `192.168.56.11` map to the identical MAC `00-0c-29-fd-17-a1`. |
| Wireshark (PCAP) | Direct Evidence | `arp.duplicate-address-detected` warnings and abnormal ICMP Redirect frames. |
| Splunk SIEM | Direct Evidence | `00:0c:29:fd:17:a1` logged claiming ownership of two distinct IPs via 2,912 frames. |
| Switch Telemetry | Supporting Evidence | Syslog errors triggered by Dynamic ARP Inspection (if enabled). |
| Windows Event Logs | Limited / Blind Spot | Windows rarely logs dynamic ARP updates; Event ID 4199 only fires on explicit hard IP conflicts. |

**Endpoint Cache Poisoning:**

![Poisoned ARP Table](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Arp%20Spoofing.png)

### Detection Engineering

**1. Wireshark Packet Filters:**

* Detect Duplicate IP Allocation: `arp.duplicate-address-detected`
* Isolate Malicious Unsolicited Replies: `arp.opcode == 2 && eth.src == 00:0c:29:fd:17:a1`

**Wireshark Network Forensics:**

![Duplicate IP Warning](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Duplicate%20IP%20address%20detected.png)

![ARP Duplicate Address Filter](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/arp.duplicate-address-detected.png)

![Unsolicited ARP Replies](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/arp.opcode%20==%202.png)

**2. Splunk Enterprise Investigation Query (SPL):**

 [Splunk Investigation Rules](https://github.com/Nesrindaw/ARP-Spoofing/blob/main/Splunk%20Investigation%20Rules.spl)

**Proof of Execution - Initial Triage:**


![Initial Triage](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Initial%20Triage%20Query.png)


**Proof of Execution - Bidirectional Poisoning Detection:**


![Bidirectional Poisoning](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Bidirectional%20Poisoning.png)


![Enterprise Investigation SPL](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Enterprise%20Investigation%20SPL.png)


**Proof of Execution - Gateway Impersonation Alert:**


![Gateway Enterprise Detection Alert](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots//Gateway%20Enterprise%20Detection%20Alert.png)
 

 Successfully isolated MAC `00:0c:29:fd:17:a1` generating 2,912 frames claiming both the gateway and the workstation.

**3. Production Sigma Rule:**

 [Sigma Rule](https://github.com/Nesrindaw/ARP-Spoofing/blob/main/Sigma%20Rule)

### Investigation & Timeline Analysis

* **T0 (00:36:00 UTC):** High-frequency ARP spoofing injected from MAC `00:0c:29:fd:17:a1`.
* **T1 (00:36:01 UTC):** Workstation ARP cache updates, binding the gateway to the rogue MAC.
* **T2 (00:36:02 UTC):** Ingestion of ICMP Redirect frames; active TCP/DNS traffic routes through the adversary.
* **T3 (00:36:06 UTC):** Injection ceases after 2,912 frames are logged.
* **Defensible Conclusion:** Verified AiTM attack. However, because intercepted sessions strictly utilized TLS/HTTPS, no plaintext credential leakage occurred.

### Hypothesis-Driven Threat Hunting

**Hunting Hypothesis:** An adversary maintaining a persistent inline position will emit control frames (ICMP Redirects) to manage traffic flows and prevent connection drops.

**Hunting Query (SPL):**

**Threat Hunting (Gateway Impersonation & ICMP Redirects):**

![Splunk Hunting Query](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Splunk%20Hunting%20Query%20.png)

![Splunk Hunting ICMP Redirect](https://raw.githubusercontent.com/Nesrindaw/ARP-Spoofing/main/screenshots/Splunk%20Hunting%20ICMP%20Redirect.png)

*Hunting Finding:* Host `192.168.56.11` dispatched 123 Redirect frames to the workstation and 75 to the gateway, proving functional router impersonation.

### Scoping the Incident

| Scope Dimension | Observed Extent | Telemetry Justification |
| --- | --- | --- |
| Affected Hosts | 1 Host: WS-014 (`192.168.56.10`) | Splunk queries confirmed spoofed replies solely targeted this endpoint. |
| Rogue Device | 1 Host: kali (`00:0c:29:fd:17:a1`) | The singular source MAC for all spoofed traffic. |
| Network Segment | Localized: `192.168.56.0/24` | ARP is a non-routable Layer 2 protocol; it cannot cross subnet boundaries. |
| Blast Radius | Local & Contained | No lateral movement or adjacent subnet poisoning detected. |

### Response & Containment Protocol

1. **Immediate Containment:** Administratively shut down the switch access port tied to the attacker (`shutdown`), physically severing the connection.
2. **Short-Term Containment:** Flush the poisoned ARP cache on the victim workstation (`arp -d *`) and the gateway.
3. **Eradication:** Sequester the rogue physical/virtual device for forensic imaging and revoke its DHCP lease.
4. **Recovery Verification:** Run `arp -a` on the endpoint to verify the gateway IP (`192.168.56.1`) properly resolves to the authentic MAC (`00-0c-29-c8-9a-03`).

### Architectural Hardening & Prevention

* **DHCP Snooping & Dynamic ARP Inspection (DAI):** Deploy these coupled features on access switches to build a trusted binding database and aggressively drop spoofed ARP frames in hardware.
* **Static ARP Configurations:** Hardcode gateway ARP entries on critical infrastructure (like Domain Controllers) to reject dynamic updates.
* **802.1X Port Security:** Enforce network access control (NAC) requiring certificate-based authentication before granting port access.

### Common SOC Analyst Mistakes

* **Assuming Interception Equals Data Breach:** Failing to inspect the transport layer encryption. Just because an attacker intercepts traffic doesn't mean they can decrypt modern TLS/HTTPS payloads.
* **Flushing Caches Before Isolating Ports:** Running `arp -d *` on the workstation before shutting down the attacker's switch port. The attacker's script will simply re-poison the cache milliseconds later.

### Analyst Decision Tree

```text
    Alert: Unsolicited ARP / Duplicate IP 
                   │
       Is it a scheduled change or VRRP Failover?
              YES ──>  Close as Benign / Update Baseline 
              NO
                   │
       Does the packet claim the Gateway IP from an unauthorized MAC?
             NO  ──>  Investigate as Host-to-Host Conflict 
             YES ──>  CONFIRMED ARP SPOOFING / MITM
                         1. Shutdown Attacker Switch Port
                         2. Flush ARP Caches (arp -d *)
                         3. Analyze PCAP for Plaintext Data Exposure
                         4. Implement DAI & DHCP Snooping

```

### Realistic SOC Scenario Review

An alert fired for anomalous ARP activity in the Finance VLAN. Triage confirmed gateway impersonation via `arp.duplicate-address-detected`. Recognizing the severity, the SOC bypassed standard wait times, immediately isolating the switch port to protect localized financial traffic, and validated that no plaintext leakage occurred.

### Final Attack Cheat Sheet

| Concept | Reference Value |
| --- | --- |
| Attack Name | ARP Spoofing / ARP Cache Poisoning |
| MITRE ATT&CK | T1557.002 (Adversary-in-the-Middle) |
| Primary Objective | Layer 2 Traffic Redirection & Interception (MITM) |
| Key Evidence | Duplicate IP detection, High-frequency Unsolicited ARP Replies |
| First Response Action | Isolate Attacker Switch Port ➔ Flush Endpoint ARP Caches |
| Core Prevention | DHCP Snooping + Dynamic ARP Inspection (DAI) |

