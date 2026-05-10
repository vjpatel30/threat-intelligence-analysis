# Threat Intelligence Analysis: STIX Investigation and SOC Application

## Overview

This project demonstrates how structured threat intelligence (STIX/TAXII) is consumed, analyzed, and operationalized in a SOC context. Using the OASIS CTI STIX Visualization tool, this investigation mapped relationships between indicators of compromise, malware families, and threat actor TTPs — then translated those findings into actionable detection guidance and KQL-style hunting queries relevant to a Microsoft Sentinel environment.

---

## Objective

- Parse and analyze STIX 2.1 formatted threat intelligence data
- Map relationships between IOCs, malware, and threat actors
- Extract actionable intelligence to support alert triage and threat hunting
- Produce detection guidance and hunting queries based on real indicator data
- Demonstrate how threat intel feeds accelerate SOC analyst decision-making

---

## Tools Used

- OASIS CTI STIX Visualization Tool (oasis-open.github.io/cti-stix-visualization)
- STIX 2.1 threat intelligence format
- MITRE ATT&CK Framework
- KQL (Kusto Query Language) — detection query development
- Mandiant Attack Lifecycle Model

---

## Environment

This lab used STIX 2.1 formatted threat intelligence data loaded into the OASIS CTI STIX Visualization tool to simulate the consumption and analysis of a threat intelligence feed — replicating the workflow a SOC analyst would use when integrating external TI into a SIEM or threat hunting workflow.

---

## Investigation Walkthrough

### Step 1 — Load and Visualize STIX Data
Imported STIX 2.1 bundle into the OASIS visualization tool. The graph revealed the following objects and relationships:

**Objects identified:**
- **Threat Actor:** Adversary Bravo (spy, criminal)
- **Malware:** Poison Ivy Variant d1c6 (remote-access-trojan)
- **Attack Pattern:** Phishing
- **Identity:** Adversary Bravo(2)
- **Indicator:** Malicious site hosting downloader
- **Malware:** x4z9arb backdoor

**Relationships mapped:**
- Adversary Bravo **uses** → Poison Ivy Variant d1c6
- Adversary Bravo **uses** → Phishing
- Adversary Bravo **attributed-to** → Adversary Bravo(2)
- Malicious site hosting downloader **indicates** → x4z9arb backdoor

### Step 2 — Threat Actor Analysis
Selected the Adversary Bravo node and reviewed full object details.

**Threat Actor details:**
- **Name:** Adversary Bravo
- **ID:** threat-actor--9a8a0d25-7636-429b-a99e-b2a73cd0f11f
- **Type:** threat-actor
- **Threat actor types:** spy, criminal
- **Created/Modified:** 2015-05-07T14:22:14.760Z
- **Description:** "Adversary Bravo is known to use phishing attacks to deliver remote access malware to the targets."
- **Outgoing relationships:** uses attack-pattern (Phishing), attributed-to identity

**SOC application:** Adversary Bravo's confirmed use of phishing for RAT delivery means any phishing alerts in the environment should be treated as elevated priority — successful delivery could result in a full remote access trojan implant on the target endpoint.

### Step 3 — Malware Analysis
Selected the Poison Ivy Variant d1c6 node and reviewed full object details.

**Malware details:**
- **Name:** Poison Ivy Variant d1c6
- **ID:** malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4
- **Malware type:** remote-access-trojan
- **is_family:** false (specific variant, not a malware family)
- **Created/Modified:** 2015-04-23T11:12:34.760Z
- **Kill chain:** mandiant-attack-lifecycle-model — phase: initial-compromise

**SOC application:** Poison Ivy is a well-documented RAT with capabilities including keylogging, screen capture, file exfiltration, and reverse shell access. Classification at the initial-compromise phase of the Mandiant lifecycle means this malware is used for initial foothold establishment — detection should focus on delivery mechanisms (phishing emails, malicious URLs) and post-execution C2 behavior.

### Step 4 — Indicator Analysis
Selected the Malicious site hosting downloader indicator node.

**Indicator details:**
- **Name:** Malicious site hosting downloader
- **ID:** indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f
- **Indicator type:** malicious-activity
- **Pattern:** `[url:value = 'http://x4z9arb.cn/4712/']`
- **Pattern type:** stix
- **Valid from:** 2014-06-29T13:49:37.079Z
- **Description:** "This organized threat actor group operates to create profit from all types of crime."
- **Relationship:** indicates → x4z9arb backdoor (malware)

**SOC application:** The URL `http://x4z9arb.cn/4712/` is a confirmed malicious indicator linked to a downloader that delivers the x4z9arb backdoor. Any connection to this URL from an endpoint in the environment should be treated as a critical alert and escalated immediately.

### Step 5 — Detection Development
Translated STIX indicator and TTP data into KQL detection queries for Microsoft Sentinel.

**KQL query — hunt for connections to known malicious URL:**
```kql
DeviceNetworkEvents
| where RemoteUrl has "x4z9arb.cn"
   or RemoteUrl has "x4z9arb.cn/4712/"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

**KQL query — detect phishing-delivered executable (Poison Ivy TTP):**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe")
| where FileName endswith ".exe" or FileName endswith ".dll"
| where ProcessCommandLine has_any ("http://", "https://", "cmd.exe", "powershell")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**KQL alert rule — detect RAT-style outbound C2 behavior:**
```kql
DeviceNetworkEvents
| where RemotePort in (443, 80, 8080, 4444)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe")
| summarize ConnectionCount = count(), DestinationIPs = make_set(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnectionCount > 20
| order by ConnectionCount desc
```

### Step 6 — Threat Intelligence Report
Produced a structured threat intelligence report documenting the full campaign: Adversary Bravo uses phishing to deliver Poison Ivy Variant d1c6 (remote-access-trojan) at the initial-compromise phase, with infrastructure including the malicious downloader URL `http://x4z9arb.cn/4712/` linking to the x4z9arb backdoor.

---

## MITRE ATT&CK Mapping

| Technique | ID | Source |
|---|---|---|
| Phishing | T1566 | Adversary Bravo confirmed attack pattern (STIX object) |
| Remote Access Tools | T1219 | Poison Ivy Variant d1c6 — remote-access-trojan |
| Command and Control | T1071 | x4z9arb backdoor C2 via malicious URL |
| Drive-by Compromise | T1189 | Malicious site hosting downloader indicator |

---

## Key Findings Summary

| Finding | Detail |
|---|---|
| Threat Actor | Adversary Bravo |
| Actor Types | Spy, Criminal |
| Actor Description | Uses phishing to deliver remote access malware |
| Malware | Poison Ivy Variant d1c6 |
| Malware Type | Remote-Access-Trojan |
| Kill Chain Phase | Initial Compromise (Mandiant model) |
| Malicious URL | http://x4z9arb.cn/4712/ |
| URL Indicates | x4z9arb backdoor |
| Valid From | 2014-06-29 |
| Detection Queries Produced | 3 (KQL — Sentinel-compatible) |
| SOC Recommendation | Block x4z9arb.cn, prioritize phishing alerts, hunt for RAT C2 behavior |

---

## Screenshots

### STIX Relationship Graph
![STIX Relationship Graph](stix-relationship-graph.png)

### Malware Details — Poison Ivy Variant d1c6
![Malware Details](stix-malware-details.png)

### Threat Actor Details — Adversary Bravo
![Threat Actor Details](stix-threat-actor-details.png)

### Indicator URL Details
![Indicator URL Details](stix-indicator-url.png)

---

## Skills Demonstrated

- Threat intelligence consumption and analysis (STIX 2.1)
- IOC extraction and indicator pattern analysis
- Threat actor profiling and TTP mapping
- Malware classification and kill chain mapping
- MITRE ATT&CK framework application
- KQL detection query development (Microsoft Sentinel)
- Threat hunting query construction
- Structured threat intelligence reporting
- SOC analyst decision-support documentation
