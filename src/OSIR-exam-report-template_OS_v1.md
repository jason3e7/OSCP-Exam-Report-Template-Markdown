---
title: "Offensive Security Incident Responder Exam Report"
author: ["student@youremailaddress.com", "OSID: XXXXX"]
date: "2024-12-01"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSTH Exam Report"
lang: "en"
titlepage: true
titlepage-color: "483D8B"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security Incident Responder Exam Report

## Introduction

The OffSec Incident Responder exam report contains all efforts that were conducted in order to pass the OffSec certification examination.
This report should contain all items that were used to pass the exam and it will be graded from a standpoint of correctness and fullness to all aspects of the exam. 
The purpose of this report is to ensure that the student has a full understanding of incident response methodologies as well as the technical knowledge to pass the qualifications for the OffSec Incident Responder.

## Objective

The objective of this assessment is to respond to an incident in the Megacorp One environment.
The objective in the first phase is to identify all compromised systems and detect if sensitive data was exfiltrated or encrypted.
Phase 2 involves performing a forensic analysis on a disk image provided by a colleague from another branch of the Megacorp One's Incident Response team.
Based on their initial analysis, the disk image contains a post-exploitation framework binary that contains an encryption key.
You must find the binary and obtain the encryption key.
Example pages have already been created for you at the latter portions of this document that should demonstrate the amount of information and detail that is expected in the exam report.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this incident response report fully and to include the following sections:

- Executive Summary (All sections)
- Incident Detection and Identification 
    - In this section, provide a detailed, story-style walkthrough of Phase 1. Focus on how you identified the answer to each exercise question, and ensure you include the exact Splunk query used in your investigation.
- Incident Detection and Identification - Containment, Eradication, and Recovery
    - In this section, outline the key steps that can be taken to contain and recover compromised systems, as well as eliminate the threat identified in Phase 1. Focus on actions that mitigate the immediate risk, restore system integrity, and remove any remaining traces of the compromise.
- Incident Detection and Identification - Findings
    - In this section, which contains a timetable of your findings, make sure to document the **overall attacker activity or phase** related to each exercise question.
- Forensic Analysis - Disk Image Analysis
    - In this section, provide a detailed, story-style walkthrough of the disk image analysis in Phase 2), focusing on how you identified the malicious binary.
- Forensic Analysis - Malware Analysis
    - In this section, provide a detailed, story-style walkthrough of the malware analysis process in Phase 2), focusing on how you analyzed and identified the encryption key used by the binary.
- Conclusion

The walkthroughs in the **Incident Detection and Identification**, **Disk Image Analysis**, and **Malware Analysis** sections should be clear and thorough, containing enough explanations and screenshots to allow a technically proficient reader to replicate each step. Additionally, ensure that your workflow and decision-making process throughout the analysis are well explained and easily understood.

# Executive Summary

## Incident Detection and Identification Overview

The SOC team escalated several triggered alerts to the Incident Response team for investigation. 
The primary objectives were to identify if the triggered alerts contained compromised systems and assess the impact of the attacker’s actions, such as determining whether data has been exfiltrated or encrypted.

While investigating the alerts and the recorded data of the incident, we identified three compromised systems in the Megacorp One environment:

- PC1
- PC2
- SRV1

The threat actor accessed and exfiltrated the secret recipe for our chocolate muffins, which could have catastrophic consequences if leaked or sold to competitors.

## High-Level Attack Path

Our investigation revealed the following high-level path the threat actor took to compromise the Megacorp One environment and accessed the sensitive recipe:

1. PC1 was used as the initial entry vector by the threat actor by trying numerous passwords against several user accounts. The threat actor finally succeeded and got access to this machine with administrative privileges. 
2. PC2 was configured to use the same password for the local administrator account and the threat actor used it to get access to it. On the machine, the attacker obtained credentials from logged on users by using Mimikatz.
3. SRV1 was accessed using one of the obtained sets of credentials from PC2. The threat actor accessed and exfiltrated the secret chocolate muffin recipe from this machine. 

## Forensic Analysis Overview

A disk image was created from a compromised machine in another branch of the Megacorp One enterprise. 
Analysis of this disk image confirmed that it had been compromised by a threat actor, who had downloaded a password-protected archive containing a malicious binary.

Upon analyzing the binary, we found that it checks whether the system is in a specific state before executing actions to generate a token. 
By leveraging this token, we were able to obtain an authentication token for the threat actor’s Command & Control (C&C) infrastructure, which provided valuable insights into their operations and helped strengthen our security.

# Incident Detection and Identification

For the scheduled threat hunting sprint, we utilized the following tools, scripts, commands, and resources:

- Splunk
- WAG Threat Intelligence Report
- PowerShell on DEV (Deobfuscation)

We performed an intelligence-based threat hunting sprint based on the information provided in the WAG threat intelligence report. This approach led us to detect the usage of Mimikatz on PC2, which revealed several additional indicators for further investigation. By analyzing these indicators, we were able to identify lateral movement to PC3 by correlating login and Sysmon events in Splunk with the known tools and techniques categorized under the "Lateral Movement" column. Through this analysis, we also discovered that after compromising PC3, the attacker exfiltrated a sensitive document.

After exhausting our list of IoCs and other information from the intelligence-based phase, we transitioned to hypothesis-based threat hunting. This shift provided us with the flexibility to investigate how PC2 was accessed and how the perimeter was breached, considering that this is not a publicly accessible machine.

Our hunting hypothesis was:

We suspect that PC3 and PC2 are not the only systems compromised by the WAG threat actor. While we couldn’t identify any further indicators that revealed additional compromised systems using the credentials obtained from PC2, or following the compromise of PC3, it is likely that PC2 was not the initial system compromised by WAG, given that it is not externally accessible. Therefore, we suspect that at least one other machine is compromised. We will validate this by investigating the events preceding the use of Mimikatz to obtain credentials and by identifying the vector the threat actor used to access PC2 and breach the perimeter.

# Hunt Narrative

The threat intelligence report covering TTPs of the threat actor We Are Garfield provided a list of IoCs including SHA-256 hashes. We used the following query in Splunk to hunt for these hashes:

```default
index="*" ("EEAAFA68236BD1629E36E81C5A8EC2CE8804C9798B5C84FEE55F6128CCBA8FB0" OR
"4ED877F6F154EB6EBB02EE44E4D836C28193D9254A4A3D6AF6236D8F5BAB88D2" OR
"11EBBAA2EDA3CCD4B7F1BB2C09AC7DCA0CD1F4B71B7E0CFCEDE36861E23DA034" OR
"8507FFC7EA1953F66D8441180C281D456889F93CF3F6CBB01F368886F9D8C097"
```

This search query resulted in only a single event with the timestamp 01/11/2024 1:11:11 AM:

![ImgPlaceholder](img/placeholder-image-300x225.png)

The matching SHA-256 hash is referred to as “Mimikatz” in the threat intelligence report. We then reviewed the event in more detail.

![ImgPlaceholder](img/placeholder-image-300x225.png)

The event provides us several important information that can be leveraged in our hunt:

- Username: Administrator
- Filename: Zwetsch.exe
- Directory: `C:\hackingtools\`

Based on the matching SHA-256 hash of the threat intelligence report and the characteristic commandline argument “sekurlsa::logonpasswords”, we can be certain that this is Mimikatz.

[…]

## Containment, Eradication, and Recovery


## Findings

Timestamp             | Observation | Affected Assets
----------------------|-------------|-----------------
01/09/2024 3:25:00 PM | Beginning of Password Spraying with Password Password1! | Host: PC1
01/09/2024 3:58:00 PM | End of Password Spraying. | Host: PC1
01/09/2024 3:58:15 PM | Successful login for local Administrator user | Host: PC1 User: Administrator (local)
01/09/2024 3:59:00 PM | Download of meterpreter.exe from `<IP>` via Browser | Host: PC1 User: Administrator
01/09/2024 3:59:49 PM | Process Creation of meterpreter.exe | Host: PC1 User: Administrator (local)
01/09/2024 4:05:11 PM | Process Creation of PsExec | Host: PC1 User: Administrator (local) Target Machine: PC2 Target User: Administrator (local) Password: Password1!"
[…] | […] | […]
01/11/2024 1:11:11 AM | Process Creation of Zwetsch.exe | Host: PC2 User: Administrator (local)
[…] | […]| […]


# Forensic Analysis

## Disk Image Analysis

## Malware Analysis

# Conclusion

Our incident detection and identification process successfully uncovered three compromised systems within Megacorp One’s infrastructure, alongside the exfiltration of our confidential chocolate muffin recipe.

During forensic analysis, it was revealed that the threat actor downloaded a password-protected archive on one of the compromised systems, extracting a malicious binary.
This binary leveraged temporary tokens to secure an authentication token linked to the threat actor's Command & Control (C&C) infrastructure.
By obtaining this authentication token, we gained valuable insights into the threat actor’s operations, enhancing our ability to defend against future attacks.

Through swift containment, recovery of the compromised systems, and eradication of the malicious artifacts, we successfully mitigated the threat and prevented further compromise of Megacorp One’s environment.
