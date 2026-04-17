# KQL-Hunting-Playbook
PLAYBOOK FOR THREAT HUNTING

## Defensive Security Query Library

### Author: [Mr. Sakho Aboubacar] | Reviewer: Josh Madakor

> A personal reference library of KQL queries for threat hunting, incident response, and SOC investigation. Built from real cyber range investigations. All queries are for defensive detection purposes.

* * *

## How to Use This Playbook

1. Find the attack technique you are investigating in the table below
2. Copy the query
3. Replace placeholder values (marked in `CAPS`) with investigation-specific values
4. Run in Microsoft Sentinel or Microsoft Defender Advanced Hunting

* * *

## Query Index

| #   | Query Title | MITRE ID | Table | Use When |
| --- | --- | --- | --- | --- |
| 01  | Brute Force RDP Detection | T1110.001 | DeviceLogonEvents | Repeated failed logons then success |
| 02  | MFA Fatigue Detection | T1621 | SigninLogs | Multiple MFA push failures then approval |
| 03  | Impossible Travel Detection | T1078 | SigninLogs | Sign-in from unexpected country |
| 04  | Session Fingerprint Comparison | T1078 | SigninLogs | Compare device/OS/browser across sessions |
| 05  | Conditional Access Gap Detection | T1078 | SigninLogs | CA policy not enforced on sign-in |
| 06  | External Inbox Forwarding Rule | T1564.008 | CloudAppEvents | Email forwarded to external address |
| 07  | Security Keyword Deletion Rule | T1564.008 | CloudAppEvents | Inbox rule deleting security alerts |
| 08  | Full Inbox Rule Parameter Extraction | T1564.008 | CloudAppEvents | Full rule configuration analysis |
| 09  | BEC Fraudulent Email Detection | T1534 | EmailEvents | Suspicious email from compromised account |
| 10  | Session Cross-Table Correlation | T1078 | SigninLogs + CloudAppEvents | Link sign-in to mailbox actions |
| 11  | Error Code Discovery | T1110 | SigninLogs | Discover all auth failure codes |
| 12  | Data Compression for Exfiltration | T1560 | DeviceProcessEvents | Archive commands on sensitive dirs |
| 13  | rclone Cloud Exfiltration | T1567.002 | DeviceProcessEvents | rclone upload to cloud storage |
| 14  | VSS Shadow Copy Abuse | T1003.003 | DeviceProcessEvents | ntds.dit extraction via shadow copy |
| 15  | Impacket Service Detection | T1543.003 | DeviceEvents | Random 8-char service name creation |
| 16  | Process Injection Detection | T1055.003 | DeviceEvents | CreateRemoteThread across processes |
| 17  | LSASS Memory Dump Detection | T1003.001 | DeviceFileEvents | .dmp file created by suspicious process |
| 18  | UAC Bypass via Registry | T1548.002 | DeviceRegistryEvents | fodhelper registry hijack |
| 19  | Lateral Movement via Admin Shares | T1021.002 | DeviceProcessEvents | copy via C$ admin share |
| 20  | Discovery Command Detection | T1087 | DeviceProcessEvents | net user, net group, nltest |
| 21  | Scheduled Task Persistence | T1053.005 | DeviceProcessEvents | schtasks /create commands |
| 22  | AnyDesk Silent Install | T1219 | DeviceProcessEvents | Remote access tool silent deployment |
| 23  | Event Log Clearing | T1070.001 | DeviceProcessEvents | wevtutil cl Security/System |
| 24  | Firewall Rule Addition | T1562.004 | DeviceProcessEvents | netsh firewall add rule |
| 25  | DNS C2 Detection | T1071.004 | DeviceNetworkEvents | Suspicious DNS queries from malware |

* * *

## The Queries

* * *

### 01 — Brute Force RDP Detection

**MITRE:** T1110.001 — Brute Force: Password Guessing**Table:** DeviceLogonEvents**Use when:** Investigating repeated failed logons followed by a successful one from the same IP

    // STEP 1 — Read the timeline
    DeviceLogonEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ActionType in ("LogonFailed", "LogonSuccess")
    | where RemoteIP != ""
    | where not(RemoteIP startswith "10.")
    | where not(RemoteIP startswith "192.168.")
    | where not(RemoteIP startswith "172.")
    | project TimeGenerated, DeviceName, RemoteIP,
              ActionType, LogonType
    | sort by TimeGenerated asc
    
    // STEP 2 — Confirm the brute force pattern
    DeviceLogonEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ActionType in ("LogonFailed", "LogonSuccess")
    | where RemoteIP != ""
    | where not(RemoteIP startswith "10.")
    | where not(RemoteIP startswith "192.168.")
    | summarize FailCount=countif(ActionType == "LogonFailed"),
                SuccessCount=countif(ActionType == "LogonSuccess")
                by RemoteIP
    | where SuccessCount > 0 and FailCount > 0
    | sort by FailCount desc

        // PIVOT: From attacker IP to compromised account
    DeviceLogonEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where RemoteIP == "ATTACKER_IP"
    | where ActionType == "LogonSuccess"
    | distinct AccountName

* * *

### 02 — MFA Fatigue Detection

**MITRE:** T1621 — Multi-Factor Authentication Request Generation**Table:** SigninLogs**Use when:** User reports unexpected MFA push notifications — count failures before first success

    // Count failed MFA attempts before first success per IP
    let FirstSuccess = toscalar(
        SigninLogs
        | where UserPrincipalName == "USER@DOMAIN.COM"
        | where ResultType == 0
        | summarize min(TimeGenerated)
    );
    SigninLogs
    | where UserPrincipalName == "USER@DOMAIN.COM"
    | where ResultType != 0
    | where TimeGenerated < FirstSuccess
    | summarize FailedAttempts=count() by IPAddress
    | sort by FailedAttempts desc

* * *

### 03 — Impossible Travel Detection

**MITRE:** T1078 — Valid Accounts**Table:** SigninLogs**Use when:** Checking if a user signed in from an unexpected country

    SigninLogs
    | where ResultType == 0
    | extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
    | extend City = tostring(parse_json(LocationDetails).city)
    | where Country !in ("GB", "US")  // Add expected countries for your org
    | project TimeGenerated, UserPrincipalName, IPAddress,
              Country, City, AppDisplayName
    | sort by TimeGenerated asc

* * *

### 04 — Session Fingerprint Comparison

**MITRE:** T1078 — Valid Accounts**Table:** SigninLogs**Use when:** Comparing legitimate vs attacker sessions — spot OS/browser/country anomalies

    SigninLogs
    | where UserPrincipalName == "USER@DOMAIN.COM"
    | where ResultType == 0
    | extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
    | extend Browser = tostring(parse_json(DeviceDetail).browser)
    | extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
    | extend City = tostring(parse_json(LocationDetails).city)
    | summarize Sessions=count(),
                FirstSeen=min(TimeGenerated),
                LastSeen=max(TimeGenerated)
      by IPAddress, Country, City, OS, Browser
    | sort by FirstSeen asc

* * *

### 05 — Conditional Access Gap Detection

**MITRE:** T1078 — Valid Accounts**Table:** SigninLogs**Use when:** Identifying sign-ins where no CA policy was enforced — defence gap finding

    SigninLogs
    | where ResultType == 0
    | where ConditionalAccessStatus == "notApplied"
    | extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
    | extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
    | project TimeGenerated, UserPrincipalName, IPAddress,
              Country, OS, ConditionalAccessStatus, AppDisplayName
    | sort by TimeGenerated asc

* * *

### 06 — External Inbox Forwarding Rule Detection

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules**Table:** CloudAppEvents**Use when:** Detecting inbox rules that forward emails to external addresses

    CloudAppEvents
    | where ActionType == "New-InboxRule"
    | mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
    | where tostring(Parameters.Name) == "ForwardTo"
    | where tostring(Parameters.Value) !endswith "YOURDOMAIN.COM"
    | project TimeGenerated, AccountDisplayName, IPAddress,
              ForwardTo = tostring(Parameters.Value)
    | sort by TimeGenerated asc

* * *

### 07 — Security Keyword Deletion Rule Detection

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules**Table:** CloudAppEvents**Use when:** Detecting inbox rules that delete security-related emails

    CloudAppEvents
    | where ActionType == "New-InboxRule"
    | mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
    | where tostring(Parameters.Name) == "SubjectOrBodyContainsWords"
    | where tostring(Parameters.Value) has_any (
        "security", "phishing", "compromised",
        "suspicious", "verify", "unusual")
    | project TimeGenerated, AccountDisplayName, IPAddress,
              Keywords = tostring(Parameters.Value)
    | sort by TimeGenerated asc

* * *

### 08 — Full Inbox Rule Parameter Extraction

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules**Table:** CloudAppEvents**Use when:** Full analysis of all inbox rule parameters — name, action, keywords, forwarding

    CloudAppEvents
    | where ActionType == "New-InboxRule"
    | mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
    | where tostring(Parameters.Name) in (
        "Name", "ForwardTo", "DeleteMessage",
        "SubjectOrBodyContainsWords", "StopProcessingRules")
    | summarize RuleConfig=make_bag(pack(
        tostring(Parameters.Name),
        tostring(Parameters.Value)))
      by TimeGenerated, AccountDisplayName, IPAddress
    | sort by TimeGenerated asc

* * *

### 09 — BEC Fraudulent Email Detection

**MITRE:** T1534 — Internal Spearphishing**Table:** EmailEvents**Use when:** Finding emails sent from a compromised account — thread hijacking and fraud

    EmailEvents
    | where SenderFromAddress == "COMPROMISED@DOMAIN.COM"
    | project TimeGenerated, SenderFromAddress,
              RecipientEmailAddress, Subject,
              EmailDirection, UrlCount, AttachmentCount
    | sort by TimeGenerated asc

* * *

### 10 — Session Cross-Table Correlation

**MITRE:** T1078 — Valid Accounts**Table:** CloudAppEvents + SigninLogs**Use when:** Linking sign-in session to all subsequent mailbox actions by same attacker

    // Extract session ID from CloudAppEvents
    CloudAppEvents
    | where ActionType == "New-InboxRule"
    | where IPAddress == "ATTACKER_IP"
    | extend SessionId = tostring(parse_json(tostring(RawEventData))
                         .AppAccessContext.AADSessionId)
    | project TimeGenerated, AccountDisplayName,
              IPAddress, ActionType, SessionId
    | sort by TimeGenerated asc

* * *

### 11 — Authentication Error Code Discovery

**MITRE:** T1110 — Brute Force**Table:** SigninLogs**Use when:** Discovering all authentication failure codes without knowing them in advance

    SigninLogs
    | where ResultType != 0
    | summarize Count=count(),
                Description=any(ResultDescription),
                AffectedUsers=make_set(UserPrincipalName),
                SeenFromIPs=make_set(IPAddress)
      by ResultType
    | sort by Count desc

* * *

### 12 — Data Compression for Exfiltration

**MITRE:** T1560 — Archive Collected Data**Table:** DeviceProcessEvents**Use when:** Finding compression commands targeting sensitive directories

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has_any (
        "Compress-Archive", "7z", "zip", "rar", "tar")
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 13 — rclone Cloud Exfiltration Detection

**MITRE:** T1567.002 — Exfiltration to Cloud Storage**Table:** DeviceProcessEvents**Use when:** Detecting rclone usage for data exfiltration to cloud storage

    // Find all rclone executions
    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where FileName == "rclone.exe"
        or ProcessCommandLine has "rclone"
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 14 — VSS Shadow Copy Abuse (NTDS Extraction)

**MITRE:** T1003.003 — OS Credential Dumping: NTDS**Table:** DeviceProcessEvents**Use when:** Detecting ntds.dit extraction via Volume Shadow Copy

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has_any (
        "vssadmin", "ntds.dit", "HarddiskVolumeShadowCopy",
        "shadow", "ntdsutil")
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 15 — Impacket Service Detection

**MITRE:** T1543.003 — Create or Modify System Process: Windows Service**Table:** DeviceEvents**Use when:** Detecting Impacket remote execution — random 8-character service names

    DeviceEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ActionType == "ServiceInstalled"
    | extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
    | where strlen(ServiceName) == 8
    | where ServiceName matches regex @"^[A-Za-z]{8}$"
    | project Timestamp, DeviceName, ServiceName, AdditionalFields
    | sort by Timestamp asc

* * *

### 16 — Process Injection Detection

**MITRE:** T1055.003 — Process Injection: Thread Execution Hijacking**Table:** DeviceEvents**Use when:** Detecting CreateRemoteThread injection between processes

    DeviceEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ActionType == "CreateRemoteThreadApiCall"
    | extend SourceProcess = tostring(parse_json(AdditionalFields).SourceProcessName)
    | extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
    | project Timestamp, DeviceName, SourceProcess,
              TargetProcess, AdditionalFields
    | sort by Timestamp asc

* * *

### 17 — LSASS Memory Dump Detection

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory**Table:** DeviceFileEvents**Use when:** Detecting .dmp files created by suspicious processes — credential theft

    DeviceFileEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where FileName endswith ".dmp"
    | where FolderPath has_any ("Temp", "Public", "AppData")
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              FileName, FolderPath, InitiatingProcessCommandLine
    | sort by Timestamp asc

* * *

### 18 — UAC Bypass via Registry (fodhelper)

**MITRE:** T1548.002 — Abuse Elevation Control: Bypass UAC**Table:** DeviceRegistryEvents**Use when:** Detecting fodhelper UAC bypass via registry hijack

    DeviceRegistryEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where RegistryKey has "ms-settings"
    | where RegistryValueName in ("", "DelegateExecute")
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              RegistryKey, RegistryValueName, RegistryValueData
    | sort by Timestamp asc

* * *

### 19 — Lateral Movement via Admin Shares

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares**Table:** DeviceProcessEvents**Use when:** Detecting file copy via C$ admin shares for lateral movement

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has "C$"
    | where ProcessCommandLine has_any ("copy", "xcopy", "move")
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 20 — Discovery Command Detection

**MITRE:** T1087 — Account Discovery**Table:** DeviceProcessEvents**Use when:** Detecting attacker reconnaissance commands

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has_any (
        "net user", "net group", "nltest",
        "whoami", "ipconfig", "systeminfo",
        "net localgroup", "quser")
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 21 — Scheduled Task Persistence Detection

**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task**Table:** DeviceProcessEvents**Use when:** Detecting scheduled task creation for persistence

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has "schtasks"
    | where ProcessCommandLine has "/create"
    | extend TaskName = extract(@"/tn\s+""?([^""
    ]+)""?", 1,
                                 ProcessCommandLine)
    | project Timestamp, DeviceName, AccountName,
              TaskName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 22 — AnyDesk Silent Install Detection

**MITRE:** T1219 — Remote Access Software**Table:** DeviceProcessEvents**Use when:** Detecting silent installation of remote access tools

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has_any (
        "anydesk", "teamviewer", "screenconnect",
        "splashtop", "logmein", "vnc")
    | where ProcessCommandLine has "--silent"
        or ProcessCommandLine has "--install"
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 23 — Event Log Clearing Detection

**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs**Table:** DeviceProcessEvents**Use when:** Detecting attacker clearing Windows event logs to destroy evidence

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has "wevtutil"
    | where ProcessCommandLine has "cl"
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 24 — Firewall Rule Addition Detection

**MITRE:** T1562.004 — Impair Defenses: Disable or Modify System Firewall**Table:** DeviceProcessEvents**Use when:** Detecting attacker adding firewall rules for lateral movement

    DeviceProcessEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where ProcessCommandLine has "netsh"
    | where ProcessCommandLine has_any ("firewall", "advfirewall")
    | where ProcessCommandLine has "add"
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName
    | sort by Timestamp asc

* * *

### 25 — DNS C2 Detection

**MITRE:** T1071.004 — Application Layer Protocol: DNS**Table:** DeviceNetworkEvents**Use when:** Finding C2 domain queries from suspicious processes

    DeviceNetworkEvents
    | where DeviceName contains "TARGET_DEVICE"
    | where InitiatingProcessFileName !in (
        "svchost.exe", "chrome.exe", "msedge.exe",
        "firefox.exe", "SearchApp.exe")
    | where RemotePort == 53
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              RemoteIP, RemoteUrl, InitiatingProcessCommandLine
    | sort by Timestamp asc

* * *
### 25 — Suspicious Binary Detection
// SUSPICIOUS BINARY IN WORLD-WRITABLE LOCATION
// MITRE: T1204.002 — User Execution: Malicious File
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where AccountName == "TARGET_ACCOUNT"
| where FolderPath has_any (
    "\\Users\\Public",
    "\\Temp",
    "\\Downloads",
    "\\AppData\\Roaming",
    "\\AppData\\Local\\Temp")
| project Timestamp, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc

* * *
## Key Azure AD Error Codes Reference

| Code | Meaning | Investigation Use |
| --- | --- | --- |
| 0   | Success | Attacker authenticated |
| 50074 | MFA required — not completed | Push sent — MFA fatigue in progress |
| 50140 | Keep me signed in interrupt | Auth in progress |
| 50126 | Invalid username or password | Credential stuffing |
| 50089 | Flow token expired | Session replay attempt |
| 50055 | Password expired | Targeted account |
| 53003 | Blocked by Conditional Access | Defence working |
| 16003 | Account not in directory | Wrong tenant |

* * *

## Table Selection Quick Reference

| Question Type | Table | Key Fields |
| --- | --- | --- |
| Who signed in? From where? | SigninLogs | UserPrincipalName, IPAddress, LocationDetails |
| What happened inside M365? | CloudAppEvents | AccountDisplayName, ActionType, RawEventData |
| What emails were sent? | EmailEvents | SenderFromAddress, RecipientEmailAddress, Subject |
| What processes ran on endpoint? | DeviceProcessEvents | FileName, ProcessCommandLine, AccountName |
| What files were created? | DeviceFileEvents | FileName, FolderPath, InitiatingProcessFileName |
| What network connections? | DeviceNetworkEvents | RemoteIP, RemotePort, InitiatingProcessFileName |
| What registry changes? | DeviceRegistryEvents | RegistryKey, RegistryValueName, RegistryValueData |
| Who logged on to endpoint? | DeviceLogonEvents | RemoteIP, ActionType, LogonType |

* * *

## JSON Field Extraction Cheat Sheet

Always use this formula for nested JSON fields:

    | extend NewColumn = tostring(parse_json(FieldName).keyName)

Common extractions:

    // SigninLogs
    | extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
    | extend City = tostring(parse_json(LocationDetails).city)
    | extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
    | extend Browser = tostring(parse_json(DeviceDetail).browser)
    
    // CloudAppEvents
    | extend SessionId = tostring(parse_json(tostring(RawEventData)).AppAccessContext.AADSessionId)
    | extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)

* * *

## The countif Pattern — Brute Force Signature

    | summarize
        FailCount=countif(ActionType == "LogonFailed"),
        SuccessCount=countif(ActionType == "LogonSuccess")
      by RemoteIP
    | where SuccessCount > 0 and FailCount > 0
    | sort by FailCount desc

Use whenever a question mentions repeated failures followed by success.

* * *

*KQL Hunting Playbook — Built from live cyber range investigations**Author: [Your Name] | Reviewer: Josh Madakor**For defensive security and portfolio use*
