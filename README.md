# 🛡️ KQL Threat Hunting Playbook
## Defensive Security Query Library

**Author:** Sakho Aboubacar &nbsp;|&nbsp; **Reviewer:** Josh Madakor

> A personal reference library of KQL queries for threat hunting, incident response, and SOC investigation.
> Built from real cyber range investigations. All queries are for **defensive detection purposes only**.

---

## 📖 How to Use This Playbook

1. Find the attack technique you are investigating in the index below
2. Copy the query
3. Replace placeholder values (marked in `ALL_CAPS`) with your investigation-specific values
4. Run in **Microsoft Sentinel** or **Microsoft Defender Advanced Hunting**

---

## 📋 Query Index

| # | Query Title | MITRE ID | Table | Use When |
|---|---|---|---|---|
| 00 | Complete Attacker Session Profiler | T1078 | DeviceLogonEvents + DeviceProcessEvents + DeviceFileEvents | Full attacker footprint from scratch |
| 01 | Brute Force RDP Detection | T1110.001 | DeviceLogonEvents | Repeated failed logons then success |
| 02 | MFA Fatigue Detection | T1621 | SigninLogs | Multiple MFA push failures then approval |
| 03 | Impossible Travel Detection | T1078 | SigninLogs | Sign-in from unexpected country |
| 04 | Session Fingerprint Comparison | T1078 | SigninLogs | Compare device/OS/browser across sessions |
| 05 | Conditional Access Gap Detection | T1078 | SigninLogs | CA policy not enforced on sign-in |
| 06 | External Inbox Forwarding Rule | T1564.008 | CloudAppEvents | Email forwarded to external address |
| 07 | Security Keyword Deletion Rule | T1564.008 | CloudAppEvents | Inbox rule deleting security alerts |
| 08 | Full Inbox Rule Parameter Extraction | T1564.008 | CloudAppEvents | Full rule configuration analysis |
| 09 | BEC Fraudulent Email Detection | T1534 | EmailEvents | Suspicious email from compromised account |
| 10 | Session Cross-Table Correlation | T1078 | SigninLogs + CloudAppEvents | Link sign-in to mailbox actions |
| 11 | Authentication Error Code Discovery | T1110 | SigninLogs | Discover all auth failure codes |
| 12 | Data Compression for Exfiltration | T1560 | DeviceProcessEvents | Archive commands on sensitive dirs |
| 13 | rclone Cloud Exfiltration | T1567.002 | DeviceProcessEvents | rclone upload to cloud storage |
| 14 | C2 Network Detection | T1071 | DeviceNetworkEvents | Outbound C2 from suspicious processes |
| 15 | VSS Shadow Copy Abuse | T1003.003 | DeviceProcessEvents | ntds.dit extraction via shadow copy |
| 16 | Impacket Service Detection | T1543.003 | DeviceEvents | Random 8-char service name creation |
| 17 | Process Injection Detection | T1055.003 | DeviceEvents | CreateRemoteThread across processes |
| 18 | LSASS Memory Dump Detection | T1003.001 | DeviceFileEvents | .dmp file created by suspicious process |
| 19 | UAC Bypass via Registry | T1548.002 | DeviceRegistryEvents | fodhelper registry hijack |
| 20 | Lateral Movement via Admin Shares | T1021.002 | DeviceProcessEvents | copy via C$ admin share |
| 21 | Discovery Command Detection | T1087 | DeviceProcessEvents | net user, net group, nltest, systeminfo |
| 22 | Scheduled Task Persistence | T1053.005 | DeviceProcessEvents + DeviceEvents | schtasks /create commands |
| 23 | AnyDesk / RAT Silent Install | T1219 | DeviceProcessEvents | Remote access tool silent deployment |
| 24 | Event Log Clearing | T1070.001 | DeviceProcessEvents | wevtutil cl Security/System |
| 25 | Firewall Rule Addition | T1562.004 | DeviceProcessEvents | netsh firewall add rule |
| 26 | DNS C2 Detection | T1071.004 | DeviceNetworkEvents | Suspicious DNS queries from malware |
| 27 | Suspicious Binary in Writable Location | T1204.002 | DeviceProcessEvents | Executables in Temp/Downloads/Public |
| 28 | Data Staging for Exfiltration | T1560 | DeviceFileEvents | Compressed archives created pre-exfil |
| 29 | PowerShell Command Audit | T1059.001 | DeviceEvents | PowerShell commands run on endpoint |
| 30 | Recently Accessed Files (LNK) | T1074 | DeviceFileEvents | Files opened manually via Explorer |
| 31 | RDP Connection Funnel | T1110.001 | DeviceNetworkEvents | Attempt vs Accepted vs Overlap on port |
| 32 | Geographic Enrichment (GeoIP) | T1078 | DeviceNetworkEvents + DeviceLogonEvents | Enrich IPs with country/continent data |
| 33 | File Rename to Executable | T1036.007 | DeviceFileEvents | Double extension or rename to .exe/.bat |
| 34 | Track File by SHA256 Hash | T1036 | DeviceFileEvents | Follow payload across all renames |
| 35 | Defender Exclusion Detection | T1562.001 | DeviceProcessEvents + DeviceEvents + DeviceRegistryEvents | AV exclusion or passive mode added |
| 36 | Windows Defender Mode Detection | T1562.001 | DeviceEvents | Detect Defender passive/disabled mode |
| 37 | Payload Execution and Parent Process | T1204 | DeviceProcessEvents | What launched the payload? |
| 38 | C2 Callback by Payload SHA256 | T1071 | DeviceNetworkEvents | Outbound C2 pivoted from file hash |

---

## 🔍 The Queries

---

### Query 00 — Complete Attacker Session Profiler

**MITRE:** T1078 — Valid Accounts
**Tables:** `DeviceLogonEvents` + `DeviceProcessEvents` + `DeviceFileEvents`
**Use when:** You only know the date range and need to discover the attacker's device name and build a full footprint from scratch. Start with Step 1 to identify who connected, then feed that into the master query.

**Red Flags to watch for:**
- Zero `FailedLogons` + high `ProcessCount` = likely credential theft or pre-tested credentials
- `FilesDeleted` spike = evidence destruction in progress
- Multiple `DeviceNames` = lateral movement confirmed

#### Step 1 — Discover the Attacker Device Name

> You only know the date range. Run this to see every external device that logged into your environment — ranked by activity. The attacker's machine will surface at the top.

```kql
// Who connected remotely to machines in this time window?
// No prior knowledge needed — discovers all remote sessions
DeviceLogonEvents
| where TimeGenerated between (
    datetime(2025-10-01) .. datetime(2025-10-15))
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| where RemoteDeviceName != ""
| where RemoteDeviceName != "-"
| where not(RemoteIP startswith "10.")
| where not(RemoteIP startswith "192.168.")
| where not(RemoteIP startswith "172.")
| summarize
    LogonCount = count(),
    IPsUsed = make_set(RemoteIP),
    MachinesAccessed = make_set(DeviceName),
    Accounts = make_set(AccountName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteDeviceName
| sort by LogonCount desc
```

#### Step 2 — Master Attacker Profiler Query

> Feed the device name discovered in Step 1 into `AttackerDevice` below.

```kql
// Complete attacker session profiler
// Combines logon data + process activity + file activity in one result

let AttackerDevice = "ATTACKER_DEVICE_NAME"; // e.g sarah-che
let StartTime = datetime(); // e.g 2025-12-09
let EndTime = datetime(); // e.g 2025-12-23

let Logons = (
    DeviceLogonEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where RemoteDeviceName contains AttackerDevice
    | summarize
        SuccessfulLogons = countif(ActionType == "LogonSuccess"),
        FailedLogons = countif(ActionType == "LogonFailed"),
        LogonTypes = make_set(LogonType),
        IPsUsed = make_set(RemoteIP),
        FirstLogon = min(TimeGenerated),
        LastLogon = max(TimeGenerated)
        by DeviceName
);

let Processes = (
    DeviceProcessEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where IsInitiatingProcessRemoteSession == true
    | where InitiatingProcessRemoteSessionDeviceName contains AttackerDevice
    | summarize
        ProcessCount = count(),
        UniqueCommands = dcount(ProcessCommandLine),
        TopCommands = make_set(ProcessCommandLine, 5)
        by DeviceName
);

let Files = (
    DeviceFileEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where IsInitiatingProcessRemoteSession == true
    | where InitiatingProcessRemoteSessionDeviceName contains AttackerDevice
    | summarize
        FilesCreated = countif(ActionType == "FileCreated"),
        FilesDeleted = countif(ActionType == "FileDeleted"),
        FileNames = make_set(FileName, 10)
        by DeviceName
);

Logons
| join kind=leftouter Processes on DeviceName
| join kind=leftouter Files on DeviceName
| project
    DeviceName,
    AttackerDevice,
    IPsUsed,
    SuccessfulLogons,
    FailedLogons,
    ProcessCount,
    UniqueCommands,
    FilesCreated,
    FilesDeleted,
    FirstLogon,
    LastLogon,
    DwellTime = LastLogon - FirstLogon,
    FileNames,
    TopCommands
```

---

### Query 01 — Brute Force RDP Detection

**MITRE:** T1110.001 — Brute Force: Password Guessing
**Table:** `DeviceLogonEvents`
**Use when:** Investigating repeated failed logons followed by a successful one from the same IP. Run Step 1 first to read the timeline, then Step 2 to confirm the brute force pattern, then pivot to find the compromised account.

#### Step 1 — Read the Timeline

```kql
DeviceLogonEvents
| where DeviceName contains "TARGET_DEVICE"
| where ActionType in ("LogonFailed", "LogonSuccess")
| where RemoteIP != ""
| where not(RemoteIP startswith "10.")
| where not(RemoteIP startswith "192.168.")
| where not(RemoteIP startswith "172.")
| project
    TimeGenerated,
    DeviceName,
    RemoteIP,
    ActionType,
    LogonType
| sort by TimeGenerated asc
```

#### Step 2 — Confirm the Brute Force Pattern

```kql
DeviceLogonEvents
| where DeviceName contains "TARGET_DEVICE"
| where ActionType in ("LogonFailed", "LogonSuccess")
| where RemoteIP != ""
| where not(RemoteIP startswith "10.")
| where not(RemoteIP startswith "192.168.")
| summarize
    FailCount = countif(ActionType == "LogonFailed"),
    SuccessCount = countif(ActionType == "LogonSuccess")
    by RemoteIP
| where SuccessCount > 0 and FailCount > 0
| sort by FailCount desc
```

#### Step 3 — Pivot to Compromised Account

```kql
DeviceLogonEvents
| where DeviceName contains "TARGET_DEVICE"
| where RemoteIP == "ATTACKER_IP"
| where ActionType == "LogonSuccess"
| distinct AccountName
```

---

### Query 02 — MFA Fatigue Detection

**MITRE:** T1621 — Multi-Factor Authentication Request Generation
**Table:** `SigninLogs`
**Use when:** A user reports unexpected MFA push notifications. Count the MFA failures before the first successful sign-in to confirm a fatigue attack.

```kql
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
| summarize FailedAttempts = count() by IPAddress
| sort by FailedAttempts desc
```

---

### Query 03 — Impossible Travel Detection

**MITRE:** T1078 — Valid Accounts
**Table:** `SigninLogs`
**Use when:** Checking if a user signed in from an unexpected country outside the organisation's expected operating regions.

```kql
SigninLogs
| where ResultType == 0
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| where Country !in ("US", "GB")  // Replace with your org's expected countries
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    City,
    AppDisplayName
| sort by TimeGenerated asc
```

---

### Query 04 — Session Fingerprint Comparison

**MITRE:** T1078 — Valid Accounts
**Table:** `SigninLogs`
**Use when:** Comparing legitimate vs attacker sessions. Spot OS, browser, and country anomalies that indicate an account takeover mid-session.

```kql
SigninLogs
| where UserPrincipalName == "USER@DOMAIN.COM"
| where ResultType == 0
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City = tostring(parse_json(LocationDetails).city)
| summarize
    Sessions = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, Country, City, OS, Browser
| sort by FirstSeen asc
```

---

### Query 05 — Conditional Access Gap Detection

**MITRE:** T1078 — Valid Accounts
**Table:** `SigninLogs`
**Use when:** Identifying sign-ins where no Conditional Access policy was enforced. This is a defence gap finding — it reveals which accounts and apps are unprotected.

```kql
SigninLogs
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied"
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    OS,
    ConditionalAccessStatus,
    AppDisplayName
| sort by TimeGenerated asc
```

---

### Query 06 — External Inbox Forwarding Rule Detection

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules
**Table:** `CloudAppEvents`
**Use when:** Detecting inbox rules that silently forward emails to an external address. A classic BEC persistence technique — the attacker keeps reading emails even after the password is reset.

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
| where tostring(Parameters.Name) == "ForwardTo"
| where tostring(Parameters.Value) !endswith "YOURDOMAIN.COM"
| project
    TimeGenerated,
    AccountDisplayName,
    IPAddress,
    ForwardTo = tostring(Parameters.Value)
| sort by TimeGenerated asc
```

---

### Query 07 — Security Keyword Deletion Rule Detection

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules
**Table:** `CloudAppEvents`
**Use when:** Detecting inbox rules that automatically delete emails containing security-related keywords. Attackers use this to hide alerts about their own activity from the victim.

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
| where tostring(Parameters.Name) == "SubjectOrBodyContainsWords"
| where tostring(Parameters.Value) has_any (
    "security", "phishing", "compromised",
    "suspicious", "verify", "unusual")
| project
    TimeGenerated,
    AccountDisplayName,
    IPAddress,
    Keywords = tostring(Parameters.Value)
| sort by TimeGenerated asc
```

---

### Query 08 — Full Inbox Rule Parameter Extraction

**MITRE:** T1564.008 — Hide Artifacts: Email Hiding Rules
**Table:** `CloudAppEvents`
**Use when:** Full analysis of all inbox rule parameters in one result — name, action, keywords, forwarding address. Use this when you need the complete picture of what a rule does.

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| mv-expand Parameters = parse_json(tostring(RawEventData)).Parameters
| where tostring(Parameters.Name) in (
    "Name", "ForwardTo", "DeleteMessage",
    "SubjectOrBodyContainsWords", "StopProcessingRules")
| summarize
    RuleConfig = make_bag(pack(
        tostring(Parameters.Name),
        tostring(Parameters.Value)))
    by TimeGenerated, AccountDisplayName, IPAddress
| sort by TimeGenerated asc
```

---

### Query 09 — BEC Fraudulent Email Detection

**MITRE:** T1534 — Internal Spearphishing
**Table:** `EmailEvents`
**Use when:** Finding emails sent from a compromised account. Used to identify thread hijacking, fraud emails, and lateral phishing from a trusted internal address.

```kql
EmailEvents
| where SenderFromAddress == "COMPROMISED@DOMAIN.COM"
| project
    TimeGenerated,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    EmailDirection,
    UrlCount,
    AttachmentCount
| sort by TimeGenerated asc
```

---

### Query 10 — Session Cross-Table Correlation

**MITRE:** T1078 — Valid Accounts
**Tables:** `CloudAppEvents` + `SigninLogs`
**Use when:** Linking a sign-in session ID to all subsequent mailbox actions performed by the same attacker. Proves that the same session that authenticated also created the inbox rules.

```kql
// Extract session ID from the attacker's inbox rule action
CloudAppEvents
| where ActionType == "New-InboxRule"
| where IPAddress == "ATTACKER_IP"
| extend SessionId = tostring(
    parse_json(tostring(RawEventData)).AppAccessContext.AADSessionId)
| project
    TimeGenerated,
    AccountDisplayName,
    IPAddress,
    ActionType,
    SessionId
| sort by TimeGenerated asc
```

---

### Query 11 — Authentication Error Code Discovery

**MITRE:** T1110 — Brute Force
**Table:** `SigninLogs`
**Use when:** Discovering all authentication failure codes without knowing them in advance. Run this early in any identity investigation to understand the full landscape of failures before narrowing down.

```kql
SigninLogs
| where ResultType != 0
| summarize
    Count = count(),
    Description = any(ResultDescription),
    AffectedUsers = make_set(UserPrincipalName),
    SeenFromIPs = make_set(IPAddress)
    by ResultType
| sort by Count desc
```

> **Azure AD Error Code Reference:**
>
> | Code | Meaning |
> |---|---|
> | `0` | Success — attacker authenticated |
> | `50074` | MFA required but not completed — fatigue in progress |
> | `50126` | Invalid username or password — credential stuffing |
> | `50140` | Keep me signed in interrupt — auth in progress |
> | `50089` | Flow token expired — session replay attempt |
> | `50055` | Password expired — targeted account |
> | `53003` | Blocked by Conditional Access — defence working |
> | `16003` | Account not in directory — wrong tenant |

---

### Query 12 — Data Compression for Exfiltration

**MITRE:** T1560 — Archive Collected Data
**Table:** `DeviceProcessEvents`
**Use when:** Finding compression commands targeting sensitive directories. Attackers compress data before exfiltration to reduce transfer time and evade DLP controls.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has_any (
    "Compress-Archive", "7z", "zip", "rar", "tar")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 13 — rclone Cloud Exfiltration Detection

**MITRE:** T1567.002 — Exfiltration to Cloud Storage
**Table:** `DeviceProcessEvents`
**Use when:** Detecting rclone usage to upload data to cloud storage providers. Rclone is frequently abused by threat actors for stealthy exfiltration because it blends with legitimate cloud sync activity.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where FileName == "rclone.exe"
    or ProcessCommandLine has "rclone"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 14 — C2 Network Detection

**MITRE:** T1071 — Application Layer Protocol
**Table:** `DeviceNetworkEvents`
**Use when:** Hunting for Command and Control (C2) beaconing from suspicious processes. Always start broad to identify all external connections, then narrow down to a specific IP for the full picture.

> **Investigation approach:** Go general first to identify the suspicious IP, then narrow down for full context and timeline.

#### Step 1 — Broad C2 Hunt (All Suspicious Processes)

```kql
DeviceNetworkEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName == "TARGET_DEVICE"
| where InitiatingProcessFileName in (
    "powershell.exe", "cmd.exe", "msupdate.exe",
    "wscript.exe", "cscript.exe", "mshta.exe")
| where RemoteIPType == "Public"
| summarize
    ConnectionCount = count(),
    Ports = make_set(RemotePort),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP, InitiatingProcessFileName
| sort by ConnectionCount desc
```

#### Step 2 — Narrow Down to Specific IP

```kql
DeviceNetworkEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName == "TARGET_DEVICE"
| where RemoteIP == "ATTACKER_C2_IP"
| project
    TimeGenerated,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

---

### Query 15 — VSS Shadow Copy Abuse (NTDS Extraction)

**MITRE:** T1003.003 — OS Credential Dumping: NTDS
**Table:** `DeviceProcessEvents`
**Use when:** Detecting ntds.dit extraction via Volume Shadow Copy. This is a domain-level credential theft technique — if this fires, assume full domain compromise.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has_any (
    "vssadmin", "ntds.dit",
    "HarddiskVolumeShadowCopy",
    "shadow", "ntdsutil")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 16 — Impacket Service Detection

**MITRE:** T1543.003 — Create or Modify System Process: Windows Service
**Table:** `DeviceEvents`
**Use when:** Detecting Impacket remote execution. Impacket's psexec creates a randomly named 8-character alphabetic service on the target — this pattern is the signature.

```kql
DeviceEvents
| where DeviceName contains "TARGET_DEVICE"
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| where strlen(ServiceName) == 8
| where ServiceName matches regex @"^[A-Za-z]{8}$"
| project
    Timestamp,
    DeviceName,
    ServiceName,
    AdditionalFields
| sort by Timestamp asc
```

---

### Query 17 — Process Injection Detection

**MITRE:** T1055.003 — Process Injection: Thread Execution Hijacking
**Table:** `DeviceEvents`
**Use when:** Detecting `CreateRemoteThread` injection between processes. A source process injecting into a target process is a strong indicator of in-memory malware execution.

```kql
DeviceEvents
| where DeviceName contains "TARGET_DEVICE"
| where ActionType == "CreateRemoteThreadApiCall"
| extend SourceProcess = tostring(parse_json(AdditionalFields).SourceProcessName)
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| project
    Timestamp,
    DeviceName,
    SourceProcess,
    TargetProcess,
    AdditionalFields
| sort by Timestamp asc
```

---

### Query 18 — LSASS Memory Dump Detection

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory
**Table:** `DeviceFileEvents`
**Use when:** Detecting `.dmp` files created by suspicious processes in temp or user-writable locations. Credential theft tools dump LSASS to extract password hashes and Kerberos tickets.

```kql
DeviceFileEvents
| where DeviceName contains "TARGET_DEVICE"
| where FileName endswith ".dmp"
| where FolderPath has_any ("Temp", "Public", "AppData")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    FileName,
    FolderPath,
    InitiatingProcessCommandLine
| sort by Timestamp asc
```

---

### Query 19 — UAC Bypass via Registry (fodhelper)

**MITRE:** T1548.002 — Abuse Elevation Control: Bypass UAC
**Table:** `DeviceRegistryEvents`
**Use when:** Detecting the fodhelper UAC bypass via registry hijack. Attackers use this to silently elevate privileges without triggering a UAC prompt.

```kql
DeviceRegistryEvents
| where DeviceName contains "TARGET_DEVICE"
| where RegistryKey has "ms-settings"
| where RegistryValueName in ("", "DelegateExecute")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    RegistryKey,
    RegistryValueName,
    RegistryValueData
| sort by Timestamp asc
```

---

### Query 20 — Lateral Movement via Admin Shares

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares
**Table:** `DeviceProcessEvents`
**Use when:** Detecting file copy via C$ admin shares for lateral movement. The combination of `copy`/`xcopy` commands with `C$` in the path is the signature of this technique.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has "C$"
| where ProcessCommandLine has_any ("copy", "xcopy", "move")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 21 — Discovery Command Detection

**MITRE:** T1087 — Account Discovery / T1082 — System Information Discovery
**Table:** `DeviceProcessEvents`
**Use when:** Detecting attacker reconnaissance commands run after initial access. These commands are almost always the first thing an attacker runs after getting a shell.

#### Broad Discovery Hunt

```kql
DeviceProcessEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has_any (
    "systeminfo", "whoami", "net user",
    "net localgroup", "ipconfig", "netstat",
    "tasklist", "wmic computersystem",
    "query user", "nltest", "net group")
| project
    TimeGenerated,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

#### Narrow to Specific Discovery Binary

> Use when the data set is large and you need to focus on one tool.

```kql
DeviceProcessEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName == "TARGET_DEVICE"
| where FileName == "systeminfo.exe"
    or ProcessCommandLine has "systeminfo"
| project
    TimeGenerated,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

### Query 22 — Scheduled Task Persistence Detection

**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Tables:** `DeviceProcessEvents` + `DeviceEvents`
**Use when:** Detecting scheduled task creation for persistence. Run both queries — the process-based query catches the command execution, the DeviceEvents query gives you the full task content.

#### Via Process Events (Catches the Command)

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has "/create"
| extend TaskName = extract(
    @"/tn\s+""?([^"" ]+)""?", 1, ProcessCommandLine)
| project
    Timestamp,
    DeviceName,
    AccountName,
    TaskName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

#### Via DeviceEvents (Gets Full Task Content)

```kql
DeviceEvents
| where DeviceName contains "TARGET_DEVICE"
| where ActionType == "ScheduledTaskCreated"
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend Command = tostring(parse_json(AdditionalFields).TaskContent)
| extend CreatedBy = tostring(parse_json(AdditionalFields).SubjectUserName)
| project
    TimeGenerated,
    CreatedBy,
    TaskName,
    Command
| sort by TimeGenerated asc
```

---

### Query 23 — AnyDesk / Remote Access Tool Silent Install Detection

**MITRE:** T1219 — Remote Access Software
**Table:** `DeviceProcessEvents`
**Use when:** Detecting silent installation of remote access tools. Attackers install RATs to maintain persistent access that survives password resets and RDP lockouts.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has_any (
    "anydesk", "teamviewer", "screenconnect",
    "splashtop", "logmein", "vnc")
| where ProcessCommandLine has "--silent"
    or ProcessCommandLine has "--install"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 24 — Event Log Clearing Detection

**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs
**Table:** `DeviceProcessEvents`
**Use when:** Detecting an attacker clearing Windows event logs to destroy evidence. If this fires, immediately preserve all available telemetry — the attacker knows they are or were detected.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has "wevtutil"
| where ProcessCommandLine has "cl"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 25 — Firewall Rule Addition Detection

**MITRE:** T1562.004 — Impair Defenses: Disable or Modify System Firewall
**Table:** `DeviceProcessEvents`
**Use when:** Detecting an attacker adding firewall rules to allow their tools or open ports for lateral movement. Commonly used to open RDP, reverse shell ports, or allow C2 traffic.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where ProcessCommandLine has "netsh"
| where ProcessCommandLine has_any ("firewall", "advfirewall")
| where ProcessCommandLine has "add"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 26 — DNS C2 Detection

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Table:** `DeviceNetworkEvents`
**Use when:** Finding C2 domain queries from suspicious processes. Excludes known-good browsers and system processes to reduce noise. DNS tunnelling is a stealthy C2 technique that often bypasses firewall rules.

```kql
DeviceNetworkEvents
| where DeviceName contains "TARGET_DEVICE"
| where InitiatingProcessFileName !in (
    "svchost.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "SearchApp.exe")
| where RemotePort == 53
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteUrl,
    InitiatingProcessCommandLine
| sort by Timestamp asc
```

---

### Query 27 — Suspicious Binary in World-Writable Location

**MITRE:** T1204.002 — User Execution: Malicious File
**Table:** `DeviceProcessEvents`
**Use when:** Finding executables running from user-writable locations like Temp, Downloads, or AppData. Legitimate software rarely executes from these paths — this is a strong indicator of malware or attacker tooling.

```kql
DeviceProcessEvents
| where DeviceName contains "TARGET_DEVICE"
| where AccountName == "TARGET_ACCOUNT"
| where FolderPath has_any (
    "\\Users\\Public",
    "\\Temp",
    "\\Downloads",
    "\\AppData\\Roaming",
    "\\AppData\\Local\\Temp")
| project
    Timestamp,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Query 28 — Data Staging for Exfiltration (Compressed Archives)

**MITRE:** T1560 — Archive Collected Data
**Table:** `DeviceFileEvents`
**Use when:** Finding compressed archives created before exfiltration. After gathering sensitive data, attackers compress it to a zip/rar/7z for staging. Search for these files then look for the upload event.

> **Note:** `ActionType` values for file events are: `FileCreated`, `FileDeleted`, `FileModified`, `FileRenamed`

```kql
DeviceFileEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName == "TARGET_DEVICE"
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project
    TimeGenerated,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

---

### Query 29 — PowerShell Command Audit

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Table:** `DeviceEvents`
**Use when:** Auditing PowerShell commands run on an endpoint. Run this at the beginning of any endpoint investigation — it surfaces what scripts and commands were executed, including those run by attackers to disable defences.

```kql
DeviceEvents
| where TimeGenerated between (
    datetime(2025-09-15T00:00:00) .. datetime(2025-09-17T23:00:00))
| where DeviceName == "TARGET_DEVICE"
| where ActionType == "PowerShellCommand"
| where InitiatingProcessAccountName != "system"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| project
    TimeGenerated,
    Command,
    FileName,
    FileOriginIP,
    InitiatingProcessAccountName
| sort by TimeGenerated asc
```

---

### Query 30 — Recently Accessed Files (LNK / Shell Recent)

**MITRE:** T1074 — Data Staged
**Table:** `DeviceFileEvents`
**Use when:** Identifying files that were manually opened by a user or attacker via Explorer. Windows creates `.lnk` shortcut files in the `Recent` folder every time a file is opened — this is a reliable indicator of what the attacker was reading.

```kql
DeviceFileEvents
| where TimeGenerated between (
    datetime(2025-10-09 12:00:00) .. datetime(2025-10-09 14:00:00))
| where FileName endswith ".lnk"
| where InitiatingProcessFileName == "explorer.exe"
| where FolderPath has "Recent"
| project
    TimeGenerated,
    FileName,
    FolderPath
| sort by TimeGenerated asc
```

> **Note:** The file ends in `.lnk` and is launched by `explorer.exe`. This tells you what the user (or attacker) opened manually from the GUI during the session.

---

### Query 31 — RDP Connection Funnel

**MITRE:** T1110.001 — Brute Force / T1021.001 — Remote Desktop Protocol
**Table:** `DeviceNetworkEvents`
**Use when:** Analysing RDP attack surface on a device. Produces three outputs in one query: unique IPs that attempted, unique IPs that were accepted, and the overlap (IPs that both attempted AND were accepted). The overlap is your highest priority investigation set.

#### Step 1 — Find the Most Targeted Port

> Run this first if you do not know which port was attacked.

```kql
DeviceNetworkEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where ActionType in ("InboundConnectionAccepted", "ConnectionAttempt")
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by LocalPort
| order by ConnectionCount desc
```

#### Step 2 — Full RDP Connection Funnel

> Feed the port identified in Step 1 into `LocalPort` below.

```kql
let AllEvents = DeviceNetworkEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted");

let Attempts = AllEvents
| where ActionType == "ConnectionAttempt"
| distinct RemoteIP;

let Accepted = AllEvents
| where ActionType == "InboundConnectionAccepted"
| distinct RemoteIP;

let Overlap = AllEvents
| summarize ActionTypes = make_set(ActionType) by RemoteIP
| where set_has_element(ActionTypes, "ConnectionAttempt")
    and set_has_element(ActionTypes, "InboundConnectionAccepted")
| distinct RemoteIP;

union
    (Attempts | summarize ConnectionAttempt_UniqueIPs = dcount(RemoteIP)),
    (Accepted | summarize InboundAccepted_UniqueIPs   = dcount(RemoteIP)),
    (Overlap  | summarize Both_Attempt_AND_Accepted   = dcount(RemoteIP))
```

---

### Query 32 — Geographic Enrichment (GeoIP Lookup)

**MITRE:** T1078 — Valid Accounts
**Tables:** `DeviceNetworkEvents` + `DeviceLogonEvents`
**Use when:** Enriching IP addresses with country and continent data. Use this on both network events and authentication events separately — the populations often differ and the gap reveals blind spots. Always enrich auth events separately from network events.

> **Important:** Always enrich `DeviceNetworkEvents` AND `DeviceLogonEvents` independently. The gap between the two populations can reveal actors you would otherwise miss.

#### How Many Countries Are Hitting the RDP Port?

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let AllEvents = DeviceNetworkEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize ActionTypes = make_set(ActionType) by RemoteIP
| where set_has_element(ActionTypes, "ConnectionAttempt")
    and set_has_element(ActionTypes, "InboundConnectionAccepted")
| distinct RemoteIP;
AllEvents
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize UniqueCountries = dcount(country_name)
```

#### How Many Countries Attempted RDP Authentication?

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIPType == "Public"
| where LogonType in ("RemoteInteractive", "Network")
| distinct RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize UniqueCountries = dcount(country_name)
```

#### Which Countries Had Successful Authentications?

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIPType == "Public"
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| distinct RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
| order by country_name asc
```

#### How Many Successful Auths Came From a Specific Country?

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIPType == "Public"
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "TARGET_COUNTRY"
| summarize count()
```

---

### Query 33 — File Rename to Executable (Double Extension Evasion)

**MITRE:** T1036.007 — Masquerading: Double File Extension
**Table:** `DeviceFileEvents`
**Use when:** Hunting for the double-extension evasion technique where a file is stored as `.exe.Txt` then renamed to `.exe` to bypass file type controls. Also catches any rename event where a file becomes an executable.

#### Pattern 1 — Find Files with Double Extension Still Active

```kql
DeviceFileEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where FileName matches regex @".*\.exe\.(txt|Txt|TXT|pdf|doc|jpg|png)$"
| project
    TimeGenerated,
    FileName,
    FolderPath,
    ActionType,
    SHA256
| order by TimeGenerated asc
```

#### Pattern 2 — Catch the Weaponization Moment (Rename to Executable)

```kql
DeviceFileEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where InitiatingProcessAccountName =~ "TARGET_ACCOUNT"
| where ActionType == "FileRenamed"
| where FileName endswith ".exe"
    or FileName endswith ".bat"
    or FileName endswith ".ps1"
    or FileName endswith ".cmd"
    or FileName endswith ".vbs"
    or FileName endswith ".dll"
| project
    TimeGenerated,
    FileName,
    PreviousFileName,
    FolderPath,
    InitiatingProcessFileName
| order by TimeGenerated asc
```

#### Pattern 3 — Full Rename History with ActionType Count

```kql
DeviceFileEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where InitiatingProcessAccountName =~ "TARGET_ACCOUNT"
| where FileName endswith ".txt" or FileName endswith ".Txt"
| summarize Count = count() by ActionType, FileName
| order by Count desc
```

---

### Query 34 — Track File by SHA256 Hash Across All Renames

**MITRE:** T1036 — Masquerading
**Table:** `DeviceFileEvents`
**Use when:** Following a payload through every rename, move, and directory change regardless of filename. File names lie — hashes do not. This is the most reliable way to track a payload's complete lifecycle.

> **Key Principle:** The SHA256 hash remains identical across all renames. One hash = one file, no matter how many times it is renamed or moved.

#### Find the SHA256 from Known Filenames

```kql
DeviceFileEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where FileName in (
    "KNOWN_FILENAME_1.exe",
    "KNOWN_FILENAME_2.Txt",
    "KNOWN_FILENAME_3.exe")
| where isnotempty(SHA256)
| project
    TimeGenerated,
    FileName,
    SHA256,
    FolderPath,
    ActionType
| order by TimeGenerated asc
```

#### Track the Full Lifecycle by Hash

```kql
DeviceFileEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where SHA256 == "KNOWN_SHA256_HASH"
| project
    TimeGenerated,
    ActionType,
    FileName,
    FolderPath
| order by TimeGenerated asc
```

---

### Query 35 — Defender Exclusion Detection

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools
**Tables:** `DeviceProcessEvents` + `DeviceEvents` + `DeviceRegistryEvents`
**Use when:** Detecting attempts to add AV exclusions or disable real-time monitoring. Attackers do this to prevent their payloads from being quarantined. Run all three paths — each catches a different method.

#### Path 1 — Process Execution (Most Common)

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "Add-MpPreference", "Set-MpPreference",
    "ExclusionPath", "DisableRealtimeMonitoring")
| project
    TimeGenerated,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

#### Path 2 — PowerShell Commands (Script-Based Changes)

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where Command has_any (
    "Add-MpPreference", "ExclusionPath",
    "DisableRealtimeMonitoring")
| project
    TimeGenerated,
    Command
| sort by TimeGenerated asc
```

#### Path 3 — Registry (When DeviceRegistryEvents is Populated)

```kql
DeviceRegistryEvents
| where RegistryKey has "Windows Defender"
| where RegistryKey has "Exclusions"
| project
    TimeGenerated,
    AccountName,
    RegistryKey,
    RegistryValueName,
    InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

### Query 36 — Windows Defender Mode Detection

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools
**Table:** `DeviceEvents`
**Use when:** Detecting that Windows Defender has been switched to passive mode or disabled. In passive mode Defender detects but does NOT block — giving attackers a free run even when the payload is flagged.

> **Defender Mode Reference:**
> - `Active Mode` — Defender scans, detects, and blocks. Normal operation.
> - `Passive Mode` — Defender detects and logs but **does not block**. Attacker's sweet spot.
> - `Disabled` — No scanning at all.

#### Step 1 — Survey All ActionTypes First

```kql
// Always run this first on an unknown device — discover what data exists
DeviceEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by ActionType
| order by count_ desc
```

#### Step 2 — Extract AV Detections with Defender Mode

```kql
DeviceEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where ActionType in (
    "AntivirusDetection",
    "AntivirusDetectionActionType",
    "AntivirusReport")
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName   = tostring(ParsedFields.ThreatName)
| extend DefenderMode = tostring(ParsedFields.ReportSource)
| extend Description  = tostring(ParsedFields.Description)
| project
    TimeGenerated,
    ActionType,
    SHA256,
    ThreatName,
    DefenderMode,
    Description
| order by TimeGenerated asc
```

#### Step 3 — Summarise Defender Mode by Threat

```kql
DeviceEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where ActionType in (
    "AntivirusDetection",
    "AntivirusDetectionActionType",
    "AntivirusReport")
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName   = tostring(ParsedFields.ThreatName)
| extend DefenderMode = tostring(ParsedFields.ReportSource)
| summarize count() by DefenderMode, ThreatName
| order by count_ desc
```

---

### Query 37 — Payload Execution and Parent Process Identification

**MITRE:** T1204 — User Execution / T1547 — Boot or Logon Autostart Execution
**Table:** `DeviceProcessEvents`
**Use when:** Identifying what process launched a known malicious executable. The `InitiatingProcessFileName` and `InitiatingProcessCommandLine` tell you whether the payload was launched manually, via a batch file, scheduled task, or service — critical for understanding the persistence mechanism.

#### Find All Executions of a Known Payload

```kql
DeviceProcessEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where FileName == "PAYLOAD_NAME.exe"
    or ProcessCommandLine contains "PAYLOAD_NAME.exe"
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```

#### Find the First Notable Process After Compromise

> Use this to identify the first command an attacker ran after gaining access. Exclude known noise processes to surface the operator's first deliberate action.

```kql
DeviceProcessEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated >= datetime(2025-12-13)
| where InitiatingProcessAccountName == "TARGET_ACCOUNT"
| where InitiatingProcessCommandLine !contains "NOISE_SCRIPT.ps1"
| where FileName !in (
    "conhost.exe", "msedge.exe", "sihost.exe",
    "taskhostw.exe", "ctfmon.exe", "RuntimeBroker.exe")
| project
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Query 38 — C2 Callback Detection by Payload SHA256

**MITRE:** T1071 — Application Layer Protocol / T1571 — Non-Standard Port
**Table:** `DeviceNetworkEvents`
**Use when:** Finding C2 beaconing pivoted from a known payload hash rather than filename. This is the most reliable C2 detection method — payload renames cannot hide the outbound connection when you filter by hash.

> **Key Principle:** Hunt by `InitiatingProcessSHA256`, not by `InitiatingProcessFileName`. The attacker renamed the file five times — the hash never changed.

#### C2 Callback by Hash

```kql
DeviceNetworkEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where InitiatingProcessSHA256 == "KNOWN_PAYLOAD_SHA256"
| where RemoteIPType == "Public"
| project
    TimeGenerated,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    ActionType
| order by TimeGenerated asc
```

#### Hunt All Non-Standard Outbound Ports (General C2 Detection)

```kql
DeviceNetworkEvents
| where DeviceName == "TARGET_DEVICE"
| where TimeGenerated between (
    datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIPType == "Public"
| where RemotePort !in (80, 443, 53, 8080, 8443)
| summarize
    count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemotePort, RemoteIP, InitiatingProcessFileName
| order by count_ desc
```

---

## 📊 Table Selection Quick Reference

| Question | Table | Key Fields |
|---|---|---|
| Who signed in? From where? | `SigninLogs` | `UserPrincipalName`, `IPAddress`, `LocationDetails` |
| What happened inside M365? | `CloudAppEvents` | `AccountDisplayName`, `ActionType`, `RawEventData` |
| What emails were sent? | `EmailEvents` | `SenderFromAddress`, `RecipientEmailAddress`, `Subject` |
| What processes ran on endpoint? | `DeviceProcessEvents` | `FileName`, `ProcessCommandLine`, `AccountName` |
| What files were created / renamed? | `DeviceFileEvents` | `FileName`, `FolderPath`, `SHA256`, `ActionType` |
| What network connections were made? | `DeviceNetworkEvents` | `RemoteIP`, `RemotePort`, `InitiatingProcessFileName` |
| What registry changes were made? | `DeviceRegistryEvents` | `RegistryKey`, `RegistryValueName`, `RegistryValueData` |
| Who logged on to an endpoint? | `DeviceLogonEvents` | `RemoteIP`, `ActionType`, `LogonType` |
| What AV detections occurred? | `DeviceEvents` | `ActionType`, `AdditionalFields`, `SHA256` |
| What PowerShell ran? | `DeviceEvents` | `ActionType == "PowerShellCommand"`, `AdditionalFields` |

---

## 🔧 JSON Field Extraction Cheat Sheet

Always use this formula for nested JSON fields:

```kql
| extend NewColumn = tostring(parse_json(FieldName).keyName)
```

**Common extractions:**

```kql
// SigninLogs
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend City    = tostring(parse_json(LocationDetails).city)
| extend OS      = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)

// CloudAppEvents
| extend SessionId   = tostring(parse_json(tostring(RawEventData)).AppAccessContext.AADSessionId)
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)

// DeviceEvents — AV detections
| extend ThreatName   = tostring(parse_json(AdditionalFields).ThreatName)
| extend DefenderMode = tostring(parse_json(AdditionalFields).ReportSource)
| extend Command      = tostring(parse_json(AdditionalFields).Command)
```

---

## 🧠 The countif Pattern — Brute Force Signature

```kql
| summarize
    FailCount    = countif(ActionType == "LogonFailed"),
    SuccessCount = countif(ActionType == "LogonSuccess")
    by RemoteIP
| where SuccessCount > 0 and FailCount > 0
| sort by FailCount desc
```

> Use whenever a question mentions repeated failures followed by success. The combination of `FailCount > 0` AND `SuccessCount > 0` on the same IP is the definitive brute force signature.

---

## 🪟 Windows Logon Type Reference

| LogonType | Value | Description | Investigation Use |
|---|---|---|---|
| Interactive | 2 | Physical keyboard login at console | Local only — not RDP |
| **Network** | **3** | **Auth over network — RDP brute force tools use this** | **RDP investigation** |
| Batch | 4 | Scheduled tasks | Persistence hunting |
| Service | 5 | Service account logons | Lateral movement |
| Unlock | 7 | Screen unlock | Limited use |
| **RemoteInteractive** | **10** | **Full RDP GUI session — real human at the keyboard** | **RDP investigation** |
| CachedInteractive | 11 | Cached domain credentials | Offline attacks |

> **For RDP investigations:** Always filter on **both** `RemoteInteractive` AND `Network`. Network logon type catches brute force tools authenticating programmatically. RemoteInteractive catches actual GUI sessions. Missing either one gives you an incomplete picture.

---

## 🔑 Key Hunting Principles

| Principle | Detail |
|---|---|
| **Survey before filtering** | Always run `summarize count() by ActionType` first on any new table or device. Never assume which ActionTypes exist — the data will surprise you. |
| **Hunt by hash, not name** | Attackers rename files constantly. `SHA256` never changes. Always pivot on hash when tracking payloads. |
| **Check RemoteIPType carefully** | `ConnectionAttempt` events often have no `RemoteIPType` set. Filtering `RemoteIPType == "Public"` can silently exclude events you need. When counts seem low — drop the filter. |
| **Enrich both tables separately** | `DeviceNetworkEvents` and `DeviceLogonEvents` have different IP populations. Always GeoIP enrich both independently — the gap between them reveals actors you would otherwise miss. |
| **Build funnels, not snapshots** | Reduce your population at each step. 173 IPs → 57 connected AND attempted → 2 countries succeeded → 1 anomalous country. Each filter increases signal fidelity. |
| **Same subnet = same actor** | When you find one malicious IP, always check the surrounding `/24`. Attackers use multiple IPs from the same infrastructure block. |
| **parse_json() for AdditionalFields** | AV, PowerShell, and service event data lives inside a JSON blob. Extract each field individually with `extend Field = tostring(parse_json(AdditionalFields).FieldName)` before filtering on it. |
| **LogonType matters for RDP** | `RemoteInteractive` = full GUI session. `Network` = brute force tool. Both are needed for complete RDP attack surface visibility. |

---

*KQL Hunting Playbook — Built from live cyber range investigations*
*Author: Sakho Aboubacar | Reviewer: Josh Madakor*
*For defensive security and portfolio use only*
