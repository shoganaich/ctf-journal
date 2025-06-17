# Helper Queries / Micro KQL Playbook

Quick reference and “I *know* I did this before!” dump.
All queries are real-world tested in CTF's, threat hunts or Labs.

---

## Table of Contents

* [Azure & VM Recon](#azure--vm-recon)
* [Process Creation & LOLBins](#process-creation--lolbins)
* [Persistence: Registry, Scheduled Tasks, Shortcuts](#persistence-registry-scheduled-tasks-shortcuts)
* [Network Beacons & C2](#network-beacons--c2)
* [File Drops & Artifacts](#file-drops--artifacts)
* [Obfuscation & Encoded Commands](#obfuscation--encoded-commands)
* [User Logons & Lateral Movement](#user-logons--lateral-movement)
* [Compression, Exfiltration, & Staging](#compression-exfiltration--staging)
* [Quick Tips, Formatting, & Troubleshooting](#quick-tips-formatting--troubleshooting)

---

## 🖥️ Azure & VM Recon

*Finding newly created, deleted, or short-lived VMs in Azure Log Analytics Workspace.*

```kql
let start = datetime(YYYY-MM-DD);
let end = datetime(YYYY-MM-DD);
AzureActivity
| extend VmName = tostring(parse_json(Properties).resource)
| where TimeGenerated between (start .. end)
| where OperationNameValue in ("MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE")
| project TimeGenerated, OperationNameValue, ResourceGroup, Resource, Caller, VMName
| order by TimeGenerated asc
```

*Refine with lifetime filter to find VMs that lived < X hours:*

```kql
let start = datetime(YYYY-MM-DD); //Add startdate or timestamp
let end = datetime(YYYY-MM-DD); //Add enddate or timestamp
VMHUNT = AzureActivity
| where TimeGenerated between (start .. end)
| where OperationNameValue in ("MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE")
| extend VMName = tostring(parse_json(Properties).resource)
| summarize
    CreateTime = minif(TimeGenerated, OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE"),
    DeleteTime = minif(TimeGenerated, OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE")
    by ResourceGroup, VMName
| extend LifetimeMinutes = datetime_diff("minute", DeleteTime, CreateTime)
| where isnotempty(DeleteTime) and LifetimeMinutes < XXX //You should add the minutes quantity here.
| sort by CreateTime asc;
```

> **When to use:**
>
> * First step in any Azure/Cloud CTF or IR to scope assets, spot ephemeral attack VMs.

---

## 🏃‍ Process Creation & LOLBins

*Catch suspicious PowerShell, LOLBin, and manual EXE launches (esp. via explorer.exe).*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where FileName in ~("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "OTHERSUSPICIUSBIN.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "IEX", "Invoke-Expression", "/c", ".lnk")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

*Or, show only processes started by explorer.exe (for user-executed malware):*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where InitiatingProcessFileName == "explorer.exe"
| where FolderPath !startswith "C:\\Windows"
| order by Timestamp asc
```

> **When to use:**
>
> * Hunt for initial access, fileless execution, living-off-the-land, and attacks launched via user interaction.

---

## 🔗 Persistence: Registry, Scheduled Tasks, Shortcuts

*Registry run keys, scheduled task creation, and dropped .lnk files.*

**Registry Run Key for Persistence:**

```kql
let asset = "<hostname>";
DeviceRegistryEvents
| where DeviceName == asset
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| where RegistryKey contains "Run" or RegistryKey contains "Startup" or RegistryKey contains "Policies"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Scheduled Task Creation:**

```kql
let asset = "<hostname>";
DeviceEvents
| where DeviceName == asset
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

*Focus on tasks with suspicious .ps1, .exe, or “flag” keywords:*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where ProcessCommandLine contains "schtasks"
| where ProcessCommandLine has_any ("spicykeywordexample", "payloadkeywordexample", "flagkeywordexample", ".ps1", ".exe")
| order by Timestamp desc
```

**Suspicious .lnk (shortcut) Files:**

```kql
let asset = "<hostname>";
DeviceFileEvents
| where DeviceName == asset
| where FileName endswith ".lnk"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

> **When to use:**
>
> * Suspect persistence, privilege escalation, malware autostart, or user-targeted shortcuts.

---

## 🌐 Network Beacons & C2

*Detect exfiltration, beacons, or connections to external C2 or staging domains.*

```kql
let asset = "<hostname>";
DeviceNetworkEvents
| where DeviceName == asset
| where RemoteUrl has_any ("pipedream.net", "ngrok", "webhook.site", "othersuspiciuswebhook.site")
| where RemoteUrl != ""
| order by Timestamp asc
```

> **When to use:**
>
> * Finding first outbound C2, suspicious domain callbacks, or lateral movement via DNS.

---

## 🗂️ File Drops & Artifacts

*Hunt for dropped malware, scripts, .lnk, or anything with "keywd1" "keywd2" "keywd3" or "keywd4" in the name.*

```kql
let asset = "<hostname>";
DeviceFileEvents
| where DeviceName == asset
| where FileName has_any ("keywd1", "keywd2", "keywd3", "keywd4")
| where FileName endswith ".ps1" or FileName endswith ".py" or FileName endswith ".dat" or FileName endswith ".js"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

*All newly created executables/scripts/shortcuts:*

```kql
let asset = "<hostname>";
DeviceFileEvents
| where DeviceName == asset
| where FileName endswith ".exe" or FileName endswith ".js" or FileName endswith ".ps1" or FileName endswith ".py" or FileName endswith ".lnk"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

> **When to use:**
>
> * Flag drops, keyloggers, persistence, lateral movement, and user artifact creation.

---

## 🧙 Obfuscation & Encoded Commands

*Detect use of -EncodedCommand, PowerShell base64 blobs, or odd command-line parameters.*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where ProcessCommandLine has "-EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

*Regex for generic base64/obfuscation:*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where ProcessCommandLine matches regex "[A-Za-z0-9+/=]{20,}"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

> **When to use:**
>
> * Find obfuscated code, “secret” flag chains, or evidence of defense evasion.

---

## 👤 User Logons & Lateral Movement

*Spot brute-force, remote logons, and credential abuse.*

```kql
let asset = "<hostname>";
DeviceLogonEvents
| where DeviceName == asset
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
| order by Timestamp desc
```

> **When to use:**
>
> * Pivoting, privilege escalation, or CTF lateral movement flags.

---

## 📦 Compression, Exfiltration, & Staging

*Find compressed files, archivers, or suspicious staging activity.*

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| where ProcessCommandLine has_any ("7z", "zip", "tar", "Compress-Archive")
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath
| sort by Timestamp desc
```

> **When to use:**
>
> * Exfil prep, staging, or when CTF flags mention “archive” or “packing.”

---

## ⚡ Quick Tips, Formatting, & Troubleshooting

**Show Complete UTC Timestamping for KQL Output:**

```kql
let asset = "<hostname>";
DeviceProcessEvents
| where DeviceName == asset
| extend TimestampFormatted = strcat(format_datetime(Timestamp, 'yyyy-MM-dd'), "T", format_datetime(Timestamp, 'HH:mm:ss.fffffff'), "Z")
```

**Reduce result overload:**
```kql
| sort by Timestamp desc`
```

**Sort by most recent:**
```kql
| sort by Timestamp desc
```

---

> As my blue team journey continues, so will this collection—expect rewrites, wild new hunts, and the occasional “WTF is this query?”
>
> Cybersecurity is all about learning, remixing, and remembering what actually works in the field!
