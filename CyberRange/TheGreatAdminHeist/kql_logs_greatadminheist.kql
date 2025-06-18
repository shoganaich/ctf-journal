DeviceFileEvents
| where DeviceName startswith "anthony-001"


DeviceProcessEvents
| where DeviceName == "anthony-001"

DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| where Timestamp >= ago(30d)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| where Timestamp >= ago(30d)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, AccountName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "BitSentinelCore.exe"
| where Timestamp >= ago(30d)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where FileName contains "news" or FileName contains "log" or FileName contains "key"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where FileName contains "news" or FileName contains "log" or FileName contains "key"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where not(FolderPath startswith "D:")
| summarize FileWrites = count() by FileName, FolderPath, InitiatingProcessFileName
| order by FileWrites desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where FileName endswith ".py"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where ProcessCommandLine contains "news" or ProcessCommandLine contains "log" or ProcessCommandLine contains "key"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where FileName endswith ".ps1" or FileName endswith ".py" or FileName endswith ".dat"
//| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)

DeviceFileEvents
//| where InitiatingProcessFileName == "BitSentinelCore.exe"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine, SHA256

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where InitiatingProcessFileName == "BitSentinelCore.exe"
//| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine, SHA256

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| where FileName has "news" or FileName has "log" or FileName has "key" or FileName has "macro"

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName

DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName has_any (".exe", ".js", ".ps1", ".py", ".ink")
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

DeviceEvents
| where DeviceName == "anthony-001"
| where AdditionalFields has_any ("GetAsyncKeyState", "SetWindowsHookEx", "Add-Type", ".dll", ".Ink")
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields, ReportId
| order by Timestamp desc 

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".ps1" or ProcessCommandLine has_any ("GetAsyncKeyState", "SetWindowsHookEx", "user32.dll", "Add-Type")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId


DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where FileName has_any ("user32.dll", "keyboard.dll")  // Keylogging-related APIs
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, FolderPath, ReportId

DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where FileName has_any ("user32.dll", "keyboard.dll")  // Keylogging-related APIs
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, FolderPath, ReportId

DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".lnk"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| where RegistryKey contains "Run" or RegistryKey contains "Startup" or RegistryKey contains "Policies"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents 
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
//| where ActionType == "TaskCreated"
//| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(60d)
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp < datetime(2025-05-07T02:02:14.6264638Z)
| where FolderPath !startswith "C:\\Windows" 
//|project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc 

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "explorer.exe"
| where FolderPath !startswith "C:\\Windows" 
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc


DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| where RegistryKey contains "Run" or RegistryKey contains "Startup" or RegistryKey contains "Policies"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| project Timestamp, TimestampFormatted, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where ActionType == "ScheduledTaskCreated"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| project Timestamp, TimestampFormatted, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where FileName endswith ".lnk"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| project Timestamp, TimestampFormatted, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc
//| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine contains "csc.exe"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
//| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, AccountName
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where LogonType == "RemoteInteractive"
| where Timestamp <= datetime(2025-05-07T03:05:00Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp desc 

DeviceEvents
| where DeviceName == "anthony-001"
| where ActionType == "ScheduledTaskCreated"
| where Timestamp <= datetime(2025-05-07T03:05:00Z)
| project Timestamp, AdditionalFields, InitiatingProcessFileName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName in ("csc.exe", "powershell.exe", "RuntimeBroker.exe")
| where Timestamp between (datetime(2025-05-07T00:00:00Z) .. datetime(2025-05-07T03:05:00Z))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T01:50:00Z) .. datetime(2025-05-07T03:10:00Z))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, InitiatingProcessParentFileName
| order by Timestamp asc

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T01:50:00Z) .. datetime(2025-05-07T03:10:00Z))
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc

DeviceLogonEvents
| where RemoteIP == "49.147.196.23" or AdditionalFields has "49.147.196.23"
//| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, InitiatingProcessFileName, AdditionalFields
| order by Timestamp asc

DeviceProcessEvents
| where ProcessCommandLine has "49.147.196.23" or AdditionalFields has "49.147.196.23"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AdditionalFields
| order by Timestamp asc

DeviceFileEvents
| where InitiatingProcessCommandLine has "49.147.196.23" or AdditionalFields has "49.147.196.23"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T03:05:00Z)
| where RemoteIP == "49.147.196.23" or AdditionalFields has "49.147.196.23"

DeviceLogonEvents
| where RemoteIP == "49.147.196.23" or AdditionalFields has "49.147.196.23"
//| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, InitiatingProcessFileName, AdditionalFields
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine contains "powershell"
| where Timestamp < datetime(2025-05-07T02:02:14.6264638Z)
| order by Timestamp desc
//| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine

DeviceLogonEvents
| where DeviceName == "anthony-001"
| order by Timestamp asc
//| project Timestamp, AccountName, RemoteIP, LogonType, InitiatingProcessFileName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine contains ".ps1"
| where ProcessCommandLine !contains @"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
| project Timestamp, ProcessCommandLine
| sort by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| where InitiatingProcessFileName startswith "powershell" or InitiatingProcessFileName startswith "csc"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| project Timestamp, TimestampFormatted, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc 

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where LogonType == "RemoteInteractive"
| where Timestamp < datetime(2025-05-07T02:00:00Z)
| order by Timestamp asc
| project Timestamp, AccountName, RemoteIP


DeviceLogonEvents
| where DeviceName == "anthony-001"
| order by Timestamp desc 
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
//| project Timestamp, AccountName, RemoteIP, LogonType, InitiatingProcessFileName
| distinct AccountName, ActionType, RemoteIP

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where AccountName =~ "4nth0ny!"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".exe"
| where FolderPath !startswith "C:\\Windows\\System32"
| order by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where AccountName =~ "4nth0ny!"
| order by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "csc.exe"
| where InitiatingProcessFileName == "powershell.exe"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc


DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "powershell.exe"
| where Timestamp between (datetime(2025-05-07T00:50:00Z) .. datetime(2025-05-07T01:00:00Z))
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= datetime(2025-05-07T00:59:07.8881755Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where AccountName == "BUBBA"
| where IsProcessRemoteSession == true
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, ProcessRemoteSessionIP
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where AccountName == "BUBBA"
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where RemoteIP == "192.168.0.110"
| project Timestamp, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, InitiatingProcessAccountName
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where RemoteIP == "192.168.0.110"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where RemotePort == 3389
| order by Timestamp asc

DeviceRegistryEvents
| where DeviceName == "anthony-001"

AlertInfo

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "powershell.exe"
| where Timestamp between (datetime(2025-05-06T00:00:00Z) .. datetime(2025-05-08T00:00:00Z))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, ProcessIntegrityLevel, IsProcessRemoteSession, ProcessRemoteSessionIP
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
//| where InitiatingProcessAccountName == @"4nth0ny!"
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| order by Timestamp asc

DeviceNetworkEvents
| where RemoteIP == "192.168.0.110"
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T00:20:00Z) .. datetime(2025-05-07T02:10:00Z))
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where FileName == "runtimebroker.exe"
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= ago(30d)
| where FileName == "runtimebroker.exe"
| order by Timestamp desc

DeviceImageLoadEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName contains "runtimebroker.exe"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)

DeviceNetworkEvents
| where DeviceName == "anthony-001"

DeviceFileEvents
| where DeviceName == "anthony-001"


DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where RegistryKey contains "CLSID"
| where Timestamp >= ago(30d)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)

DeviceEvents
| where DeviceName == "anthony-001"
| where ActionType contains "ScheduledTask"


DeviceInfo
| where DeviceName == "anthony-001"

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "explorer.exe"
| where FolderPath !startswith "C:\\Windows"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc

DeviceProcessEvents 
| where DeviceName == "anthony-001"
| order by Timestamp asc


DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp desc

DeviceNetworkEvents

DeviceLogonEvents
| where DeviceName == "anthony-001"
| order by Timestamp desc 
| where Timestamp <= datetime(2025-05-07T02:02:14.6264638Z)
//| project Timestamp, AccountName, RemoteIP, LogonType, InitiatingProcessFileName
| distinct AccountName, ActionType, RemoteIP

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where AccountName =~ "4nth0ny!"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".exe"
| where FolderPath !startswith "C:\\Windows\\System32"
| order by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where AccountName =~ "4nth0ny!"
| order by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "csc.exe"
| where InitiatingProcessFileName == "powershell.exe"
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc


DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "powershell.exe"
| where Timestamp between (datetime(2025-05-07T00:50:00Z) .. datetime(2025-05-07T01:00:00Z))
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp >= datetime(2025-05-07T00:59:07.8881755Z)
| extend TimestampFormatted = strcat(
    format_datetime(Timestamp, 'yyyy-MM-dd'),
    "T",
    format_datetime(Timestamp, 'HH:mm:ss.fffffff'),
    "Z"
)
| order by Timestamp asc

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where AccountName == "BUBBA"
| where IsProcessRemoteSession == true
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, ProcessRemoteSessionIP
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where AccountName == "BUBBA"
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where RemoteIP == "192.168.0.110"
| project Timestamp, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, InitiatingProcessAccountName
| order by Timestamp asc

DeviceLogonEvents
| where DeviceName == "anthony-001"
| where RemoteIP == "192.168.0.110"
| project Timestamp, AccountName, RemoteIP, LogonType, DeviceName
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "anthony-001"
| where RemotePort == 3389
| order by Timestamp asc

DeviceRegistryEvents
| where DeviceName == "anthony-001"

AlertInfo

DeviceImageLoadEvents



