# MDE : LNK file activity
This query monitors LNK file activity that includes executable content or HTTP/HTTPS file downloading activity.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where ActionType == "ShellLinkCreateFileEvent"
| extend Parsed = parse_json(AdditionalFields)
| extend CommandLine = Parsed.ShellLinkCommandLine
| where isnotempty(CommandLine)
| where CommandLine has_any ("bat", "exe", "ps1") and CommandLine has_any ("/c", "powershell", ":%username%", "$env") or CommandLine has_any ("http", "https","iwr")
| project TimeGenerated, DeviceId, DeviceName, ActionType, FileName, FolderPath, CommandLine
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
