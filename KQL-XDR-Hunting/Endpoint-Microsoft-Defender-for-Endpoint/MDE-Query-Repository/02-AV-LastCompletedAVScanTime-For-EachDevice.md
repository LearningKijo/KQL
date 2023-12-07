# AV : Last Completed Scan Time for Each Device in the Past 7 Days
This query displays the last completed scan time of Microsoft Defender Antivirus for each device in the past 7 days

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusScanCompleted"
| extend Parsed = parse_json(AdditionalFields)
| extend ScanType = Parsed.ScanTypeIndex
| summarize arg_max(Timestamp, *) by DeviceId, DeviceName
| project DeviceId, DeviceName, ActionType, ScanType, Timestamp, InitiatingProcessVersionInfoProductVersion
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.