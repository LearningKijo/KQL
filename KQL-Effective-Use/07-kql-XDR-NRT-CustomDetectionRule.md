# KQL : XDR Custom Detection Rule with NRT
WIP


```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "audited"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```
