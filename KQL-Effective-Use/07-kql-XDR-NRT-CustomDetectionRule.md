# KQL : XDR Custom Detection Rule with NRT
WIP


```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "audited"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```
```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "blocked"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```

![image](https://user-images.githubusercontent.com/120234772/228133466-69fb1e17-c5f2-4130-ba27-3562ce119c40.png)

![image](https://user-images.githubusercontent.com/120234772/228149676-e2ac0076-f004-46af-8d6b-7845f6d46830.png)
