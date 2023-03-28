# KQL : XDR Custom Detection Rule with NRT
WIP


```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "audited"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```
![image](https://user-images.githubusercontent.com/120234772/228131787-0e851e2f-0643-495a-801f-596daa7076d1.png)
