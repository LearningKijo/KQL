# Account Discovery - Net Command Usage

This query tracks net command activities, specifically focusing on gathering domain account and local account information.
```kusto
DeviceProcessEvents
| where FileName == "net.exe"
| where ProcessCommandLine has_any ("/domain", "user", "group")
```

This query tracks net command activities, specifically focusing on gathering domain account and local account information. 
It lists all activities for each device in the past 7 days.
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "net.exe"
| where ProcessCommandLine has_any ("/domain", "user", "group")
| summarize CmdList = make_set(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ProcessCommandLine)) by DeviceId, DeviceName
| extend Case = array_length(CmdList)
| project DeviceId, DeviceName, Case, CmdList
| order by Case desc 
```

![image](https://github.com/LearningKijo/KQL/assets/120234772/f3c22355-c052-4cd8-8bd3-8385558e440d)

#### Reference
- [Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
