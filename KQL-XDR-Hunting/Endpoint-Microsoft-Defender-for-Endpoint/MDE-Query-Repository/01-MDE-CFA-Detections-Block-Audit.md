# Controlled Folder Access :  Detections List - Block & Audit
This query displays Controlled Folder Access Block and Audit detections for each device over the past 7 days, including detection type (Block/Audit), time, and targeted folder path.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("ControlledFolderAccessViolationBlocked", "ControlledFolderAccessViolationAudit")
| extend Detection = iff(ActionType == "ControlledFolderAccessViolationBlocked", "Block", "Audit")
| extend Time = format_datetime(Timestamp,'yyyy-M-dd H:mm:ss')
| extend Type = strcat("<", "CFA", " : ", Detection, ">")
| extend Path = strcat("<", "TargetedFolderPath", " : ", FolderPath, ">")
| extend List = strcat(Time, " : ", Type, " ", Path)
| summarize CFA_List = make_list(List) by DeviceId, DeviceName
| extend Case = array_length(CFA_List)
| project DeviceId, DeviceName, Case, CFA_List
| order by Case desc 
```

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
