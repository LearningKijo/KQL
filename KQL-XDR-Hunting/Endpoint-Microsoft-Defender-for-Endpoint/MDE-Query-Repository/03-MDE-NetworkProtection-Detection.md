# MDE : Network Protection Detection List
This query displays MDE  Network Protection detections for each device over the past 7 days.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table?view=o365-worldwide) : 	Network connection and related events

```Kusto
let NetworkLogs = (DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (80, 443)
| extend IPaddress = RemoteIP
| extend Port = RemotePort
| extend URL = RemoteUrl
| project Timestamp, DeviceId, DeviceName, IPaddress, Port, URL);
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend Parsed = parse_json(AdditionalFields)
| extend NetworkProtectionCategory = Parsed.ResponseCategory
| where NetworkProtectionCategory in ("CmdCtrl", "Malicious")
| join kind=inner NetworkLogs on $left.RemoteUrl == $right.URL
| extend DetectionTime = strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'))
| extend DetectionType = strcat("<", NetworkProtectionCategory, " /", InitiatingProcessFileName, ">")
| extend DetectionURL = strcat("[", RemoteUrl, " : ", IPaddress, " : ", Port, "]")
| extend Details = strcat(DetectionTime, " ", DetectionType, " ", DetectionURL)
| summarize NP_DetectionList = make_list(Details) by DeviceId, DeviceName
| extend Case = array_length(NP_DetectionList)
| project DeviceId, DeviceName, Case, NP_DetectionList
| order by Case desc
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/cd73db0f-9572-4704-ab18-2aba134689a4)

![image](https://github.com/LearningKijo/KQL/assets/120234772/88fbdde9-c579-401e-87d8-5fe3b551a669)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
