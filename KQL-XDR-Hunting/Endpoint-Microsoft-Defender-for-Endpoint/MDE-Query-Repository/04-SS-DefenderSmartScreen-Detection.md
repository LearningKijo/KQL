# Microsoft Defender SmartScreen : Detection List
This query displays Microsoft Defender SmartScreen detections for each device over the past 7 days.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table?view=o365-worldwide) : 	Network connection and related events

```kusto
let NetworkLogs = (DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (80, 443)
| extend IPaddress = RemoteIP
| extend Port = RemotePort
| extend URL = RemoteUrl
| project Timestamp, DeviceId, DeviceName, IPaddress, Port, URL);
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUrlWarning"
| extend Parsed = parse_json(AdditionalFields)
| extend SmartScreenCategory = Parsed.Experience
| where SmartScreenCategory in ("Exploit", "Malicious", "Phishing", "Untrusted")
| join kind=leftouter NetworkLogs on $left.RemoteUrl == $right.URL
| extend DetectionTime = strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'))
| extend DetectionType = strcat("<", SmartScreenCategory, " /", InitiatingProcessFileName, ">")
| extend DetectionURL = strcat("[", RemoteUrl, " : ", IPaddress, " : ", Port, "]")
| extend Details = strcat(DetectionTime, " ", DetectionType, " ", DetectionURL)
| summarize SS_DetectionList = make_list(Details) by DeviceId, DeviceName
| extend Case = array_length(SS_DetectionList)
| project DeviceId, DeviceName, Case, SS_DetectionList
| order by Case desc  
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/33ad8f17-925a-4a2e-99b4-51d8c0c52430)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
