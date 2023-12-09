# MDE : WCF detection on Edge & 3rd Party Browsers
This query displays MDE Web Content Filtering detections by both Edge and 3rd party browsers for each device over the past 7 days.

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
| where ActionType in ("SmartScreenUrlWarning", "ExploitGuardNetworkProtectionBlocked")
| extend Parsed = parse_json(AdditionalFields)
| extend SmartScreen = Parsed.Experience
| extend NetworkProtection = Parsed.ResponseCategory
| where SmartScreen == "CustomPolicy" or NetworkProtection == "CustomPolicy"
| extend Browser = iff(ActionType == "SmartScreenUrlWarning" and SmartScreen == "CustomPolicy", "Edge", "3rd Party")
| join kind=inner NetworkLogs on $left.RemoteUrl == $right.URL
| extend DetectionTime = strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'))
| extend BrowserType = strcat("<", Browser, " /", InitiatingProcessFileName, ">")
| extend DetectionURL = strcat("[", RemoteUrl, " : ", IPaddress, " : ", Port, "]")
| extend Details = strcat(DetectionTime, " ", BrowserType, " ", DetectionURL)
| summarize IoCList = make_list(Details) by DeviceId, DeviceName
| extend Case = array_length(IoCList)
| project DeviceId, DeviceName, Case, IoCList
| order by Case desc 
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/355ad2d3-80d8-4cc7-9830-31b8eccb18aa)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.

