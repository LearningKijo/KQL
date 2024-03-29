# MDE : URL IoCs Block on Edge & 3rd Party Browsers
This query displays MDE URL Indicators detections by both Edge and 3rd party browsers for each device over the past 7 days.

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
| where SmartScreen == "CustomBlockList" or NetworkProtection == "CustomBlockList"
| extend Browser = iff( ActionType == "SmartScreenUrlWarning" and SmartScreen == "CustomBlockList", "Edge", "3rd Party")
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
> [!Important]
> In DeviceNetworkEvents, URLs may appear as ***'ConnectionSuccess'***, but this is the expected result due to the three-way handshake that occurs before an IoC, such as blocking a URL.
> Technically, end users were blocked from accessing the URL, even if the record shows ***'ConnectionSuccess'***.
> MS docs : [IP/URL Indicators: Network protection and the TCP three-way handshake](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-indicators?view=o365-worldwide#ipurl-indicators-network-protection-and-the-tcp-three-way-handshake)

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/a39b9f95-05c8-4597-a37f-9a49dc46b0bf)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
