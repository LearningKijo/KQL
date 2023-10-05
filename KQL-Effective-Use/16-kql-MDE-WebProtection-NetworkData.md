# Web Protection detection with KQL
Thanks for checking out Web Protection threat hunting series. 
In this article, I'll be diving into gathering network insights by merging data from the MDE network table. 
If you missed our previous Web Protection threat hunting articles, you can catch up on them here.

- [x] [03-kql-MDE-WebProtection.md](https://github.com/LearningKijo/KQL/blob/main/KQL-Effective-Use/03-kql-MDE-WebProtection.md)
- [x] [08-kql-MDE-WebProtection-CheatSheet-v3.pdf](https://github.com/LearningKijo/KQL/blob/main/KQL-Effective-Use/08-kql-MDE-WebProtection-CheatSheet-v3.pdf)

## KQL : Hunting queries
This query helps you understand URLs accessed by end-users detected by MDE IoC URL and Web Content Filtering. 
It also reveals the type of browser launched by the end-user. 
Furthermore, by combining network data (DeviceNetworkEvents) with URLs, the query provides insights into IP addresses and ports.

```kql
let NetworkLogs = (DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort in (80, 443)
| extend IPaddress = RemoteIP
| extend Port = RemotePort
| extend URL = RemoteUrl);
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("SmartScreenUrlWarning", "ExploitGuardNetworkProtectionBlocked")
| extend Parsed = parse_json(AdditionalFields)
| extend SmartScreen = Parsed.Experience
| extend NetworkProtection = Parsed.ResponseCategory
| where SmartScreen in ("CustomBlockList", "CustomPolicy") or NetworkProtection in ("CustomBlockList", "CustomPolicy")
| extend DetectionType = case(
            ActionType == "SmartScreenUrlWarning" and SmartScreen == "CustomBlockList", "Edge / IoC URL",
            ActionType == "SmartScreenUrlWarning" and SmartScreen == "CustomPolicy", "Edge / Web Content Filtering",
            ActionType == "ExploitGuardNetworkProtectionBlocked" and NetworkProtection == "CustomBlockList", "3rd party / IoC URL",
            ActionType == "ExploitGuardNetworkProtectionBlocked" and NetworkProtection == "CustomPolicy", "3rd party / Web Content Filtering",
            "N/A"
)
| join kind=inner NetworkLogs on RemoteUrl
| project Timestamp, DeviceId, DeviceName, DetectionType, InitiatingProcessFileName, URL, IPaddress, Port
```

![image](https://github.com/LearningKijo/KQL/assets/120234772/436cf538-496f-4b35-b257-6303383bc7c6)
> Query result in Advanced Hunting, Microsoft 365 Defender 

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
