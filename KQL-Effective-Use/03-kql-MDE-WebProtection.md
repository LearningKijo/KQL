# KQL : Web Protection
Microsoft Defender for Endpoint's web protection comprises of several features, including web threat protection, web content filtering, and custom indicators.
Therefore, in this section, I am going to share hunting queries related to web protection.

The KQL hunting queries will include the following products :
1. Microsoft Defender for Endpoint - Url Indicators
2. Microsoft Defender for Endpoint - Web Content Filtering
3. Microsoft Defender for Cloud Apps - Unsanctioned app
4. Microsoft Defender SmartScreen


## Web Protection architecture
![image](https://user-images.githubusercontent.com/120234772/224228868-2dc0c0f9-1841-423b-a64b-f6d655192c92.png)
> [Web protection | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/web-protection-overview?view=o365-worldwide)


## KQL : Hunting queries
**Edge browser** - Microsoft SmartScreen
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = countif(Experience=tostring(ParsedFields.Experience) == "CustomBlockList"), 
MDE_WCF = countif(Experience=tostring(ParsedFields.Experience) == "CustomPolicy"), 
MDA_CASB = countif(Experience=tostring(ParsedFields.Experience) == "CasbPolicy"), 
Edge_SS = countif(Experience=tostring(ParsedFields.Experience) in ("Malicious", "Phishing")) by DeviceId, DeviceName
```

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomPolicy"),
MDA_CASB = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CasbPolicy"),
Edge_SS = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) in ("Malicious", "Phishing")) by DeviceId, DeviceName
```

**3rd party browser** - Windows Defender Exploit Guard, Netwrk Protection
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = countif(ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomBlockList"), 
MDE_WCF = countif(ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomPolicy"),
MDA_CASB = countif(ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CasbPolicy") by DeviceId, DeviceName
```

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomPolicy"),
MDA_CASB = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CasbPolicy") by DeviceId, DeviceName
```

**Bypass** - MDE Indicators Warn & MDA Monitored app
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("SmartScreenUserOverride", "NetworkProtectionUserBypassEvent")
| extend Browser = case(
        InitiatingProcessFileName has "msedge", "Edge",
        InitiatingProcessFileName has "chrome", "Chrome", 
        InitiatingProcessFileName has "firefox", "Firefox",
        InitiatingProcessFileName has "opera", "Opera",
"3rd party browser")
| project Timestamp, DeviceId, DeviceName, ActionType, Browser, RemoteUrl
```
## KQL : Hunting results
e.g. Edge browser - Microsoft SmartScreen

![image](https://user-images.githubusercontent.com/120234772/228752118-d90b881a-4267-48f6-b404-e8d9cd658a5d.png)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
