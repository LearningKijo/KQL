# KQL : Web Protection
Microsoft Defender for Endpoint's web protection comprises of several features, including web threat protection, web content filtering, and custom indicators.
Therefore, in this section, I am going to share hunting queries related to web protection.

The KQL hunting queries will include the following products :
1. Microsoft Defender for Endpoint - Url Indicators
2. Microsoft Defender for Endpoint - Network Protection
3. Microsoft Defender for Endpoint - Web Content Filtering
4. Microsoft Defender for Cloud Apps - Unsanctioned app
5. Microsoft Defender SmartScreen


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
| summarize MDE_IoC = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomPolicy"),
MDA_CASB = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CasbPolicy"),
Edge_SS = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) in ("Malicious", "Phishing")) by DeviceId, DeviceName
| extend MDE_IoC_case = array_length(MDE_IoC)
| extend MDE_WCF_case = array_length(MDE_WCF)
| extend MDA_CASB_case = array_length(MDA_CASB)
| extend Edge_SS_case = array_length(Edge_SS)
| project DeviceId, DeviceName, MDE_IoC_case, MDA_CASB_case, MDE_WCF_case, Edge_SS_case, MDE_IoC, MDE_WCF,  MDA_CASB, Edge_SS
```

**3rd party browser** - Windows Defender Exploit Guard, Netwrk Protection
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomPolicy"),
MDE_NP = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CmdCtrl"),
MDA_CASB = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CasbPolicy") by DeviceId, DeviceName
| extend MDE_IoC_case = array_length(MDE_IoC)
| extend MDE_WCF_case = array_length(MDE_WCF)
| extend MDE_NP_case = array_length(MDE_NP)
| extend MDA_CASB_case = array_length(MDA_CASB)
| project DeviceId, DeviceName, MDE_IoC_case, MDE_NP_case, MDE_WCF_case, MDA_CASB_case,  MDE_IoC, MDE_NP, MDE_WCF,  MDA_CASB
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
e.g. 3rd party browser - Windows Defender Exploit Guard, Netwrk Protection

![image](https://github.com/LearningKijo/KQL/assets/120234772/5de6b732-3204-46a9-a7b2-58b4e07f6eb7)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
