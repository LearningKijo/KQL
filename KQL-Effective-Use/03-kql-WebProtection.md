# 03-kql-WebProtection.md

## Web Protection architecture
![image](https://user-images.githubusercontent.com/120234772/224228868-2dc0c0f9-1841-423b-a64b-f6d655192c92.png)
> https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/web-protection-overview?view=o365-worldwide

## KQL Hunting queries
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
