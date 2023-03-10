# 03-kql-WebProtection.md

## KQL Hunting queries

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
