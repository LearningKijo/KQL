# KQL : Network Protection - WIP

![image](https://github.com/LearningKijo/KQL/assets/120234772/d7a2c834-3b3e-4337-a694-f61e22889962)

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend Parsed = parse_json(AdditionalFields)
| where Parsed.ResponseCategory == "CmdCtrl"
| extend Category = Parsed.ResponseCategory
| project Timestamp, DeviceId, DeviceName, ActionType, Category, RemoteUrl
```
