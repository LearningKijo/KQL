# Mango Sandstorm

```kql
let MangoSandstorm042023 = externaldata(Indicator:string, Type:string, Description:string)
[@'https://raw.githubusercontent.com/LearningKijo/KQL/main/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/MangoSandstorm-Storm-1084-IOCs-042023.csv'] with (format='csv', ignorefirstrecord = true);
let Domains042023 = (MangoSandstorm042023 | where Type == "Domain"| project Indicator);
let IP042023 = (MangoSandstorm042023 | where Type == "IP address"| project Indicator);
DeviceNetworkEvents
| where Timestamp > ago(1d) 
| where RemoteUrl has_any (Domains042023) or RemoteIP in (IP042023) 
| project-reorder Timestamp, DeviceId, DeviceName, RemoteUrl, RemoteIP, ActionType![image](https://user-images.githubusercontent.com/120234772/235415259-0c3d910a-ea82-427f-beac-0fe4c369d2ae.png)
```
