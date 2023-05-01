# Mango Sandstorm

## Reference
1. August 25, 2022, [MERCURY leveraging Log4j 2 vulnerabilities in unpatched systems to target Israeli organizations](https://www.microsoft.com/en-us/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/)
2. April 7, 2023, [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

## KQL Threat Hunting
```kql
let MangoSandstorm042023 = externaldata(Indicator:string, Type:string, Description:string)
[@'https://raw.githubusercontent.com/LearningKijo/KQL/main/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/MangoSandstorm-Storm-1084-IOCs-042023.csv'] with (format='csv', ignorefirstrecord = true);
let Domains042023 = (MangoSandstorm042023 | where Type == "Domain"| project Indicator);
let IP042023 = (MangoSandstorm042023 | where Type == "IP address"| project Indicator);
DeviceNetworkEvents
| where Timestamp > ago(1d) 
| where RemoteUrl has_any (Domains042023) or RemoteIP in (IP042023) 
| project-reorder Timestamp, DeviceId, DeviceName, RemoteUrl, RemoteIP, ActionType
```
