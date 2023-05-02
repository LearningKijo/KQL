# Mango Sandstorm

## Reference
1. August 25, 2022, [MERCURY leveraging Log4j 2 vulnerabilities in unpatched systems to target Israeli organizations](https://www.microsoft.com/en-us/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/)
2. April 7, 2023, [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

## IoCs
KQL/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/[MangoSandstorm-Storm-1084-IOCs-042023.csv](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/MangoSandstorm-Storm-1084-IOCs-042023.csv)

## KQL Threat Hunting
```kql
// IoCs - MERCURY and DEV-1084: Destructive attack on hybrid environment
let MangoSandstorm = externaldata(Indicator:string, Type:string, Description:string)
[@'https://raw.githubusercontent.com/LearningKijo/KQL/main/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/MangoSandstorm-Storm-1084-IOCs-042023.csv'] with (format='csv', ignorefirstrecord = true);
let Domains = (MangoSandstorm | where Type == "Domain"| project Indicator);
let IPaddress = (MangoSandstorm | where Type == "IP address"| project Indicator);
let SHA256hash = (MangoSandstorm | where Type == "SHA-256"| project Indicator);
(union isfuzzy=true
(DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any (Domains) or RemoteIP in (IPaddress) 
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
),
(DeviceFileEvents
| where Timestamp > ago(1d)
| where SHA256 in~(SHA256hash)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FileSize, FolderPath, SHA256
),
(DeviceProcessEvents
| where Timestamp > ago(1d)
| where SHA256 in~(SHA256hash)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FileSize, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessCommandLine
),
(DeviceImageLoadEvents
| where Timestamp > ago(1d)
| where SHA256 in~(SHA256hash)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FileSize, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
)
)
```

