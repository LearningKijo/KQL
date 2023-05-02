# Mango Sandstorm : Threat Hunting with KQL



## KQL Threat Hunting
#### IOCs csv file : [MangoSandstorm-Storm-1084-IOCs-042023.csv](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/ThreatHunting/IOCs-Folder/MangoSandstorm-Storm-1084-IOCs-042023.csv)

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

## KQL Advanced hunting queries 
#### Source : April 7, 2023, [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

```kql
// Advanced Hunting Query to surface potential Mercury PowerShell script backdoor installation

DeviceFileEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where FolderPath in~ (@"c:\programdata\db.ps1", @"c:\programdata\db.sqlite")
| summarize min(Timestamp), max(Timestamp) by DeviceId, SHA256, InitiatingProcessParentFileName

DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_cs "-EP BYPASS -NoP -W h"
| summarize makeset(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId


// Advanced Hunting Query to surface potential Mercury PowerShell script backdoor initiating commands

DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine contains_cs @"c:\programdata\db.ps1"
| summarize makeset(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId


//Advanced Hunting Query for Azure resource deletion activity

let PrivEscalation = CloudAppEvents 
| where Application == "Microsoft Azure"
| where ActionType == "ElevateAccess Microsoft.Authorization"
| where ActivityObjects has "Azure Subscription" and ActivityObjects has "Azure Resource Group"
| extend PrivEscalationTime = Timestamp
| project AccountObjectId, PrivEscalationTime ,ActionType;
CloudAppEvents
| join kind = inner PrivEscalation on AccountObjectId
| extend DeletionTime = Timestamp
| where (DeletionTime - PrivEscalationTime) <= 1h
| where Application == "Microsoft Azure"
| where ActionType has "Delete"
|summarize min(DeletionTime), TotalResourcersDeleted =count(), CountOfDistinctResources= dcount(ActionType), DistinctResources=make_set(ActionType) by AccountObjectId


//AHQ used to detect attacker abusing OAuth application during the attack

CloudAppEvents
    | where Application == "Office 365"
    | where ActionType == "Consent to application."
    | where RawEventData.ResultStatus =~ "success"
    | extend UserId = tostring(RawEventData.UserId)
    | mv-expand AdminConsent = RawEventData.ModifiedProperties 
    | where AdminConsent.Name == "ConsentContext.IsAdminConsent" and AdminConsent.NewValue == "True"
    | project ConsentTimestamp =Timestamp, UserId, AccountObjectId, ReportId, ActionType
    | join kind = leftouter (CloudAppEvents  
        | where Application == "Office 365"      
        | where ActionType == "Add app role assignment to service principal."   
        | extend PermissionAddedTo = tostring(RawEventData.Target[3].ID)
        | extend FullAccessPermission = RawEventData.ModifiedProperties 
        | extend OuthAppName = tostring(FullAccessPermission[6].NewValue) // Find app name
        | extend OAuthApplicationId = tostring(FullAccessPermission[7].NewValue) // Find appId
        | extend AppRoleValue = tostring(FullAccessPermission[1].NewValue) // Permission Level
        | where AppRoleValue == "full_access_as_app"
        | project PermissionTime=Timestamp, InitiatingUser=AccountDisplayName, OuthAppName, OAuthApplicationId, AppRoleValue, AccountObjectId, FullAccessPermission
    ) on AccountObjectId
```
## Reference
1. August 25, 2022, [MERCURY leveraging Log4j 2 vulnerabilities in unpatched systems to target Israeli organizations](https://www.microsoft.com/en-us/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/)
2. April 7, 2023, [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)
