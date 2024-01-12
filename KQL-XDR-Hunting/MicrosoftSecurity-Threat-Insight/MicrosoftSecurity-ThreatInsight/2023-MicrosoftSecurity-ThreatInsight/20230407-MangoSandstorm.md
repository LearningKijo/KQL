# MERCURY and DEV-1084: Destructive attack on hybrid environments
Microsoft Threat Intelligence has detected destructive operations enabled by MERCURY, a nation-state actor linked to the Iranian government, that attacked both on-premises and cloud environments. 
While the threat actors attempted to masquerade the activity as a standard ransomware campaign, the unrecoverable actions show destruction and disruption were the ultimate goals of the operation.

Previous MERCURY attacks have been observed targeting on-premises environments, however, the impact in this case notably also included destruction of cloud resources. 
Microsoft assesses that MERCURY likely worked in partnership with another actor that Microsoft tracks as DEV-1084, who carried out the destructive actions after MERCURY’s successful operations had gained access to the target environment.

MERCURY likely exploited known vulnerabilities in unpatched applications for initial access before handing off access to DEV-1084 to perform extensive reconnaissance and discovery, establish persistence, and move laterally throughout the network, oftentimes waiting weeks and sometimes months before progressing to the next stage. 
DEV-1084 was then later observed leveraging highly privileged compromised credentials to perform en masse destruction of resources, including server farms, virtual machines, storage accounts, and virtual networks, and send emails to internal and external recipients.

> [!Important]
> April 2023 update – Microsoft Threat Intelligence has shifted to a new threat actor naming taxonomy aligned around the theme of weather. MERCURY is now tracked as Mango Sandstorm and DEV-1084 is now tracked as Storm-1084.

## Advanced hunting queries
Advanced Hunting Query to surface potential Mercury PowerShell script backdoor installation
```kusto
DeviceFileEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where FolderPath in~ (@"c:\programdata\db.ps1", @"c:\programdata\db.sqlite")
| summarize min(Timestamp), max(Timestamp) by DeviceId, SHA256, InitiatingProcessParentFileName
```
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_cs "-EP BYPASS -NoP -W h"
| summarize makeset(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId
```

Advanced Hunting Query to surface potential Mercury PowerShell script backdoor initiating commands
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine contains_cs @"c:\programdata\db.ps1"
| summarize makeset(ProcessCommandLine), min(Timestamp), max(Timestamp) by DeviceId
```

Advanced Hunting Query for Azure resource deletion activity
```kusto
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
```

AHQ used to detect attacker abusing OAuth application during the attack
```kusto
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

## Microsoft Security Blog
April 7, 2023, [MERCURY and DEV-1084: Destructive attack on hybrid environment](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
