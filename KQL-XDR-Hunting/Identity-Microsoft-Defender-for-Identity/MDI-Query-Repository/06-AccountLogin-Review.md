# Account Login Review
When investigating a potential compromise, it can often be helpful to understand which devices or locations a user typically logged into, and which type of logon was used. 
Typically, the most interesting types of logon for an investigation are Interactive, Remote Interactive and Network. 
This information is useful in both proactive and reactive contexts since it can give an indication of the pattern of life of a user and helps identify anomalies.

#### Table name & Description
- [IdentityLogonEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitylogonevents-table?view=o365-worldwide) : Authentication events on Active Directory and Microsoft online services
```kusto
IdentityLogonEvents
| where AccountName contains "adfsadmin"
| where Application == "Active Directory"
| summarize TotalCount=count(),FirstSeen=min(Timestamp),LastSeen=max(Timestamp),SuccessCount=countif(ActionType=="LogonSuccess"),ListOfSuccessfulDevices=make_set_if(DeviceName,ActionType=="LogonSuccess"),FailureCount=countif(ActionType=="LogonFailed"),ListofFailedDevices=make_set_if(DeviceName,ActionType=="LogonFailure") by AccountName,DeviceName,LogonType
```

#### Reference
[Follow the Breadcrumbs with Microsoft Incident Response and MDI: Working Together to Fight Identity](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/follow-the-breadcrumbs-with-microsoft-incident-response-and-mdi/ba-p/4089623) 

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
