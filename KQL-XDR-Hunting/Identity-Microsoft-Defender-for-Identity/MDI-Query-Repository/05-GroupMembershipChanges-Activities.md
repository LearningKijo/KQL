# Group Membership Changes
Privileged groups can grant permissions in Active Directory and other applications, and allow access to resources such as SCCM administration, Domain Admins, and more. 
As a result, Threat Actors often add themselves to privileged groups to gain access to a resource that is useful to them.

The query below can be used to review group changes and track which accounts were added to which groups.

#### Table name & Description
- [IdentityDirectoryEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide) : Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller

```kusto
IdentityDirectoryEvents
| where Application == "Active Directory"
| where ActionType == "Group Membership changed"
| where DestinationDeviceName != "" 
| extend ToGroup = tostring(parse_json(AdditionalFields).["TO.GROUP"]) 
| extend FromGroup = tostring(parse_json(AdditionalFields).["FROM.GROUP"])
| extend Action = iff(isempty(ToGroup), "Remove", "Add")
| extend GroupModified = iff(isempty(ToGroup), FromGroup, ToGroup) 
| extend Target_Group = tostring(parse_json(AdditionalFields)["TARGET_OBJECT.GROUP"])
| project Timestamp, Action, GroupModified,  Target_Account = TargetAccountDisplayName, Target_UPN = TargetAccountUpn, Target_Group,  DC=DestinationDeviceName, Actor=AccountName, ActorDomain=AccountDomain, AdditionalFields
```

#### Reference
[Follow the Breadcrumbs with Microsoft Incident Response and MDI: Working Together to Fight Identity](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/follow-the-breadcrumbs-with-microsoft-incident-response-and-mdi/ba-p/4089623)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
