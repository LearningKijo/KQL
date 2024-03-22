# Lateral Movement Paths (LMP)
Lateral movement path is defined as the steps an attacker takes to navigate your network and gain additional access to secure data. 
Lateral Movement Paths (LMPs) reporting is available for every identity tracked by Microsoft Defender for Identity and serves as a visual guide that can demonstrate routes from non-sensitive to sensitive accounts.

Microsoft Incident Response leans on these LMPs frequently via both Advanced Hunting and the visual guides to understand the potential scope of access for a compromised identity.

![DenizSezer_0-1710838441569](https://github.com/LearningKijo/KQL/assets/120234772/c277340c-e035-444c-b0d8-3feaf75c9976)

During an investigation, the following query can identify service accounts granted a high level of privileges, as well as the machines those accounts regularly logged into. 
This can help investigators rapidly identify and remediate Lateral Movement risks.

#### Table name & Description
- [IdentityDirectoryEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide) : Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller

```kusto
IdentityDirectoryEvents 
| where ActionType == "Potential lateral movement path identified"
| project Timestamp, ActionType, Application, AccountName, AccountDomain, AccountSid, AccountDisplayName, DeviceName, AdditionalFields
```

Microsoft Defender for Identity continuously monitors your environment and alerts you to sensitive accounts with the riskiest lateral movement paths. 
This assists Microsoft Incident Response during engagements by providing insights into the customer’s attack surface. 
In scenarios where we engage after an incident, it’s more efficient to retrieve this information via query.

#### Reference
[Follow the Breadcrumbs with Microsoft Incident Response and MDI: Working Together to Fight Identity](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/follow-the-breadcrumbs-with-microsoft-incident-response-and-mdi/ba-p/4089623)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
