# Service Creation Review
Services are often used by threat actors as persistence mechanisms, allowing them to leave a running executable which will allow a Threat Actor to maintain long-term access to a compromised system. 
The query below will display service creation events on machines protected by MDI, allowing for review to ensure that all newly created services are expected. 
These systems should only be used for domain management and any atypical service creation should be investigated. It is a simple query, but an effective one in many cases.

#### Table name & Description
- [IdentityDirectoryEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide) : Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller

```kusto
IdentityDirectoryEvents
| where ActionType == 'Service creation'
| project Timestamp, Application, AccountName, AdditionalFields.ServiceName
```

#### Reference
[Follow the Breadcrumbs with Microsoft Incident Response and MDI: Working Together to Fight Identity](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/follow-the-breadcrumbs-with-microsoft-incident-response-and-mdi/ba-p/4089623)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
