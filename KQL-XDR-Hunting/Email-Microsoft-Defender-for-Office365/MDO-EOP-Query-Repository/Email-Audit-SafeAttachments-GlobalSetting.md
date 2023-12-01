#  Email Audit SafeAttachments GlobalSetting
This query shows the configuration auditing - [Safe Attachments for SharePoint, OneDrive, and Microsoft Teams](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure?view=o365-worldwide) in Microsoft Defender for Office 365.

#### Table name & Description
- [CloudAppEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table?view=o365-worldwide) : Events involving accounts and objects in Office 365 and other cloud apps and services

```kusto
   let StartTime = datetime(2023-01-22);
   let EndTime = datetime(2023-01-24);
   CloudAppEvents
   | where Timestamp between ((StartTime) .. (EndTime))
   | where Application == "Microsoft Exchange Online"
   | where ActionType contains "atp"
```

```
Output : 
 Parameters 
  [
    {"Name":"Identity","Value":"Default"},
    {"Name":"EnableATPForSPOTeamsODB","Value":"True"},
    {"Name":"EnableSafeDocs","Value":"True"},
    {"Name":"AllowSafeDocsOpen","Value":"False"}
  ]
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
