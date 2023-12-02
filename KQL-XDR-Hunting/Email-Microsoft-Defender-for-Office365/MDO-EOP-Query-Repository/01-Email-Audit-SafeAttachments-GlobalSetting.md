#  Email Audit SafeAttachments GlobalSetting
This query shows the configuration auditing - [Safe Attachments for SharePoint, OneDrive, and Microsoft Teams](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure?view=o365-worldwide) in Microsoft Defender for Office 365.

#### Table name & Description
- [CloudAppEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table?view=o365-worldwide) : Events involving accounts and objects in Office 365 and other cloud apps and services

#### Query
```kusto
CloudAppEvents
| where Application == "Microsoft Exchange Online"
| where ActionType == "Set-AtpPolicyForO365"
| mv-expand ActivityObjects
| extend Name = tostring(ActivityObjects.Name)
| extend Value = tostring(ActivityObjects.Value)
| where Name in ("EnableATPForSPOTeamsODB", "EnableSafeDocs", "AllowSafeDocsOpen")
| extend packed = pack(Name, Value)
| summarize PackedInfo = make_bag(packed), ActionType = any(ActionType) by Timestamp, AccountDisplayName
| evaluate bag_unpack(PackedInfo)
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/220a08ac-6688-4d91-8e24-217940b38b9b)


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
