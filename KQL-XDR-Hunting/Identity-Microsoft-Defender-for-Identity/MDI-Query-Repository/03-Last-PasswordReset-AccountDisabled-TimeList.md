# Last Password Reset & Account Disabled Time List
This query helps list the last password reset and account disabled time in your environment.

#### Table name & Description
- [IdentityDirectoryEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide) : Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller
- [IdentityInfo](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityinfo-table?view=o365-worldwide) : Account information from various sources, including Microsoft Entra ID

```kusto
let PasswordChanged = IdentityDirectoryEvents 
| where ActionType == "Account Password changed"
| extend PasswordChangedTime = Timestamp
| summarize arg_max(PasswordChangedTime, *) by TargetAccountUpn
| project PasswordChangedTime, TargetAccountUpn, ActionType, Application;
let AccountDisabled = IdentityDirectoryEvents 
| where ActionType == "Account Disabled changed"
| extend AccountDisabledTime = Timestamp
| summarize arg_max(AccountDisabledTime, *) by TargetAccountUpn
| project AccountDisabledTime, TargetAccountUpn, ActionType, Application;
IdentityInfo 
| where SourceProvider in ("Hybrid", "ActiveDirectory")
| summarize arg_max(Timestamp, *) by AccountUpn
| join kind = leftouter PasswordChanged on $left.AccountUpn == $right.TargetAccountUpn 
| join kind = leftouter AccountDisabled on $left.AccountUpn == $right.TargetAccountUpn 
| project AccountUpn, AccountDisplayName, SourceProvider, AccountDisabledTime, PasswordChangedTime
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/5521bc01-514b-4ea7-8bdb-5fa25eb1cb0e)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
