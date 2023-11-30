## Last Password Reset & Account Disabled Time List
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
