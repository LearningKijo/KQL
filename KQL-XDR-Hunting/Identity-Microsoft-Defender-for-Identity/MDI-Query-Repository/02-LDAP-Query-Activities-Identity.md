# LDAP query activities captured by MDI table
This query helps filter daily LDAP query activities captured by Microsoft Defender for Identity sensor based on [bin()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/binfunction) operator.

#### Table name & Description
- [IdentityQueryEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityqueryevents-table?view=o365-worldwide) : Queries for Active Directory objects, such as users, groups, devices, and domains

```kusto
IdentityQueryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAP query"
| extend DeviceQuery = strcat(DeviceName, " : ",  QueryType, " : ", Query)
| summarize QueryList = make_list(DeviceQuery) by bin(Timestamp, 1d)
| extend Case = array_length(QueryList)
| project Timestamp, Case, QueryList
```
#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/36aeb06d-faa7-41aa-b802-d0c7628ba94e)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
