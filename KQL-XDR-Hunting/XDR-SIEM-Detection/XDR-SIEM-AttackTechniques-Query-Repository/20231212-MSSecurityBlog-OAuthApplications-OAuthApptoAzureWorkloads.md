# OAuth application interacting with Azure workloads
Microsoft Security Blog title - Threat actors misuse OAuth applications to automate financially driven attacks

#### OAuth application interacting with Azure workloads
```kusto
let OAuthAppId = <OAuth app ID in question>;
CloudAppEvents
| where Timestamp >ago (7d)  
| where AccountId == OAuthAppId 
| where AccountType== "Application"
| extend Azure_Workloads = RawEventData["operationName"]
| distinct Azure_Workloads by AccountId
```

#### Reference
- December 12, 2023, [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
