# Suspicious application creation
Microsoft Security Blog title - Threat actors misuse OAuth applications to automate financially driven attacks

#### Suspicious application creation
This query finds new applications added in your tenant.
```kusto
CloudAppEvents
| where ActionType in ("Add application.", "Add service principal.")
| mvexpand modifiedProperties = RawEventData.ModifiedProperties
| where modifiedProperties.Name == "AppAddress"
| extend AppAddress = tolower(extract('\"Address\": \"(.*)\",',1,tostring(modifiedProperties.NewValue)))
| mvexpand ExtendedProperties = RawEventData.ExtendedProperties
| where ExtendedProperties.Name == "additionalDetails"
| extend OAuthApplicationId = tolower(extract('\"AppId\":\"(.*)\"',1,tostring(ExtendedProperties.Value)))
| project Timestamp, ReportId, AccountObjectId, Application, ApplicationId, OAuthApplicationId, AppAddress
```

#### Reference
- December 12, 2023, [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
