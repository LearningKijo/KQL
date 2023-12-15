# Password spray attempts
Microsoft Security Blog title - Threat actors misuse OAuth applications to automate financially driven attacks

#### Password spray attempts
This query identifies failed sign-in attempts to Microsoft Exchange Online from multiple IP addresses and locations.
```kusto
IdentityLogonEvents
| where ActionType == "LogonFailed" and LogonType == "OAuth2:Token" and Application == "Microsoft Exchange Online"
| summarize count(), dcount(IPAddress), dcount(Location) by AccountObjectId, AccountDisplayName, bin(Timestamp, 1h)
```
> [!note]
> As 'dcount(CountryCode)' is not available in IdentityLogonEvents, it has been shifted to 'Location'.

#### Reference
- December 12, 2023, [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
