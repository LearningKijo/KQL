# DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit
> [!Important]
> April 2023 update – Microsoft Threat Intelligence has shifted to a new threat actor naming taxonomy aligned around the theme of weather. DEV-1101 is now tracked as Storm-1101.

> [!Note]
> ***AiTM - "adversary-in-the-middle"*** - In AiTM phishing, attackers deploy a proxy server between a target user and the website the user wishes to visit (that is, the site the attacker wishes to impersonate). 
> Such a setup allows the attacker to steal and intercept the target’s password and the session cookie that proves their ongoing and authenticated session with the website. 
> Note that this is not a vulnerability in MFA; since AiTM phishing steals the session cookie, the attacker gets authenticated to a session on the user’s behalf, regardless of the sign-in method the latter uses.

#### Microsoft Sentinel Analytics template - [Possible AiTM Phishing Attempt Against Azure AD](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/SecurityThreatEssentialSolution/Analytic%20Rules/PossibleAiTMPhishingAttemptAgainstAAD.yaml)
This detection uses signals from Azure AD Identity Protection, specifically it looks for successful sign ins that have been flagged as high risk, and then combines this with data from Web Proxy services such as ZScaler to identify where users might have connected to the source of those sign ins immediately prior. 
This can indicate a user interacting with a AiTM phishing site and having their session hijacked. This detection uses the Advanced Security Information Model (ASIM) Web Session schema. 
More details on the schema and its requirements can be found in the documentation: https://learn.microsoft.com/azure/sentinel/normalization-schema-web
```kusto
let time_threshold = 10m;
let RiskySignins = materialize (SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where RiskLevelDuringSignIn =~ "high" or RiskLevelAggregated =~ "high"
| extend SignInTime = TimeGenerated, Name=split(UserPrincipalName, "@")[0], UPNSuffix=split(UserPrincipalName, "@")[1]);
let ips = todynamic(toscalar(RiskySignins | summarize make_list(IPAddress)));
RiskySignins
| join kind=inner (_Im_WebSession(starttime=ago(1d), ipaddr_has_any_prefix=ips, eventresult="Success", pack=True)) on $left.IPAddress == $right.DstIpAddr
| where EventStartTime < TimeGenerated
| extend TimeDelta = TimeGenerated - EventStartTime
| where TimeDelta <= time_threshold
| extend NetworkEventStartTime = EventStartTime, NetworkEventEndTime = EventEndTime
| extend SrcUsername = column_ifexists("SrcUsername", "Unknown")
| project-reorder SignInTime, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed, DeviceDetail, LocationDetails, NetworkLocationDetails, RiskEventTypes, UserAgent, NetworkEventStartTime, NetworkEventEndTime, SrcIpAddr, DstIpAddr, DstPortNumber, Dvc, DvcHostname, SrcBytes, NetworkProtocol, SrcUsername
```

#### Reference
- March 13, 2023, [DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
