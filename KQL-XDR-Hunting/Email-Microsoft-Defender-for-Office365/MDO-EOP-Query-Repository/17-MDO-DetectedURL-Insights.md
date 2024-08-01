#  URL & Domain Insights from MDO Alerts Detection
This query displays URLs (domains) from Microsoft Defender for Office 365 detected alerts. You can also leverage this query as a function.

#### Table name & Description
- [AlertInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table?view=o365-worldwide) : Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity, including severity information and threat categorization
- [AlertEvidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table) : Files, IP addresses, URLs, users, or devices associated with alerts

```kusto
AlertInfo
| where DetectionSource == "Microsoft Defender for Office 365"
| join kind=inner (
        AlertEvidence 
        | where DetectionSource == "Microsoft Defender for Office 365"
        | where EntityType in ("Url", "User")
) on AlertId
| extend Entities = parse_json(AdditionalFields)
| mv-apply Entity = Entities on (
        where Entity.Type in ('account', 'url')
        | extend EntityUPN = iff(Entities.Type == 'account', strcat(Entities.Name, "@", Entities.UPNSuffix), Entities.UserPrincipalName), "",
                 EntityUrl = iff(Entities.Type == 'url', tostring(Entities.Url), "")
) 
| extend DomainFromUrl = iff(isnotempty(EntityUrl), tostring(parse_url(EntityUrl).Host), "")
| summarize EntityUPN = strcat_array(make_set(EntityUPN), ""), Domain = strcat_array(make_set(DomainFromUrl), ""), URL = strcat_array(make_set(EntityUrl), "") by AlertId, TimeGenerated 
| where isnotempty(URL)
| project TimeGenerated, AlertId, EntityUPN, Domain, URL
```

#### Reference 
[Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
