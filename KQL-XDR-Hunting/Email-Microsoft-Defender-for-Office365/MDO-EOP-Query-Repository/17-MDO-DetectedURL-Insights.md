#  URL & Domain Insights from MDO Alerts Detection
This query displays URLs (domains) from Microsoft Defender for Office 365 detected alerts. You can also leverage this query as a function.

Thanks to the Unified Security Operations Platform, there are now no boundaries for threat hunting. 
You can use various tables across XDR and Sentinel. In the past, I’ve seen useful queries like ['Phishing Link Clicks in Network Traffic' from a blog](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358). 
However, due to the integration, SecurityAlert table no longer exists in Advanced Hunting. Even though we switched to using the AlertInfo and AlertEvidence tables, they use different columns and data types. 
To leverage the great query, I rewrote it to fit this advanced hunting environment.

#### Table name & Description
- [AlertInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table?view=o365-worldwide) : Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity, including severity information and threat categorization
- [AlertEvidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table) : Files, IP addresses, URLs, users, or devices associated with alerts

```kusto
let Alert_List= dynamic([
    "Phishing link click observed in Network Traffic",
    "Phish delivered due to an IP allow policy",
    "A potentially malicious URL click was detected",
    "High Risk Sign-in Observed in Network Traffic",
    "A user clicked through to a potentially malicious URL",
    "Suspicious network connection to AitM phishing site",
    "Messages containing malicious entity not removed after delivery",
    "Email messages containing malicious URL removed after delivery",
    "Email reported by user as malware or phish",
    "Phish delivered due to an ETR override",
    "Phish not zapped because ZAP is disabled"]);
AlertInfo
| where DetectionSource == "Microsoft Defender for Office 365"
| where Title has_any (Alert_List)
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
| summarize UPN = make_set(EntityUPN), URL = make_set(EntityUrl) by AlertId, TimeGenerated 
| mv-expand URL
| mv-expand UPN
| where isnotempty(URL)
| where isnotempty(UPN)
| extend URLtoString = tostring(URL)
| extend Domain = parse_url(URLtoString).Host
| project TimeGenerated, AlertId, UPN, URL, Domain
```

If you create the above query as a function, you can simplify it further and combine it with other tables, such as Sentinel-related network data.

```kusto
<Function-Demo>
| where TimeGenerated > ago(15d)
| join kind= inner (CommonSecurityLog
| where TimeGenerated > ago(15d)
| where DeviceAction != "Block"
| where DeviceProduct startswith "FortiGate" or DeviceProduct startswith  "PAN" or DeviceProduct startswith  "VPN" or DeviceProduct startswith "FireWall" or DeviceProduct startswith  "NSSWeblog" or DeviceProduct startswith "URL"
| where isnotempty(RequestURL)
| where isnotempty(SourceUserName)
| project 3plogTime=TimeGenerated, DeviceVendor, DeviceProduct,
          Activity, DestinationHostName, DestinationIP, RequestURL=tostring(tolower(RequestURL)),
          MaliciousIP, Name = tostring(split(SourceUserName,"@")[0]), UPNSuffix =tostring(split(SourceUserName,"@")[1]),
          SourceUserName, IndicatorThreatType, ThreatSeverity,AdditionalExtensions, ThreatConfidence
    ) on $left.URL == $right.RequestURL
```

#### Reference 
[Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
