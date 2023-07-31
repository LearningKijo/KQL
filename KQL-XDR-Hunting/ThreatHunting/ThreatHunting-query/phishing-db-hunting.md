# Phishing DB hunting

```kql
// Phishing Domain Database
// https://github.com/mitchellkrogza/Phishing.Database/tree/master
let PhishingDB = materialize(externaldata(Phish_url:string)[@'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt'] with (format='txt'));
let URLs = materialize((PhishingDB | project Phish_url));
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where Url has_any (URLs) 
| join kind = inner EmailEvents on NetworkMessageId
| join kind = leftouter UrlClickEvents on NetworkMessageId
| where LatestDeliveryLocation != "Quarantine"
| project TimeGenerated, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, LatestDeliveryLocation, Url, ActionType, IsClickedThrough
```

```kql
// Phishtank
// https://data.phishtank.com/
let PhishingDB = materialize(externaldata(phish_id:string, url:string, phish_detail_url:string, submission_time:datetime, verified:string, verification_time:datetime, online:string, target:string)[@'http://data.phishtank.com/data/online-valid.csv'] with (format='csv', ignorefirstrecord = true));
let URLs = materialize((PhishingDB | where verification_time > ago(8h) | project url));
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where Url has_any (URLs) 
| join kind = inner EmailEvents on NetworkMessageId
| join kind = leftouter UrlClickEvents on NetworkMessageId
| where LatestDeliveryLocation != "Quarantine"
| project TimeGenerated, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, LatestDeliveryLocation, Url, ActionType, IsClickedThrough
```
