# Phishing DB hunting
These queries will help find out the inbound emails which include potential phishing links.
1. [Phishing Domain Database](https://github.com/mitchellkrogza/Phishing.Database/tree/master)
2. [PhishTank](https://phishtank.org/)

### Phishing Domain Database
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

### PhishTank
```kql
// PhishTank
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

## Appendix
Regarding PhishTank, there is a huge amount of data. Therefore, I filtered the phishing link data every 8 hours. This is a sample query that returns the total number of phishing links detected/reported every 8 hours.
```kql
// URLs case calculation for every 8 hours 
externaldata(phish_id:string, url:string, phish_detail_url:string, submission_time:datetime, verified:string, verification_time:datetime, online:string, target:string)[@'http://data.phishtank.com/data/online-valid.csv'] with (format='csv', ignorefirstrecord = true)
| summarize URLs = count() by bin(verification_time, 8h)
```
![image](https://github.com/LearningKijo/KQL/assets/120234772/288013f8-f2d0-4e26-b969-f7c172d8a3fe)

externaldata

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
