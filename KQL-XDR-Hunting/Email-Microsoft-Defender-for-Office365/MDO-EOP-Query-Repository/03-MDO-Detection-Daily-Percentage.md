# MDO Detection Daily Percentage
This query shows the daily percentage of MDO detections.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(DetectionMethods)
| extend MDO_detection = parse_json(DetectionMethods)
| summarize TotalEmailCount = count(),
            Phish_detection = countif(isnotempty(MDO_detection.Phish)),
            Malware_detection = countif(isnotempty(MDO_detection.Malware)),
            URL_detonation_reputation = countif(MDO_detection.Phish == @'["URL detonation reputation"]' or MDO_detection.Malware == @'["URL detonation reputation"]'),
            URL_detonation = countif(MDO_detection.Phish == @'["URL detonation"]' or MDO_detection.Malware == @'["URL detonation"]'),
            Impersonation_user = countif(MDO_detection.Phish == @'["Impersonation user"]'),
            Impersonation_domain = countif(MDO_detection.Phish == @'["Impersonation domain"]'),
            Mailbox_intelligence_impersonation = countif(MDO_detection.Phish == @'["Mailbox intelligence impersonation"]'),
            File_detonation = countif(MDO_detection.Phish == @'["File detonation"]' or MDO_detection.Malware == @'["File detonation"]'),
            File_detonation_reputation = countif(MDO_detection.Phish == @'["File detonation reputation"]' or MDO_detection.Malware == @'["File detonation reputation"]'),
            Campaign = countif(MDO_detection.Phish == @'["Campaign"]' or MDO_detection.Malware == @'["Campaign"]') by bin(Timestamp, 1d)
| extend Phish_detection_percentage = todouble(round(Phish_detection / todouble(TotalEmailCount) * 100, 2))
| extend Malware_detection_percentage = todouble(round(Malware_detection / todouble(TotalEmailCount) * 100, 2))
| extend URL_detonation_reputation_percentage = todouble(round(URL_detonation_reputation / todouble(TotalEmailCount) * 100, 2))
| extend URL_detonation_percentage = todouble(round(URL_detonation / todouble(TotalEmailCount) * 100, 2))
| extend Impersonation_user_percentage = todouble(round(Impersonation_user / todouble(TotalEmailCount) * 100, 2))
| extend Impersonation_domain_percentage = todouble(round(Impersonation_domain / todouble(TotalEmailCount) * 100, 2))
| extend Mailbox_intelligence_impersonation_percentage = todouble(round(Mailbox_intelligence_impersonation / todouble(TotalEmailCount) * 100, 2))
| extend File_detonation_percentage = todouble(round(File_detonation / todouble(TotalEmailCount) * 100, 2))
| extend File_detonation_reputation_percentage = todouble(round(File_detonation_reputation / todouble(TotalEmailCount) * 100, 2))
| extend Campaign_percentage = todouble(round(Campaign / todouble(TotalEmailCount) * 100, 2))
| project Timestamp, TotalEmailCount, Phish_detection_percentage, Malware_detection_percentage, URL_detonation_reputation_percentage, URL_detonation_percentage, Impersonation_user_percentage,  Impersonation_domain_percentage, Mailbox_intelligence_impersonation_percentage, File_detonation_percentage, File_detonation_reputation_percentage, Campaign_percentage
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
