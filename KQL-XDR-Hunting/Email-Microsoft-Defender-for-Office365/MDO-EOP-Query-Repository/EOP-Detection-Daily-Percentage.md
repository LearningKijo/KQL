# EOP Detection Daily Percentage
This query shows the daily percentage of EOP detections.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(DetectionMethods)
| extend EOP_detection = parse_json(DetectionMethods)
| summarize TotalEmailCount = count(),
            Phish_detection = countif(isnotempty(EOP_detection.Phish)),
            Malware_detection = countif(isnotempty(EOP_detection.Malware)),
            URL_malicious_reputation = countif(EOP_detection.Phish == @'["URL malicious reputation"]' or EOP_detection.Malware == @'["URL malicious reputation"]'),
            Advanced_filter = countif(EOP_detection.Phish == @'["Advanced filter"]'),
            General_filter = countif(EOP_detection.Phish == @'["General filter"]'),
            Spoof_intra_org = countif(EOP_detection.Phish == @'["Spoof intra-org"]'),
            Spoof_external_domain = countif(EOP_detection.Phish ==  @'["Spoof external domain"]'),
            Spoof_DMARC = countif(EOP_detection.Phish == @'["Spoof DMARC"]'),
            Impersonation_brand = countif(EOP_detection.Phish == @'["Impersonation brand"]'),
            Mixed_analysis_detection= countif(EOP_detection.Phish == @'["Mixed analysis detection"]'),
            File_reputation = countif(EOP_detection.Phish == @'["File reputation"]' or EOP_detection.Malware == @'["File reputation"]'),
            Fingerprint_matching = countif(EOP_detection.Phish == @'["Fingerprint matching"]'), 
            Antimalware_engine = countif(EOP_detection.Malware == @'["Antimalware engine"]') by bin(Timestamp, 1d)
| extend Phish_detection_percentage = todouble(round(Phish_detection / todouble(TotalEmailCount) * 100, 2))
| extend Malware_detection_percentage = todouble(round(Malware_detection / todouble(TotalEmailCount) * 100, 2))
| extend URL_malicious_reputation_percentage = todouble(round(URL_malicious_reputation / todouble(TotalEmailCount) * 100, 2))
| extend Advanced_filter_percentage = todouble(round(Advanced_filter / todouble(TotalEmailCount) * 100, 2))
| extend General_filter_percentage = todouble(round(General_filter / todouble(TotalEmailCount) * 100, 2))
| extend Spoof_intra_org_percentage = todouble(round(Spoof_intra_org / todouble(TotalEmailCount) * 100, 2))
| extend Spoof_external_domain_percentage = todouble(round(Spoof_external_domain / todouble(TotalEmailCount) * 100, 2))
| extend Spoof_DMARC_percentage = todouble(round(Spoof_DMARC / todouble(TotalEmailCount) * 100, 2))
| extend Impersonation_brand_percentage = todouble(round(Impersonation_brand / todouble(TotalEmailCount) * 100, 2))
| extend Mixed_analysis_detection_percentage = todouble(round(Mixed_analysis_detection / todouble(TotalEmailCount) * 100, 2))
| extend File_reputation_percentage = todouble(round(File_reputation / todouble(TotalEmailCount) * 100, 2))
| extend Fingerprint_matching_percentage = todouble(round(Fingerprint_matching / todouble(TotalEmailCount) * 100, 2))
| extend Antimalware_engine_percentage = todouble(round(Antimalware_engine / todouble(TotalEmailCount) * 100, 2))
| project Timestamp, TotalEmailCount, Phish_detection_percentage, Malware_detection_percentage, URL_malicious_reputation_percentage, Advanced_filter_percentage, General_filter_percentage, Spoof_intra_org_percentage, Spoof_external_domain_percentage, Spoof_DMARC_percentage, Impersonation_brand_percentage, Mixed_analysis_detection_percentage, File_reputation_percentage, Antimalware_engine_percentage
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
