# EOP Phishing Detection filtering
This query displays weekly EOP phishing detection.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

#### Query
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(DetectionMethods)
| extend EOP_detection = parse_json(DetectionMethods)
| where EOP_detection.Phish in 
        (
          @'["URL malicious reputation"]',
          @'["Advanced filter"]',
          @'["General filter"]',
          @'["Spoof intra-org"]',
          @'["Spoof external domain"]',
          @'["Spoof DMARC"]',
          @'["Impersonation brand"]',
          @'["Mixed analysis detection"]',
          @'["File reputation"]',
          @'["Fingerprint matching"]'
        )
| extend SenderFromAddress_IPv4 = strcat(SenderFromAddress, ", ", SenderIPv4)
| project Timestamp, NetworkMessageId, Subject, SenderFromAddress_IPv4, RecipientEmailAddress, DeliveryLocation, EOP_detection.Phish
```

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
