# MDO Phishing Detection filtering
This query displays weekly MDO phishing detection.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

#### Query
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(DetectionMethods)
| extend MDO_detection = parse_json(DetectionMethods)
| where MDO_detection.Phish in 
        (
          @'["URL detonation reputation"]',
          @'["URL detonation"]',
          @'["Impersonation user"]',
          @'["Impersonation domain"]',
          @'["Mailbox intelligence impersonation"]',
          @'["File detonation"]',
          @'["File detonation reputation"]',
          @'["Campaign"]'
        )
| extend SenderFromAddress_IPv4 = strcat(SenderFromAddress, ", ", SenderIPv4)
| project Timestamp, NetworkMessageId, Subject, SenderFromAddress_IPv4, RecipientEmailAddress, DeliveryLocation, EOP_detection.Phish
```

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
