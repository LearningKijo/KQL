#  Emails delivered having URLs(QR codes)
This query displays emails delivered having URLs in the form of QR codes.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| project Timestamp, NetworkMessageId, SenderFromAddress, Subject, Url, UrlDomain, UrlLocation
```

#### Reference 
[Hunting and responding to QR code-based phishing attacks with Defender for Office 365](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
