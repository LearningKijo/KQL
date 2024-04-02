#  QR code, volume of inbound emails
This query displays volume of inbound emails with QR code in last 30 days

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

```kusto
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| summarize dcount(NetworkMessageId) by bin(Timestamp, 1d)
| render timechart
```

#### Reference 
[Hunting and responding to QR code-based phishing attacks with Defender for Office 365](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
