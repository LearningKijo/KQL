# Hunting and responding to QR code-based phishing attacks with Defender for Office 365

**Hunting for adversary-in-the-middle (AiTM) phishing and user compromise:**

The downside of users not being able to decode what is hidden behind a QR code has been a major factor behind the attacks involving malicious QR codes. 
One such example is adversary-in-the-middle (AiTM) attacks. 
Adversaries have the capability to design QR codes that reroute users to counterfeit versions of trusted websites, including banks, social media platforms, or online services. 
Once the unsuspecting user scans the QR code, they are promptly directed to a fraudulent phishing page. 
Upon authentication by the user, attackers seize the user's session token, providing them with the means to execute various malicious activities, such as Business Email Compromise attacks and attempts to illicitly extract data. 
Conversely, attackers may also engineer QR codes that prompt users to unknowingly download malware onto their devices. 
These forms of attacks carry grave consequences, potentially leading to identity theft, financial detriment, data breaches, or compromise of the user's device integrity.


```kusto
let senderprevalence =
EmailEvents
    | where Timestamp between (ago(7d)..(now()-24h))
    | where isnotempty(SenderFromAddress)
    | summarize TotalEmailCount = dcount(NetworkMessageId) by SenderFromAddress
    | where TotalEmailCount > 1;
let prevalent_Sender = senderprevalence
    | where isnotempty (SenderFromAddress)
    | distinct SenderFromAddress;
let QR_from_non_prevalent =
EmailEvents
| where EmailDirection == "Inbound"
| where Timestamp > ago(1d)
| where SenderFromAddress !in (prevalent_Sender)
| join EmailUrlInfo on NetworkMessageId
    | where UrlLocation == "QRCode"
    | distinct SenderFromAddress,Url,NetworkMessageId;
QR_from_non_prevalent
```

**Next Steps:** 

In addition to conducting threat hunting activities and implementing remediation measures, there are several proactive steps that organizations can take to enhance their protection against potential attacks covering continuous monitoring along with providing essential training against such attacks to the end users. 
Here are a few steps security teams can take to ensure secure posture:

**1) Write a custom detection rule:**

Custom detection rules are customizable rules that defined using advanced hunting queries. 
These rules facilitate proactive surveillance of suspicious events and activities, which allows security teams to have proactive monitors on the threat landscape in their organization. 
They can be scheduled for periodic execution, facilitating the generation of incidents/alerts and triggering automatic email remediation actions as per the rule configuration. 
To learn more about how to create and manage custom detection rules, check out - [Create and manage custom detection rules in Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide)
With the new QR code-based emerging attack patterns, security teams can write a custom detection rule to check the sender prevalence over the last 14 days and use the same to detect malicious activity via email containing QR code. 
Here’s a sample custom detection rule using sender prevalence over emails containing QR codes:

```kusto
let QRCode_emails = EmailUrlInfo
    | where Timestamp > ago (2d)
    | where UrlLocation == "QRCode"
    | distinct Url,NetworkMessageId;
let nMIDs = QRCode_emails | distinct NetworkMessageId;
// Extracting sender of the email with QRCode:
let senders_NMIDs = EmailEvents
    | where Timestamp > ago (2d)
    | where DeliveryLocation != "Blocked" // Only delivered or Junked emails are interesting
    | where isnotempty(NetworkMessageId)
    | where NetworkMessageId in (nMIDs)
    | distinct  Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, InternetMessageId, RecipientObjectId, ReportId;
let senders = senders_NMIDs
    | distinct SenderFromAddress;
// Checking sender prevalence in the organization
let senderprevalence = EmailEvents
    | where Timestamp between (ago(14d)..(now()-24h))
    | where isnotempty(SenderFromAddress)
    | where SenderFromAddress in (senders)
    | summarize TotalEmailCount = count()  by SenderFromAddress
    | where TotalEmailCount > 1;
let prevalent_Sender = senderprevalence
    | where isnotempty (SenderFromAddress)
    | distinct SenderFromAddress;
// Checking if in clicked emails sender was not prevalent.
let nMIDs_from_non_prevalent_Senders = senders_NMIDs
    | where SenderFromAddress !in (prevalent_Sender)
    | distinct NetworkMessageId;
let QRCode_emails_from_non_prevalent_senders = QRCode_emails
    | where NetworkMessageId in (nMIDs_from_non_prevalent_Senders)
    | join kind=inner senders_NMIDs on NetworkMessageId
    | project Timestamp,Url, NetworkMessageId, InternetMessageId, RecipientObjectId, ReportId;
QRCode_emails_from_non_prevalent_senders
```
 


#### Reference
- Apr 01 2024, [Hunting and responding to QR code-based phishing attacks with Defender for Office 365](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730)
- Feb 12 2024, [Hunting for QR Code AiTM Phishing and User Compromise](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-for-qr-code-aitm-phishing-and-user-compromise/bc-p/4054850)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
