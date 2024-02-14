# Hunting for QR Code AiTM Phishing and User Compromise

> [!Note]
> ***AiTM - "adversary-in-the-middle"*** - In AiTM phishing, attackers deploy a proxy server between a target user and the website the user wishes to visit (that is, the site the attacker wishes to impersonate). 
> Such a setup allows the attacker to steal and intercept the target’s password and the session cookie that proves their ongoing and authenticated session with the website. 
> Note that this is not a vulnerability in MFA; since AiTM phishing steals the session cookie, the attacker gets authenticated to a session on the user’s behalf, regardless of the sign-in method the latter uses.

### 1. Hunting for user behavior
This is one of the primary detections that helps Defender Experts surface suspicious sign-in attempts from QR code phishing campaigns.
Although the user scans the QR code from an email on their personal mobile device, in the majority of the scenarios, the phishing email being accessed is recorded with MailItemsAccessed mail-box auditing action.
The majority of the QR code campaigns have image (png/jpg/jpeg/gif) or document attachments (pdf/doc/xls) – Yes! QR codes are embedded in Excel attachments too! 
The campaigns can include a legitimate URL that redirects to a phishing page with malicious QR code as well.
A malicious sign-in attempt with session token compromise that follows the QR code scan is always observed from non-trusted devices with medium/high risk score for the session.
This detection approach correlates a user accessing an email with image/document attachments and a risky sign-in attempt from non-trusted devices in closer proximity and 
validates if the location from where the email item was accessed is different from the location of sign-in attempt.

```kusto
let successfulRiskySignIn = materialize(AADSignInEventsBeta
| where Timestamp > ago(1d)
| where isempty(DeviceTrustType)
| where IsManaged != 1
| where IsCompliant != 1
| where RiskLevelDuringSignIn in (50, 100)
| project Timestamp, ReportId, IPAddress, AccountUpn, AccountObjectId, SessionId, Country, State, City
);
let suspiciousSignInUsers = successfulRiskySignIn
| distinct AccountObjectId;
let suspiciousSignInIPs = successfulRiskySignIn
| distinct IPAddress;
let suspiciousSignInCities = successfulRiskySignIn
| distinct City;
CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "MailItemsAccessed"
| where AccountObjectId in (suspiciousSignInUsers)
| where IPAddress !in (suspiciousSignInIPs)
| where City !in (suspiciousSignInCities)
| join kind=inner successfulRiskySignIn on AccountObjectId
| where AccountObjectId in (suspiciousSignInUsers)
| where (Timestamp - Timestamp1) between (-5min .. 5min)
| extend folders = RawEventData.Folders
| mv-expand folders
| extend items = folders.FolderItems
| mv-expand items
| extend InternetMessageId = tostring(items.InternetMessageId)
| project Timestamp, ReportId, IPAddress, InternetMessageId, AccountObjectId, SessionId, Country, State, City
```

### 2. Hunting for sender patterns
The sender attributes play a key role in the detection of QR code campaigns. Since the campaigns are typically large scale in nature, 95% of the campaigns do not involve phishing emails from compromised trusted vendors. 
Predominant emails are sent from newly-created domains or non-prevalent domains in the organization.
Since the attack involves multiple user actions involving scanning the QR code from a mobile device and completing the authentication, 
unlike typical phishing with simple URL clicks, the attackers induce a sense of urgency by impersonating IT support, HR support, payroll, administrator team, 
or the display name indicates the email is sent on-behalf of a known high value target in the organization (e.g., “Lara Scott on-behalf of CEO”).
In this detection approach, we correlate email from non-prevalent senders in the organization with impersonation intents.

```kusto
let PhishingSenderDisplayNames = ()
{
    pack_array("IT", "support", "Payroll", "HR", "admin", "2FA", "notification", "sign", "reminder", "consent", "workplace",
                "administrator", "administration", "benefits", "employee", "update", "on behalf");
};
let suspiciousEmails = EmailEvents
| where Timestamp > ago(1d)
| where isnotempty(RecipientObjectId)
| where isnotempty(SenderFromAddress)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| join kind=inner (EmailAttachmentInfo
| where Timestamp > ago(1d)
| where isempty(SenderObjectId)
| where FileType has_any ("png", "jpg", "jpeg", "bmp", "gif")
) on NetworkMessageId
| where SenderDisplayName has_any (PhishingSenderDisplayNames())
| project Timestamp, Subject, FileName, SenderFromDomain, RecipientObjectId, NetworkMessageId;
let suspiciousSenders = suspiciousEmails | distinct SenderFromDomain;
let prevalentSenders = materialize(EmailEvents
| where Timestamp between (ago(7d) .. ago(1d))
| where isnotempty(RecipientObjectId)
| where isnotempty(SenderFromAddress)
| where SenderFromDomain in (suspiciousSenders)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| distinct SenderFromDomain);
suspiciousEmails
| where SenderFromDomain !in (prevalentSenders)
| project Timestamp, Subject, FileName, SenderFromDomain, RecipientObjectId, NetworkMessageId
```

### 3. Hunting for subject patterns
In addition to impersonating IT and HR teams, attackers also craft the campaigns with actionable subjects. 
(e.g., MFA completion required, Digitally sign documents). The targeted user is requested to complete the highlighted action by scanning the QR code in the email and providing credentials and MFA token.
In most cases, these automated phishing campaigns also include a personalized element, where the user’s first name/last name/alias/email address is included in the subject. 
The email address of the targeted user is also embedded in the URL behind the QR code. This serves as a unique tracker for the attacker to identify emails successfully delivered and QR codes scanned.
In this detection, we track emails with suspicious keywords in subjects or personalized subjects. 
To detect personalized subjects, we track campaigns where the first three words or last three words of the subject are the same, but the other values are personalized/unique.

For example:
- Alex, you have an undelivered voice message
- Bob, you have an undelivered voice message
- Charlie, you have an undelivered voice message
- Your MFA update is pending, Alex
- Your MFA update is pending, Bob
- Your MFA update is pending, Charlie

***Personalized campaigns based on the first few keywords***
```kusto
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where isempty(SenderObjectId)
| extend words = split(Subject," ")
| project firstWord = tostring(words[0]), secondWord = tostring(words[1]), thirdWord = tostring(words[2]), Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId
| summarize SubjectsCount = dcount(Subject), RecipientsCount = dcount(RecipientEmailAddress), suspiciousEmails = make_set(NetworkMessageId, 10) by firstWord, secondWord, thirdWord, SenderFromAddress
| where SubjectsCount >= 10
```

***Personalized campaigns based on the last few keywords***
```kusto
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where isempty(SenderObjectId)
| extend words = split(Subject," ")
| project firstLastWord = tostring(words[-1]), secondLastWord = tostring(words[-2]), thirdLastWord = tostring(words[-3]), Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId
| summarize SubjectsCount = dcount(Subject), RecipientsCount = dcount(RecipientEmailAddress), suspiciousEmails = make_set(NetworkMessageId, 10) by firstLastWord, secondLastWord, thirdLastWord, SenderFromAddress
| where SubjectsCount >= 10
```

***Campaign with suspicious keywords***
```kusto
let PhishingKeywords = ()
{
    pack_array("account", "alert", "bank", "billing", "card", "change", "confirmation",
"login", "password", "mfa", "authorize", "authenticate", "payment", "urgent", "verify", "blocked");
};
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where isempty(SenderObjectId)
| where Subject has_any (PhishingKeywords())
```

### 4. Hunting for attachment name patterns
Based on the historical QR code campaigns investigations, Defender Experts have identified that the attachment names of the campaigns are usually randomized by the attackers, 
meaning every email has a different attachment name for the QR code with high levels of randomization. 
Emails with randomly named attachment names from the same sender to multiple recipients, typically more than 50, can potentially indicate a QR code phishing campaign.

***Campaign with randomly named attachments***
```kusto
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in ("png", "jpg", "jpeg", "gif", "svg")
| where isnotempty(FileName)
| extend firstFourFileName = substring(FileName, 0, 4)
| summarize RecipientsCount = dcount(RecipientEmailAddress), FirstFourFilesCount = dcount(firstFourFileName), suspiciousEmails = make_set(NetworkMessageId, 10) by SenderFromAddress
| where FirstFourFilesCount >= 10
```

### 5. Hunting for user signals/clusters
In order to craft effective large scale QR code phishing attacks, the attackers perform reconnaissance across social media to gather target user email addresses, their preferences and much more. 
These campaigns are sent across to 1,000+ users in the organization with luring subjects and contents based on their preferences. 
However, Defender Experts have observed that, at least one user finds the campaign suspicious and reports the email, which generates this alert: “Email reported by user as malware or phish.”  
This alert can be another starting point for hunting activity to identify the scope of the campaign and compromises. 
Since the campaigns are specifically crafted for each group of users, scoping based on sender/subject/filename might not be an effective approach. Microsoft Defender for Office offers a heuristic based approach based on the email content as a solution for this problem. 
Emails with similar content that are likely to be from one attacker are clustered together and the cluster ID is populated in the EmailClusterId field in EmailEvents table.
The clusters can include all phishing attempts from the attackers so far against the organization, it can aggregate emails with malicious URLs, attachments, and QR codes as one, based on the similarity. Hence, this is a powerful approach to explore the persistent phishing techniques of the attacker and the repeatedly targeted users.
Below is a sample query on scoping a campaign from the email reported by the end user. The same scoping logic can be used on the previously discussed hunting hypotheses as well.

```kusto
let suspiciousClusters = EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where NetworkMessageId in (<List of suspicious Network Message Ids from Alerts>)
| distinct EmailClusterId;
 EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where EmailClusterId in (suspiciousClusters)
| summarize make_set(Subject), make_set(SenderFromDomain), dcount(RecipientObjectId), dcount(SenderDisplayName) by EmailClusterId
```

### 6. Hunting for suspicious sign-in attempts
In addition to detecting the campaigns, it is critical that we identify the compromised identities. To surface the identities compromised by AiTM, we can utilize the below approaches.

***Risky sign-in attempt from a non-managed device***
- Any sign-in attempt from a non-managed, non-compliant, untrusted device should be taken into consideration, and a risk score for the sign-in attempt increases the anomalous nature of the activity. 
Monitoring these sign-in attempts can surface the identity compromises.

***Suspicious sign-in attributes***
- Sign-in attempts from untrusted devices with empty user agent, operating system or anomalous BrowserId can also be an indication of identity compromises from AiTM.
- Defender Experts also recommend monitoring the sign-ins from known malicious IP addresses. Although the mode of delivery of the phishing campaigns differ (QR code, HTML attachment, URL), the sign-in infrastructure often remains the same. Monitoring the sign-in patterns of compromised users, and continuously scoping the sign-in attempts based on the known patterns can also surface the identity compromises from AiTM.

```kusto
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IsManaged != 1
| where IsCompliant != 1
//Filtering only for medium and high risk sign-in
| where RiskLevelDuringSignIn in (50, 100)
| where ClientAppUsed == "Browser"
| where isempty(DeviceTrustType)
| where isnotempty(State) or isnotempty(Country) or isnotempty(City)
| where isnotempty(IPAddress)
| where isnotempty(AccountObjectId)
| where isempty(DeviceName)
| where isempty(AadDeviceId)
| project Timestamp,IPAddress, AccountObjectId, ApplicationId, SessionId, RiskLevelDuringSignIn
```

#### Reference
- February 12 2024, [Hunting for QR Code AiTM Phishing and User Compromise](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-for-qr-code-aitm-phishing-and-user-compromise/ba-p/4053324)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
