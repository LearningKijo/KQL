# Suspicious email events
- Threat actors misuse OAuth applications to automate financially driven attacks

> [!Note]
> These queries need to be updated with timestamps related to application creation time before running.

####  Suspicious email events
Identify High Outbound Email Sender
```kusto
EmailEvents 
| where Timestamp between (<start> .. <end>) //Timestamp from the app creation time to few hours upto 24 hours or more 
| where EmailDirection in ("Outbound") 
| project
    RecipientEmailAddress,
    SenderFromAddress,
    SenderMailFromAddress,
    SenderObjectId,
    NetworkMessageId 
| summarize
    RecipientCount = dcount(RecipientEmailAddress),
    UniqueEmailSentCount = dcount(NetworkMessageId)
    by SenderFromAddress, SenderMailFromAddress, SenderObjectId
| sort by UniqueEmailSentCount desc 
//| where UniqueEmailSentCount > <threshold> //Optional, return only if the sender sent more than the threshold
//| take 100 //Optional, return only top 100
```

Identify Suspicious Outbound Email Sender
```kusto
EmailEvents 
//| where Timestamp between (<start> .. <end>) //Timestamp from the app creation time to few hours upto 24 hours or more 
| where EmailDirection in ("Outbound") 
| project
    RecipientEmailAddress,
    SenderFromAddress,
    SenderMailFromAddress,
    SenderObjectId, 
    DetectionMethods,
    NetworkMessageId 
| summarize
    RecipientCount = dcount(RecipientEmailAddress),
    UniqueEmailSentCount = dcount(NetworkMessageId),
    SuspiciousEmailCount = dcountif(NetworkMessageId,isnotempty(DetectionMethods))
    by SenderFromAddress, SenderMailFromAddress, SenderObjectId
| extend SuspiciousEmailPercentage = SuspiciousEmailCount/UniqueEmailSentCount * 100 //Calculate the percentage of suspicious email compared to all email sent
| sort by SuspiciousEmailPercentage desc 
//| where UniqueEmailSentCount > <threshold> //Optional, return only if the sender suspicious email percentage is more than the threshold
//| take 100 //Optional, return only top 100
```

Identify Recent Emails Sent by Restricted Email Sender
```kusto
AlertEvidence
| where Title has "User restricted from sending email"
| project AccountObjectId //Identify the user who are restricted to send email
| join EmailEvents on $left.AccountObjectId == $right.SenderObjectId //Join information from Alert Evidence and Email Events
| project
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderMailFromAddress,
    SenderObjectId,
    SenderIPv4,
    Subject,
    UrlCount,
    AttachmentCount,
    DetectionMethods,
    AuthenticationDetails, 
    NetworkMessageId
| sort by Timestamp desc 
//| take 100 //Optional, return only first 100
```

#### Reference
- December 12, 2023, [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
