# BEC reconnaissance and OAuth application activity

 ### Threat actors misuse OAuth applications to automate financially driven attacks

#### BEC reconnaissance and OAuth application activity

High and Medium risk SignIn activity
```kusto
AADSignInEventsBeta
| where Timestamp >ago (7d)
| where ErrorCode==0
| where RiskLevelDuringSignIn >= 50
| project AccountUpn, AccountObjectId, SessionId, RiskLevelDuringSignIn, ApplicationId, Application
```

Oauth Application creation or modification by user who has suspicious sign in activities
```kusto
AADSignInEventsBeta
| where Timestamp >ago (7d)
| where ErrorCode == 0
| where RiskLevelDuringSignIn >= 50
| project SignInTime=AccountUpn, AccountObjectId, SessionId, RiskLevelDuringSignIn, ApplicationId, Application
| join kind=leftouter (CloudAppEvents | where Timestamp > ago(7d)
| where ActionType in ("Add application.", "Update application.", "Update application – Certificates and secrets management ")
| extend appId = tostring(parse_json(RawEventData.Target[4].ID))
| project Timestamp, ActionType, Application, ApplicationId, UserAgent, ISP, AccountObjectId, AppName=ObjectName, OauthApplicationId=appId, RawEventData ) on AccountObjectId
| where isnotempty(ActionType)
```

Suspicious BEC reconnaisance activity
```kusto 
let bec_keywords = pack_array("payment", "receipt", "invoice", "inventory"); 
let reconEvents = 
    CloudAppEvents
    | where Timestamp >ago (7d)
    | where ActionType in ("MailItemsAccessed", "Update")
    | where AccountObjectId in ("<Impacted AccountObjectId>")
    | extend SessionId = tostring(parse_json(RawEventData.SessionId))
    | project
        Timestamp,
        ActionType,
        AccountObjectId,
        UserAgent,
        ISP,
        IPAddress,
        SessionId,
        RawEventData;
reconEvents;
let updateActions = reconEvents
    | where ActionType == "Update" 
    | extend Subject=tostring(RawEventData["Item"].Subject)
    | where isnotempty(Subject)
    | where Subject has_any (bec_keywords)
    | summarize UpdateCount=count() by bin (Timestamp, 15m), Subject, AccountObjectId, SessionId, IPAddress;
updateActions;
let mailItemsAccessedActions = reconEvents 
    | where ActionType == "MailItemsAccessed" 
    | extend OperationCount = toint(RawEventData["OperationCount"])
    | summarize TotalCount = sum(OperationCount) by bin (Timestamp, 15m), AccountObjectId, SessionId, IPAddress;
mailItemsAccessedActions;
```
> [!Note]
> This query works in Kusto Explorer

SignIn to newly created app within Risky Session
```kusto
//SignIn to newly created app within Risky Session
AADSignInEventsBeta
| where Timestamp >ago (7d) 
| where AccountObjectId in ("<Impacted AccountObjectId>") and SessionId in ("<Risky Session Id>")
| where ApplicationId in ("<Oauth appId>") // Recently added or modified App Id
| project AccountUpn, AccountObjectId, ApplicationId, Application, SessionId, RiskLevelDuringSignIn, RiskLevelAggregated, Country
```

To check suspicious Mailbox rules
```kusto
CloudAppEvents
| where Timestamp between (start .. end) //Timestamp from the app creation time to few hours, usually before spam emails sent
| where AccountObjectId in ("<Impacted AccountObjectId>")
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Set-TransportRule", "New-TransportRule", "Enable-InboxRule", "UpdateInboxRules")
| where isnotempty(IPAddress)
| mvexpand ActivityObjects
| extend name = parse_json(ActivityObjects).Name
| extend value = parse_json(ActivityObjects).Value
| where name == "Name"
| extend RuleName = value 
| project Timestamp, ReportId, ActionType, AccountObjectId, IPAddress, ISP, RuleName
```

To check any suspicious Url clicks from emails before risky signin by the user
```kusto
UrlClickEvents
| where Timestamp between (start .. end) //Timestamp around time proximity of Risky signin by user
| where AccountUpn has "<Impacted User’s UPN or Email address>" and ActionType has "ClickAllowed"
| project Timestamp, Url, NetworkMessageId
```

To fetch the suspicious email details
```kusto
EmailEvents
| where Timestamp between (start .. end) //Timestamp lookback to be increased gradually to find the email received
| where EmailDirection has "Inbound"
| where RecipientEmailAddress has "<Impacted User’s UPN or Email address>" and NetworkMessageId == "<NetworkMessageId from UrlClickEvents>"
| project SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderFromDomain, Subject, UrlCount, AttachmentCount
```  
     
To check if suspicious emails sent for spamming (with similar email subjects, urls etc.)
```kusto
EmailEvents
| where Timestamp between (start .. end) //Timestamp from the app creation time to few hours upto 24 hours or more
| where EmailDirection in ("Outbound","Intra-org")
| where SenderFromAddress has "<Impacted User’s UPN or Email address>"  or SenderMailFromAddress has "<Impacted User’s UPN or Email address>"
| project RecipientEmailAddress, RecipientObjectId, SenderIPv4, SenderFromDomain, Subject, UrlCount, AttachmentCount, NetworkMessageId
```

#### Reference
- December 12, 2023, [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
