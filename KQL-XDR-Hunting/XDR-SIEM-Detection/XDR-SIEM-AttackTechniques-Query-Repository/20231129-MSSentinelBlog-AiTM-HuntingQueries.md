# Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection

> [!Note]
> ***AiTM - "adversary-in-the-middle"*** - In AiTM phishing, attackers deploy a proxy server between a target user and the website the user wishes to visit (that is, the site the attacker wishes to impersonate). 
> Such a setup allows the attacker to steal and intercept the target’s password and the session cookie that proves their ongoing and authenticated session with the website. 
> Note that this is not a vulnerability in MFA; since AiTM phishing steals the session cookie, the attacker gets authenticated to a session on the user’s behalf, regardless of the sign-in method the latter uses.

#### 1. [Phishing Link Clicks in Network Traffic](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/PhishinglinkExecutionObserved.yaml)
- **Description** : This rule is designed to identify successful phishing link clicks by users and the subsequent network activity from non-Microsoft network devices.
- **How it works** : It identifies phishing-related alerts in Microsoft 365 Defender and matches them with 3rd party network device logs such as Firewalls instead non Microsoft devices. It aims to detect successful phishing link clicks followed by suspicious network activity.
```kusto
//Finding MDO Security alerts and extracting the Entities user, Domain, Ip, and URL.
    let Alert_List= dynamic([
    "Phishing link click observed in Network Traffic",
    "Phish delivered due to an IP allow policy",
    "A potentially malicious URL click was detected",
    "High Risk Sign-in Observed in Network Traffic",
    "A user clicked through to a potentially malicious URL",
    "Suspicious network connection to AitM phishing site",
    "Messages containing malicious entity not removed after delivery",
    "Email messages containing malicious URL removed after delivery",
    "Email reported by user as malware or phish",
    "Phish delivered due to an ETR override",
    "Phish not zapped because ZAP is disabled"]);
    SecurityAlert
    |where ProviderName in~ ("Office 365 Advanced Threat Protection", "OATP")
    | where AlertName in~ (Alert_List)
    //extracting Alert Entities
     | extend Entities = parse_json(Entities)
    | mv-apply Entity = Entities on
    (
    where Entity.Type == 'account'
    | extend EntityUPN = iff(isempty(Entity.UserPrincipalName), tostring(strcat(Entity.Name, "@", tostring (Entity.UPNSuffix))), tostring(Entity.UserPrincipalName))
    )
    | mv-apply Entity = Entities on
    (
    where Entity.Type == 'url'
    | extend EntityUrl = tostring(Entity.Url)
    )
    | summarize AccountUpn=tolower(tostring(take_any(EntityUPN))),Url=tostring(tolower(take_any(EntityUrl))),AlertTime= min(TimeGenerated)by SystemAlertId, ProductName
    // filtering 3pnetwork devices
    | join kind= inner (CommonSecurityLog
    | where DeviceVendor has_any  ("Palo Alto Networks", "Fortinet", "Check Point", "Zscaler")
    | where DeviceAction != "Block"
    | where DeviceProduct startswith "FortiGate" or DeviceProduct startswith  "PAN" or DeviceProduct startswith  "VPN" or DeviceProduct startswith "FireWall" or DeviceProduct startswith  "NSSWeblog" or DeviceProduct startswith "URL"
    | where isnotempty(RequestURL)
    | where isnotempty(SourceUserName)
    | extend SourceUserName = tolower(SourceUserName)
    | project
    3plogTime=TimeGenerated,
    DeviceVendor,
    DeviceProduct,
    Activity,
    DestinationHostName,
    DestinationIP,
    RequestURL=tostring(tolower(RequestURL)),
    MaliciousIP,
    Name = tostring(split(SourceUserName,"@")[0]),
    UPNSuffix =tostring(split(SourceUserName,"@")[1]),
    SourceUserName,
    IndicatorThreatType,
    ThreatSeverity,AdditionalExtensions,
    ThreatConfidence)on $left.Url == $right.RequestURL and $left.AccountUpn == $right.SourceUserName
    // Applied the condition where alert trigger 1st and then the 3p Network activity execution
    | where AlertTime between ((3plogTime - 1h) .. (3plogTime + 1h))
```

#### 2. [ Correlating M365D Alerts with Non-Microsoft Network Device Activity](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/SucessfullSiginFromPhingLink.yaml)
- **Description** : This rule correlates Microsoft 365 Defender phishing-related alerts with sign-in activities on non-Microsoft network devices, especially when users connect to phishing URLs.
- **How it works** : It correlates Microsoft 365 Defender alerts with network logs from devices like Palo Alto Networks, Fortinet, Check Point, and Zscaler. It focuses on cases where users connect to phishing URLs from these devices and subsequently make successful sign-in attempts.
```kusto
    let Alert_List= dynamic([
    "Phishing link click observed in Network Traffic",
    "Phish delivered due to an IP allow policy",
    "A potentially malicious URL click was detected",
    "High Risk Sign-in Observed in Network Traffic",
    "A user clicked through to a potentially malicious URL",
    "Suspicious network connection to AitM phishing site",
    "Messages containing malicious entity not removed after delivery",
    "Email messages containing malicious URL removed after delivery",
    "Email reported by user as malware or phish",
    "Phish delivered due to an ETR override",
    "Phish not zapped because ZAP is disabled"]);
    SecurityAlert
    | where AlertName in~ (Alert_List)
    //Findling Alerts which has the URL
    | where Entities has "url"
    //extracting Entities
    | extend Entities = parse_json(Entities)
    | mv-apply Entity = Entities on
        (
        where Entity.Type == 'url'
        | extend EntityUrl = tostring(Entity.Url)
        )
    | summarize
        Url=tostring(tolower(take_any(EntityUrl))),
        AlertTime= min(TimeGenerated),
        make_set(SystemAlertId, 100)
        by ProductName, AlertName
    // matching with 3rd party network logs and 3p Alerts
    | join kind= inner (CommonSecurityLog
        | where DeviceVendor has_any  ("Palo Alto Networks", "Fortinet", "Check Point", "Zscaler")
        | where DeviceProduct startswith "FortiGate" or DeviceProduct startswith  "PAN" or DeviceProduct startswith  "VPN" or DeviceProduct startswith "FireWall" or DeviceProduct startswith  "NSSWeblog" or DeviceProduct startswith "URL"
        | where DeviceAction != "Block"
        | where isnotempty(RequestURL)
        | project
            3plogTime=TimeGenerated,
            DeviceVendor,
            DeviceProduct,
            Activity,
            DestinationHostName,
            DestinationIP,
            RequestURL=tostring(tolower(RequestURL)),
            MaliciousIP,
            SourceUserName=tostring(tolower(SourceUserName)),
            IndicatorThreatType,
            ThreatSeverity,
            ThreatConfidence,
            SourceUserID,
            SourceHostName)
        on $left.Url == $right.RequestURL
    // matching successful Login from suspicious IP
    | join kind=inner (SigninLogs
        //filtering the Successful Login
        | where ResultType == 0
        | project
            IPAddress,
            SourceSystem,
            SigniningTime= TimeGenerated,
            OperationName,
            ResultType,
            ResultDescription,
            AlternateSignInName,
            AppDisplayName,
            AuthenticationRequirement,
            ClientAppUsed,
            RiskState,
            RiskLevelDuringSignIn,
            UserPrincipalName=tostring(tolower(UserPrincipalName)),
            Name = tostring(split(UserPrincipalName, "@")[0]),
            UPNSuffix =tostring(split(UserPrincipalName, "@")[1]))
        on $left.DestinationIP == $right.IPAddress and $left.SourceUserName == $right.UserPrincipalName
    | where SigniningTime between ((AlertTime - 6h) .. (AlertTime + 6h)) and 3plogTime between ((AlertTime - 6h) .. (AlertTime + 6h))
```

#### 3. [Risky User SignIn on Non-Microsoft Network Devices](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/RiskyUserIn3Pnetworkactivity.yaml)
- **Description** : This rule identifies successful logins by risky users on non-Microsoft network devices. It looks for users who have engaged in potentially suspicious network activity on these devices.
- **How it works** : By analyzing Azure Active Directory and security logs from network devices like Palo Alto Networks, Fortinet, Check Point, and Zscaler, this rule identifies suspicious user sign-ins. It then correlates these sign-ins with risky network activity.
```kusto
SigninLogs
    //Find risky Signin
    | where RiskState == "atRisk" and ResultType == 0
    | extend Signin_Time = TimeGenerated
    | summarize
        AppDisplayName=make_set(AppDisplayName),
        ClientAppUsed=make_set(ClientAppUsed),
        UserAgent=make_set(UserAgent),
        CorrelationId=make_set(CorrelationId),
        Signin_Time= min(Signin_Time),
        RiskEventTypes=make_set(RiskEventTypes)
        by
        ConditionalAccessStatus,
        IPAddress,
        IsRisky,
        ResourceDisplayName,
        RiskDetail,
        ResultType,
        RiskLevelAggregated,
        RiskLevelDuringSignIn,
        RiskState,
        UserPrincipalName=tostring(tolower(UserPrincipalName)),
        SourceSystem
    | join kind=inner (
        CommonSecurityLog
        | where DeviceVendor has_any  ("Palo Alto Networks", "Fortinet", "Check Point", "Zscaler")
        | where DeviceProduct startswith "FortiGate" or DeviceProduct startswith  "PAN" or DeviceProduct startswith  "VPN" or DeviceProduct startswith "FireWall" or DeviceProduct startswith  "NSSWeblog" or DeviceProduct startswith "URL"
        | where DeviceAction != "Block"
        | where isnotempty(RequestURL)
        | where isnotempty(SourceUserName)
        | extend SourceUserName = tolower(SourceUserName)
        | summarize
            min(TimeGenerated),
            max(TimeGenerated),
            Activity=make_set(Activity)
            by DestinationHostName, DestinationIP, RequestURL, SourceUserName=tostring(tolower(SourceUserName)),DeviceVendor,DeviceProduct
        | extend 3p_observed_Time= min_TimeGenerated,Name = tostring(split(SourceUserName,"@")[0]),UPNSuffix =tostring(split(SourceUserName,"@")[1]))
        on $left.IPAddress == $right.DestinationIP and $left.UserPrincipalName == $right.SourceUserName
    | extend Timediff = datetime_diff('day', 3p_observed_Time, Signin_Time)
    | where Timediff <= 1 and Timediff >= 0
```

#### Reference
- Nov 29 2023, [Identifying Adversary-in-the-Middle (AiTM) Phishing Attacks through 3rd-Party Network Detection](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/identifying-adversary-in-the-middle-aitm-phishing-attacks/ba-p/3991358)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
