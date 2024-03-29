# KQL : Azure AD Identity Protection & Detection
Azure AD Identity Protection is a cloud-based security service that helps organizations protect their identity infrastructure. It uses machine learning and threat intelligence to identify and mitigate risks related to identity and access. Some of its key features include risk-based conditional access, identity risk assessment, threat intelligence, and self-service password reset. It helps organizations to prevent identity-related attacks and improve the security of their identity infrastructure.

## KQL : Hunting queries
1. This KQL shows AAD Identity Protection data for a given month with barchart.
```kql
SigninLogs
| where TimeGenerated > ago(180d)
| extend RemovedBracketAndQuotation = replace_regex(replace_regex(RiskEventTypes, @'[\[\]]', ''), @'"', '')
| where isnotempty(RemovedBracketAndQuotation)
| extend ParsedRisk =parse_json(RemovedBracketAndQuotation)
| extend RiskName = split(ParsedRisk, ",")
| mv-expand RiskName
| extend Detection = iff(RiskName in ("impossibleTravel", "newCountry", "riskyIPAddress", "mcasSuspiciousInboxManipulationRules", "suspiciousInboxForwarding"),
 "Microsoft Defender for Cloud Apps", "Azure AD Identity Protection")
| summarize count() by tostring(RiskName), Detection
| render barchart 
```
> **Note** : 
> SigninLogs table is available in Log Analytics workspace / Microsoft Sentinel, Not in Microsoft 365 Defender. 
> [Stream Azure Active Directory logs to Azure Monitor logs - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)


2. This KQL shows the daily AAD Identity Protection data for a given month.
```kql
SigninLogs
| where TimeGenerated > ago(180d)
| extend RemovedBracketAndQuotation = replace_regex(replace_regex(RiskEventTypes, @'[\[\]]', ''), @'"', '')
| where isnotempty(RemovedBracketAndQuotation)
| extend ParsedRisk =parse_json(RemovedBracketAndQuotation)
| extend RiskName = split(ParsedRisk, ",")
| mv-expand RiskName
| extend Detection = iff(RiskName in ("impossibleTravel", "newCountry", "riskyIPAddress", "mcasSuspiciousInboxManipulationRules", "suspiciousInboxForwarding"),
 "Microsoft Defender for Cloud Apps", "Azure AD Identity Protection")
| summarize count() by tostring(RiskName), Detection,bin(TimeGenerated, 1d)
| render columnchart 
```
> **Note** : 
> SigninLogs table is available in Log Analytics workspace / Microsoft Sentinel, Not in Microsoft 365 Defender. 
> [Stream Azure Active Directory logs to Azure Monitor logs - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)

## KQL : Hunting results
**e.g. - Case 1**

![image](https://user-images.githubusercontent.com/120234772/225237878-cc8cd3e2-8d4f-4c16-b6aa-16a3148cb4f4.png)

**e.g. - Case 2**

![image](https://user-images.githubusercontent.com/120234772/225238025-737af0f3-2a81-47b4-b59f-ef98eb3d6cc4.png)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
