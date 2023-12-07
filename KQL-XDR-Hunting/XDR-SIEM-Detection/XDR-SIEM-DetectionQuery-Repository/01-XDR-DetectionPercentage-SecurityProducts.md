# XDR : Daily Security Product Detections Breakdown
This query provides a daily breakdown, indicating the percentage of detections attributed to various security products, including:
- [x] Microsoft Defender XDR (Microsoft 365 Defender)
- [x] Microsoft Defender for Identity
- [x] Microsoft Defender for Cloud Apps
- [x] Microsoft Defender for Office 365
- [x] Microsoft Defender for Endpoint
- [x] Microsoft Entra ID Protection (AAD Identity Protection)
- [x] App Governance
- [x] Microsoft Data Loss Prevention"

#### Table name & Description
- [AlertInfo](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertinfo-table?view=o365-worldwide) : Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity, including severity information and threat categorization

```kusto
AlertInfo
| where TimeGenerated > ago(7d)
| summarize TotalAlertCount = count(),
            App_Governance = countif(ServiceSource == "App Governance"),
            AAD_Identity_Protection = countif(ServiceSource == "AAD Identity Protection"),
            Microsoft_365_Defender = countif(ServiceSource == "Microsoft 365 Defender"),
            Microsoft_Defender_for_Identity = countif(ServiceSource == "Microsoft Defender for Identity"),
            Microsoft_Defender_for_Cloud_Apps = countif(ServiceSource == "Microsoft Cloud App Security"),
            Microsoft_Defender_for_Office365 = countif(ServiceSource == "Microsoft Defender for Office 365"),
            Microsoft_Defender_for_Endpoint = countif(ServiceSource == "Microsoft Defender for Endpoint"),
            Microsoft_Data_Loss_Prevention  = countif(ServiceSource == "Microsoft Data Loss Prevention") by bin(TimeGenerated, 1d)
| extend App_Governance_percentage = todouble(round(App_Governance / todouble(TotalAlertCount) * 100, 2))
| extend AAD_Identity_Protection_percentage = todouble(round(AAD_Identity_Protection / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_365_Defender_percentage = todouble(round(Microsoft_365_Defender / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_Defender_for_Identity_percentage = todouble(round(Microsoft_Defender_for_Identity / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_Defender_for_Cloud_Apps_percentage = todouble(round(Microsoft_Defender_for_Cloud_Apps / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_Defender_for_Office365_percentage = todouble(round(Microsoft_Defender_for_Office365 / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_Defender_for_Endpoint_percentage = todouble(round(Microsoft_Defender_for_Endpoint / todouble(TotalAlertCount) * 100, 2))
| extend Microsoft_Data_Loss_Prevention_percentage = todouble(round(Microsoft_Data_Loss_Prevention / todouble(TotalAlertCount) * 100, 2))
| project TimeGenerated,  
          App_Governance_percentage, 
          AAD_Identity_Protection_percentage, 
          Microsoft_365_Defender_percentage,
          Microsoft_Defender_for_Identity_percentage,
          Microsoft_Defender_for_Cloud_Apps_percentage,
          Microsoft_Defender_for_Office365_percentage,
          Microsoft_Defender_for_Endpoint_percentage,
          Microsoft_Data_Loss_Prevention_percentage
| render columnchart 
```
> [!Important]
> You can use this query in Advanced Hunting, Microsoft Defender XDR, by shifting 'TimeGenerated' to 'Timestamp' (Line 2). However, in terms of columnchart and data visualization, I recommend utilizing this query in Microsoft Sentinel.

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/52213a49-aa88-48aa-8ab5-e7ef40b53d4c)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
