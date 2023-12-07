# EDR : Endpoint Analyzing Daily Detections
This query presents endpoint-based daily detections over the past 30 days. 
It proves valuable for analyzing devices—understanding those targeted by attackers, identifying vulnerable devices, determining the most frequently alerted devices, and more.

#### Table name & Description
- [AlertEvidence](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertevidence-table?view=o365-worldwide) : Files, IP addresses, URLs, users, or devices associated with alerts

```kusto
AlertEvidence
| where TimeGenerated > ago(30d)
| where EntityType == "Machine"
| summarize Case= count() by DeviceName, bin(TimeGenerated, 1d)
| render timechart 
```
> [!Important]
> You can use this query in Advanced Hunting, Microsoft Defender XDR, by shifting 'TimeGenerated' to 'Timestamp' (Line 2). However, in terms of columnchart and data visualization, I recommend utilizing this query in Microsoft Sentinel.

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/0c2602ed-c236-4172-b8db-a3bbfff4f9b3)


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
