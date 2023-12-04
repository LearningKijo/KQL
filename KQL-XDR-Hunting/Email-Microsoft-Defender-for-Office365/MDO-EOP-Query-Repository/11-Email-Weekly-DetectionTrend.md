#  Email Weekly Detection Trend
This query displays the weekly detection trends captured by MDO and EOP for Phish, Malware, and Spam.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(ThreatTypes)
| extend StringtoDynamic = split(ThreatTypes, ", ")
| mv-expand StringtoDynamic
| extend EmailThreat = tostring(StringtoDynamic)
| summarize Case = count() by EmailThreat, bin(Timestamp, 1d)
| render linechart 
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
