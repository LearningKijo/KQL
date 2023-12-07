# Visualizing ASR Rules With PieChart : Block & Audit mode 
The first query generates a pie chart visualizing the distribution of ASR rules block detections, and the second query does the same for audit detections.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

####  ASR rules : Block mode 
```kusto
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "false" 
| summarize ASR_rule_case = count() by ActionType
| render piechart 
```

#### ASR rules : Audit mode 
```kusto
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "true" 
| summarize ASR_rule_case = count() by ActionType
| render piechart 
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/8052b7f3-2900-44f8-811e-6a68f8e34d76)


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
