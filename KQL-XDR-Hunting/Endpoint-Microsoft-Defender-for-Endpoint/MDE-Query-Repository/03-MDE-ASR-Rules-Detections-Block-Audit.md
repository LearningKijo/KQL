# ASR Rules Detections : Block & Audit mode 
The first query displays ASR rules detection for block mode, and the second query shows ASR rules detection for audit mode.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection


####  ASR rules Block activities 
```kusto
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "false" 
```

#### ASR rules Audit activities 
```kusto
DeviceEvents 
| where Timestamp > ago(7d) 
| where ActionType startswith "asr" 
| extend Parsed = parse_json(AdditionalFields) 
| where Parsed.IsAudit == "true" 
```

#### <Result> 

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
