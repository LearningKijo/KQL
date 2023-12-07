# AV detection : Threat Family & Filename by Device
This query displays threat family and filename that were detected by Microsoft Defender Antivirus in the past 7 days for each device.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend DetectionType =parse_json(AdditionalFields)
| summarize MalwareFamilyList = make_list(strcat(DetectionType.ThreatName, @"\", FileName)) by DeviceName, DeviceId
| extend ThreatNumber = array_length(MalwareFamilyList)
| project DeviceId, DeviceName, ThreatNumber, MalwareFamilyList
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
