# Categorized ASR Rules Detection Graph  
This query displays a daily categorization of ASR rules. 
For example, with the current count of 16 rules, SOC analysts may wish to monitor the day-to-day detection rates for specific categories, such as office-related activities or WMI. 

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "asr"
| extend Parsed = parse_json(AdditionalFields)
// | where Parsed.IsAudit == "true" 
| where Parsed.IsAudit == "false" 
| summarize Email = countif(ActionType in ("AsrExecutableEmailContentBlocked", "AsrOfficeCommAppChildProcessBlocked")),
            Script = countif(ActionType in ("AsrObfuscatedScriptBlocked", "AsrScriptExecutableDownloadBlocked")),
            WMI = countif(ActionType in ("AsrPersistenceThroughWmiBlocked", "AsrPsexecWmiChildProcessBlocked")),
            OfficeApp = countif(ActionType in ("AsrOfficeChildProcessBlocked", "AsrOfficeMacroWin32ApiCallsBlocked", "AsrExecutableOfficeContentBlocked", "AsrOfficeProcessInjectionBlocked")),
            3rdPartyApp = countif(ActionType == "AsrAdobeReaderChildProcessBlocked"),
            WindowsCredentials = countif(ActionType == "AsrLsassCredentialTheftBlocked"),
            PolymorphicThreats = countif(ActionType in ("AsrUntrustedExecutableBlocked", "AsrUntrustedUsbProcessBlocked", "AsrRansomwareBlocked", "AsrVulnerableSignedDriverBlocked")) by bin(Timestamp, 1d)
| render columnchart
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/aaf41c5e-2383-4e4e-98c7-3ea9bafc7bea)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
