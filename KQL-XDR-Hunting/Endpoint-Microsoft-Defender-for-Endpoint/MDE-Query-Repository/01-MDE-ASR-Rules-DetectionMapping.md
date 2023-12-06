# ASR Rules Detections Across All Devices
This query provides a summary of all ASR rules detections across all devices, displaying ***1) ASR rules names***, ***2) Filenames***, and ***3) Timelines***.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
 DeviceEvents
 | where Timestamp > ago(7d)
 | where ActionType startswith "asr"
 | extend Parsed = parse_json(AdditionalFields)
 | where Parsed.IsAudit == "false" 
 | summarize Email = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType in ("AsrExecutableEmailContentBlocked", "AsrOfficeCommAppChildProcessBlocked")),
             Script = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName),ActionType in ("AsrObfuscatedScriptBlocked", "AsrScriptExecutableDownloadBlocked")),
             WMI = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType in ("AsrPersistenceThroughWmiBlocked", "AsrPsexecWmiChildProcessBlocked")),
             OfficeApp = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType in ("AsrOfficeChildProcessBlocked", "AsrOfficeMacroWin32ApiCallsBlocked", "AsrExecutableOfficeContentBlocked", "AsrOfficeProcessInjectionBlocked")),
             3rdPartyApp = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType == "AsrAdobeReaderChildProcessBlocked"),
             WindowsCredentials = make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType == "AsrLsassCredentialTheftBlocked"),
             PolymorphicThreats =make_list_if(strcat(format_datetime(Timestamp,'yyyy-M-dd H:mm:ss'), " : ", ActionType, " : ", FileName), ActionType in ("AsrUntrustedExecutableBlocked", "AsrUntrustedUsbProcessBlocked", "AsrRansomwareBlocked", "AsrVulnerableSignedDriverBlocked")) by DeviceId, DeviceName
 | extend Case = array_length(Email) + array_length(Script) + array_length(WMI) + array_length(OfficeApp) + array_length(3rdPartyApp) + array_length(WindowsCredentials) + array_length(PolymorphicThreats)
 | project DeviceId, DeviceName, Case, Email, Script, WMI, OfficeApp, 3rdPartyApp, WindowsCredentials, PolymorphicThreats
 | order by Case desc
```

#### Result 
![1692085121731](https://github.com/LearningKijo/KQL/assets/120234772/c8fbb62b-c668-4638-9d36-0b7de5a52fcd)



#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
