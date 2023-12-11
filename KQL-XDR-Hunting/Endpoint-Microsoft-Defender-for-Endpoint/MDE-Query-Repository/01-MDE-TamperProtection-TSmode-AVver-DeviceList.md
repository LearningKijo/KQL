# TamperProtection & Troubleshooting mode - Device List
This query displays 1) ***Tamper Protection status***, 2) ***Troubleshooting Mode*** status and 3) ***Defender Antivirus versions*** for each device over the past 7 days.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection
- [DeviceTvmSecureConfigurationAssessment](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessment-table?view=o365-worldwide) : Microsoft Defender Vulnerability Management assessment events, indicating the status of various security configurations on devices

```kusto
// TroubleshootMode Status
let TroubleshootMode = (DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusTroubleshootModeEvent"
| extend Parsed = parse_json(AdditionalFields)
| where Parsed.TroubleshootingStateChangeReason == "Troubleshooting mode started"
| extend StartTime = todatetime(Parsed.TroubleshootingStartTime)
| extend EndTime = todatetime(Parsed.TroubleshootingStateExpiry)
| extend CurrentTime = now()
| extend TroubleshootMode_Status = iff(CurrentTime > todatetime(EndTime), "Inactive", "Active")
| summarize arg_max(Timestamp, *) by DeviceId 
| project Timestamp, DeviceId, DeviceName, TroubleshootMode_Status, StartTime, EndTime);
// Microsoft Defender Antivirus versions 
// Some AV versions are prerequisites for using MDE Troubleshooting Mode
let AV_versions = (DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVSigVersion = tostring(avdata[0][0])
| extend AVEngineVersion = tostring(avdata[0][1])
| extend AVSigLastUpdateTime = tostring(avdata[0][2])
| extend AVProductVersion = tostring(avdata[0][3]) 
| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion, IsCompliant, IsApplicable);
let AV_config =(DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ('scid-2010', 'scid-2012')
| extend Test = case(
         ConfigurationId == "scid-2010", "AntivirusEnabled",
         ConfigurationId == "scid-2012", "RealtimeProtection",
         "N/A"),
         Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "Enable", "Disable")
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName) by DeviceId
| evaluate bag_unpack(Tests));
// MDE TamperProtection Status
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2003"
| extend TamperProtection_State = iff(IsCompliant == 1, "Active", "Inactive")
| summarize arg_max(Timestamp, *) by DeviceId
| join kind=leftouter TroubleshootMode on DeviceId
| join kind=leftouter AV_versions on DeviceId
| join kind=leftouter AV_config on DeviceId
| extend TamperProtectionTime = Timestamp
| project DeviceId, DeviceName, TamperProtection_State, TamperProtectionTime, TroubleshootMode_Status, StartTime, EndTime, AntivirusEnabled, RealtimeProtection, AVProductVersion, AVEngineVersion, AVSigVersion, AVSigLastUpdateTime
```

#### <Result>

#### Reference
1. [Endpoint Agent Health Status Report](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/Endpoint%20Agent%20Health%20Status%20Report.md)
2. [Endpoint AV version report](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/MD%20AV%20Signature%20and%20Platform%20Version.md)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
