# TVM : MacOS AV config report
This query displays Microsoft Defender Antivirus configuration for MacOS.

#### Table name & Description
- [DeviceTvmSecureConfigurationAssessment](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessment-table?view=o365-worldwide) : Microsoft Defender Vulnerability Management assessment events, indicating the status of various security configurations on devices

```kusto
DeviceTvmSecureConfigurationAssessment
| where OSPlatform == "macOS" 
| where ConfigurationSubcategory == "Antivirus"
| where IsApplicable == 1
| where ConfigurationId in ('scid-5090', 'scid-5091', 'scid-5092', 'scid-5094', 'scid-5095')
| extend Test = case(
    ConfigurationId == "scid-5090", "Real-time protection",
    ConfigurationId == "scid-5091", "PUA protection",
    ConfigurationId == "scid-5092", "Tamper Protection",
    ConfigurationId == "scid-5094", "Cloud-delivered protection",
    ConfigurationId == "scid-5095", "Antivirus definitions",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName) by DeviceId
| evaluate bag_unpack(Tests)
```

**Note & Source**
```kusto
DeviceTvmSecureConfigurationAssessmentKB 
| where ConfigurationId in ('scid-5090', 'scid-5091', 'scid-5092', 'scid-5094', 'scid-5095')

//scid-5090, Turn on Microsoft Defender Antivirus real-time protection in macOS
//scid-5091, Turn on Microsoft Defender Antivirus PUA protection in block mode in macOS
//scid-5092, Turn on Tamper Protection for MacOS
//scid-5094, Enable Microsoft Defender Antivirus cloud-delivered protection in macOS
//scid-5095, Update Microsoft Defender Antivirus definitions in macOS
```

#### Reference
1. [Endpoint Agent Health Status Report](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/Endpoint%20Agent%20Health%20Status%20Report.md)
2. [Endpoint AV version report](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/MD%20AV%20Signature%20and%20Platform%20Version.md)

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.