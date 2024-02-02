# TVM : Risky Browser Extensions List for Windows Device
The query displays all installed browser extensions categorized as 'Medium' or 'High' risk on devices.

# Prerequisites
Must have the license for TVM-Addon. E5/P2 is not sufficient.

#### Table name & Description
- [DeviceInfo](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceinfo-table?view=o365-worldwide) : Machine information, including OS information
- [DeviceTvmBrowserExtensions](https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-browser-extensions?view=o365-worldwide#use-advanced-hunting) : Details about the browser extensions installed per device 

```kusto
let ChromeExtensions = DeviceTvmBrowserExtensions
| where BrowserName == "chrome"
| where ExtensionRisk in ("Medium", "High")
| extend Risk = strcat("<", "Risk", " : ", ExtensionRisk, ">")
| extend Name = strcat("<", "Name", " : ", ExtensionName, ">")
| extend Version = strcat("<", "Version", " : ", ExtensionVersion, ">")
| extend ExtensionLists = strcat(Risk , " ", Name, " ", Version)
| summarize Chrome= make_set(ExtensionLists) by DeviceId
| extend Chrome_Case = array_length(Chrome)
| project DeviceId, Chrome_Case, Chrome;
let FireFoxExtensions = DeviceTvmBrowserExtensions
| where BrowserName == "firefox"
| where ExtensionRisk in ("Medium", "High")
| extend Risk = strcat("<", "Risk", " : ", ExtensionRisk, ">")
| extend Name = strcat("<", "Name", " : ", ExtensionName, ">")
| extend Version = strcat("<", "Version", " : ", ExtensionVersion, ">")
| extend ExtensionLists = strcat(Risk , " ", Name, " ", Version)
| summarize Firefox= make_set(ExtensionLists) by DeviceId
| extend Firefox_Case = array_length(Firefox)
| project DeviceId, Firefox_Case, Firefox;
let EdgeExtensions = DeviceTvmBrowserExtensions
| where BrowserName == "edge"
| where ExtensionRisk in ("Medium", "High")
| extend Risk = strcat("<", "Risk", " : ", ExtensionRisk, ">")
| extend Name = strcat("<", "Name", " : ", ExtensionName, ">")
| extend Version = strcat("<", "Version", " : ", ExtensionVersion, ">")
| extend ExtensionLists = strcat(Risk , " ", Name, " ", Version)
| summarize Edge= make_set(ExtensionLists) by DeviceId
| extend Edge_Case = array_length(Edge)
| project DeviceId, Edge_Case, Edge;
DeviceInfo 
| where OSPlatform contains "windows"
| summarize arg_max(Timestamp, *) by DeviceId, DeviceName
| join kind=leftouter ChromeExtensions on DeviceId
| join kind=leftouter FireFoxExtensions on DeviceId
| join kind=leftouter EdgeExtensions on DeviceId
| extend Case = coalesce(Edge_Case, 0) + coalesce(Chrome_Case, 0) + coalesce(Firefox_Case, 0)
| project DeviceName, DeviceId, OSPlatform, Case, Edge, Chrome, Firefox
| order by Case desc 
```

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
