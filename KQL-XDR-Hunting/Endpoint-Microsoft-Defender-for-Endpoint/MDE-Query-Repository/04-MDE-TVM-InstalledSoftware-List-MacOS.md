# TVM : Installed Software List for MacOS Device
This query displays a list of all installed software on MacOS devices.

#### Table name & Description
- [DeviceTvmSoftwareInventory](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareinventory-table?view=o365-worldwide) : Inventory of software installed on devices, including their version information and end-of-support status

```kusto
DeviceTvmSoftwareInventory
| where OSPlatform == "macOS"
| extend SoftwareName = strcat("<", "Name", " : ", SoftwareName, ">")
| extend SoftwareVersion = strcat("<", "Version", " : ", SoftwareVersion, ">")
| extend SoftwareInfo = strcat(SoftwareName, " ", SoftwareVersion)
| summarize Installed_Software = make_set(SoftwareInfo) by DeviceName, DeviceId, OSPlatform, OSVersion
| extend Installed_Software_Case = array_length(Installed_Software)
| project DeviceId, DeviceName, OSPlatform, OSVersion, Installed_Software_Case, Installed_Software
| order by Installed_Software_Case desc 
```

#### <Result>

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.