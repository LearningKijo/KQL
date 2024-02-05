# Flax Typhoon using legitimate software to quietly access Taiwanese organizations
Microsoft has identified a distinct pattern of malicious activity primarily affecting organizations in Taiwan, attributed to Flax Typhoon, a Chinese nation-state actor (overlapping with ETHEREAL PANDA). The campaign involves espionage and maintaining access across various industries. Although no final objectives have been observed, Microsoft highlights the concern for potential impact on customers. The blog aims to raise community awareness and enhance protection measures. The threat relies on valid accounts and living-off-the-land binaries, making detection and mitigation challenging. Recommendations include closing or changing compromised accounts, isolating and investigating compromised systems. Microsoft 365 Defender is equipped to detect such stealthy attacks, and the blog provides additional mitigation steps and best practices.
> 👉 August 24, 2023, [Flax Typhoon using legitimate software to quietly access Taiwanese organizations](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/)

## Advanced hunting queries
***Microsoft 365 Defender : Microsoft 365 Defender customers can run the following queries to find related activity in their networks:***

Network activity with Flax Typhoon network infrastructure
```kusto
let ipAddressTimes = datatable(ip: string, startDate: datetime, endDate: datetime)
[
    "101.33.205.106", datetime("2022-11-07"), datetime("2022-11-08"),
    "39.98.208.61", datetime("2023-07-28"), datetime("2023-08-12"),
    "45.195.149.224", datetime("2023-01-04"), datetime("2023-03-29"),
    "122.10.89.230", datetime("2023-01-12"), datetime("2023-01-13"),
    "45.204.1.248", datetime("2023-02-23"), datetime("2023-05-09"),
    "45.204.1.247", datetime("2023-07-24"), datetime("2023-08-10"),
    "45.88.192.118", datetime("2022-11-07"), datetime("2022-11-08"),
    "154.19.187.92", datetime("2022-12-01"), datetime("2022-12-02"),
    "134.122.188.20", datetime("2023-06-13"), datetime("2023-06-20"),
    "104.238.149.146", datetime("2023-07-13"), datetime("2023-07-14"),
    "139.180.158.51", datetime("2022-08-30"), datetime("2023-07-27"),
    "137.220.36.87", datetime("2023-02-23"), datetime("2023-08-04"),
    "192.253.235.107", datetime("2023-06-06"), datetime("2023-06-07")
];
let RemoteIPFiltered = DeviceNetworkEvents
    | join kind=inner (ipAddressTimes) on $left.RemoteIP == $right.ip
    | where Timestamp between (startDate .. endDate);
let LocalIPFiltered = DeviceNetworkEvents
    | join kind=inner (ipAddressTimes) on $left.LocalIP == $right.ip
    | where Timestamp between (startDate .. endDate);
union RemoteIPFiltered, LocalIPFiltered
```

SoftEther VPN bridge launched by SQL Server process
```kusto
DeviceProcessEvents 
| where ProcessVersionInfoOriginalFileName == "vpnbridge.exe" or ProcessVersionInfoFileDescription == "SoftEther VPN"  
| where InitiatingProcessParentFileName == "sqlservr.exe"
```

SoftEther VPN bridge renamed to “conhost.exe” or “dllhost.exe”
```kusto
DeviceProcessEvents 
| where ProcessVersionInfoOriginalFileName == "vpnbridge.exe" or ProcessVersionInfoFileDescription == "SoftEther VPN"  
| where ProcessCommandLine has_any ("conhost.exe", "dllhost.exe") or FolderPath has_any ("mssql", "conhost.exe", "dllhost.exe")
```

Certutil launched by SQL Server process
```kusto
DeviceProcessEvents 
| where ProcessCommandLine has_all ("certutil", "-urlcache") 
| where InitiatingProcessFileName has_any ("sqlservr.exe", "sqlagent.exe", "sqlps.exe", "launchpad.exe", "sqldumper.exe")

```

File downloaded by MSSQLSERVER account using certutil
```kusto
DeviceFileEvents 
| where InitiatingProcessAccountName == "MSSQLSERVER"  
| where InitiatingProcessFileName == "certutil.exe"
```

File renamed to “conhost.exe” or “dllhost.exe”, downloaded using certutil
```kusto
DeviceFileEvents 
| where InitiatingProcessFileName == "certutil.exe" 
| where FileName in ("conhost.exe", "dllhost.exe") 
```

Network connection made by SoftEther VPN bridge renamed to “conhost.exe” or “dllhost.exe”
```kusto
DeviceNetworkEvents 
| where InitiatingProcessVersionInfoOriginalFileName == "vpnbridge.exe" or InitiatingProcessVersionInfoProductName == "SoftEther VPN" 
| where InitiatingProcessFileName == "conhost.exe"
```

Network connection made by MSSQLSERVER account, using SoftEther VPN bridge
```kusto
DeviceNetworkEvents 
| where InitiatingProcessVersionInfoOriginalFileName == "vpnbridge.exe" or InitiatingProcessVersionInfoProductName == "SoftEther VPN" 
| where InitiatingProcessAccountName == "MSSQLSERVER"
```

## Microsoft Security Blog
August 24, 2023, [Flax Typhoon using legitimate software to quietly access Taiwanese organizations](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
