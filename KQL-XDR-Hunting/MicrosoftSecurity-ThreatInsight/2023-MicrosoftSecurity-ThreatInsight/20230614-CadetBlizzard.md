# Cadet Blizzard emerges as a novel and distinct Russian threat actor

Microsoft has identified a new Russian cyber threat group called Cadet Blizzard, associated with the GRU. Operating separately from other GRU-affiliated groups, Cadet Blizzard has conducted destructive cyber operations supporting military objectives in Ukraine. Microsoft has been tracking them since January 2022, noting their activities since at least 2020. Cadet Blizzard engages in focused attacks, including hack-and-leak operations, primarily targeting Ukrainian government and IT sectors. Microsoft collaborates with CERT-UA and global partners to address the threat, urging organizations to take preventive measures. The blog provides insights on detection and prevention against Cadet Blizzard.
> 👉 June 14, 2023, [Cadet Blizzard emerges as a novel and distinct Russian threat actor](https://www.microsoft.com/en-us/security/blog/2023/06/14/cadet-blizzard-emerges-as-a-novel-and-distinct-russian-threat-actor/)

## Advanced hunting queries
***Microsoft 365 Defender : Microsoft 365 Defender customers can run the following query to find related activity in their networks:***

Check for WMIExec Impacket activity with common Cadet Blizzard commands
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe" and FileName =~ "cmd.exe"
| where ProcessCommandLine matches regex "2>&1"
| where ProcessCommandLine has_any ("get-volume","systeminfo","reg.exe","downloadfile","nslookup","query session","route print")
```

Find PowerShell file downloads
```kusto
DeviceProcessEvents
| where FileName == "powershell.exe" and ProcessCommandLine has "DownloadFile"
```

Scheduled task creation, command execution and C2 communication
```kusto
DeviceProcessEvents 
| where Timestamp  > ago(14d) 
| where FileName =~ "schtasks.exe"  
| where (ProcessCommandLine  contains "splservice" or ProcessCommandLine contains "spl32") and 
(ProcessCommandLine contains "127.0.0.1" or ProcessCommandLine contains "2>&1")
```

## Microsoft Security Blog
June 14, 2023, [Cadet Blizzard emerges as a novel and distinct Russian threat actor](https://www.microsoft.com/en-us/security/blog/2023/06/14/cadet-blizzard-emerges-as-a-novel-and-distinct-russian-threat-actor/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
