# Cadet Blizzard emerges as a novel and distinct Russian threat actor
Microsoft assesses that Cadet Blizzard operations are associated with the Russian General Staff Main Intelligence Directorate (GRU) but are separate from other known and more established GRU-affiliated groups such as Forest Blizzard (STRONTIUM) and Seashell Blizzard (IRIDIUM). 
While Microsoft constantly tracks a number of activity groups with varying degrees of Russian government affiliation, the emergence of a novel GRU affiliated actor, particularly one which has conducted destructive cyber operations likely supporting broader military objectives in Ukraine, is a notable development in the Russian cyber threat landscape. 
A month before Russia invaded Ukraine, Cadet Blizzard foreshadowed future destructive activity when it created and deployed WhisperGate, a destructive capability that wipes Master Boot Records (MBRs), against Ukrainian government organizations. 
Cadet Blizzard is also linked to the defacements of several Ukrainian organization websites, as well as multiple operations, including the hack-and-leak forum known as “Free Civilian”.

## Advanced hunting queries
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
