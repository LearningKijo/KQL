#  Possible Impacket (WMI) module usage
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

Impacket's WMI modules were used throughout the early stages of the compromise for remote execution and discovery. 
Impacket is an open-source collection of scripts for working with network protocols. 
This toolkit has recently been used by a large variety of crimeware groups for lateral movement and network discovery.

The actor used Impacket to execute PowerShell scripts out of "C:\Perflogs\", which created .txt files within the same directory. 
All commands executed through Impacket output the results of the command to "\\127.0.0.1\ADMIN$\__1648051380.61". 
The actor then deleted the PowerShell scripts and text files after execution.

The actor also used Impacket to test if the destination server was able to ping the actor's C2 before deploying Cobalt Strike to the device.
#### Possible Impacket (WMI) module usage

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreatedUsingWmiQuery" 
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "/Q /c"
| project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessParentFileName == "WmiPrvSE.exe"
| where InitiatingProcessFolderPath has "cmd.exe"
| where InitiatingProcessCommandLine contains "/Q /c"
| project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)
- August 31, 2022, [Defense Against the Lateral Arts: Detecting and Preventing Impacket’s Wmiexec](https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.