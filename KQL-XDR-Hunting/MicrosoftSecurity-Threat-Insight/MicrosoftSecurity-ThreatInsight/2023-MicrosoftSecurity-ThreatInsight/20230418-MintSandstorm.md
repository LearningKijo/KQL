# Nation-state threat actor Mint Sandstorm refines tradecraft to attack high-value targets
### Who is Mint Sandstorm?
Mint Sandstorm is Microsoft’s new name for PHOSPHORUS, an Iranian nation-state actor. 
This new name is part of the new threat actor naming taxonomy we announced today, designed to keep pace with the evolving and growing threat landscape.

Mint Sandstorm is known to pursue targets in both the private and public sectors, including political dissidents, activist leaders, the Defense Industrial Base (DIB), journalists, and employees from multiple government agencies, including individuals protesting oppressive regimes in the Middle East. Activity Microsoft tracks as part of the larger Mint Sandstorm group overlaps with public reporting on groups known as APT35, APT42, Charming Kitten, and TA453.

Mint Sandstorm is a composite name used to describe several subgroups of activity with ties to the same organizational structure. 
Microsoft assesses that Mint Sandstorm is associated with an intelligence arm of Iran’s military, the Islamic Revolutionary Guard Corps (IRGC), an assessment that has been corroborated by multiple credible sources including Mandiant, Proofpoint, and SecureWorks.  
In 2022, the US Department of Treasury sanctioned elements of Mint Sandstorm for past cyberattacks citing sponsorship from the IRGC.

Today, Microsoft is reporting on a distinct Mint Sandstorm subgroup that specializes in hacking into and stealing sensitive information from high-value targets. 
This Mint Sandstorm subgroup is technically and operationally mature, capable of developing bespoke tooling and quickly weaponizing N-day vulnerabilities, and has demonstrated agility in its operational focus, which appears to align with Iran’s  national priorities.

## Advanced hunting queries
ManageEngine Suspicious Process Execution
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName hasprefix "java"
| where InitiatingProcessFolderPath  has @"\manageengine\" or InitiatingProcessFolderPath has @"\ServiceDesk\"
| where (FileName in~ ("powershell.exe", "powershell_ise.exe") and
        (ProcessCommandLine has_any ("whoami", "net user", "net group", "localgroup administrators", "dsquery", "samaccountname=", " echo ", "query session", "adscredentials", "o365accountconfiguration", "-dumpmode", "-ssh", "usoprivate", "usoshared", "Invoke-Expression", "DownloadString", "DownloadFile", "FromBase64String",  "System.IO.Compression", "System.IO.MemoryStream", "iex ", "iex(", "Invoke-WebRequest", "set-MpPreference", "add-MpPreference", "certutil", "bitsadmin") // "csvhost.exe", "ekern.exe", "svhost.exe", ".dmp" or ProcessCommandLine matches regex @"[-/–][Ee^]{1,2}[ncodema^]*\s[A-Za-z0-9+/=]{15,}"))
           or (FileName =~ "curl.exe" and ProcessCommandLine contains "http")
           or (FileName =~ "wget.exe" and ProcessCommandLine contains "http")
           or ProcessCommandLine has_any ("E:jscript", "e:vbscript")
           or ProcessCommandLine has_all ("localgroup Administrators", "/add")
           or ProcessCommandLine has_all ("reg add", "DisableAntiSpyware", @"\Microsoft\Windows Defender")
           or ProcessCommandLine has_all ("reg add", "DisableRestrictedAdmin", @"CurrentControlSet\Control\Lsa")
           or ProcessCommandLine has_all ("wmic", "process call create")
           or ProcessCommandLine has_all ("net", "user ", "/add")
           or ProcessCommandLine has_all ("net1", "user ", "/add")
           or ProcessCommandLine has_all ("vssadmin", "delete", "shadows")
           or ProcessCommandLine has_all ("wmic", "delete", "shadowcopy")
           or ProcessCommandLine has_all ("wbadmin", "delete", "catalog")
           or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("procdump", "tasklist", "findstr"))
 | where ProcessCommandLine !contains "download.microsoft.com" and ProcessCommandLine !contains "manageengine.com" and ProcessCommandLine !contains "msiexec"
```

Ruby AsperaFaspex Suspicious Process Execution
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName hasprefix "ruby"
| where InitiatingProcessFolderPath has @"aspera"
| where (FileName in~ ("powershell.exe", "powershell_ise.exe") and
        (ProcessCommandLine has_any ("whoami", "net user", "net group", "localgroup administrators", "dsquery", "samaccountname=", " echo ", "query session", "adscredentials", "o365accountconfiguration", "-dumpmode", "-ssh", "usoprivate", "usoshared", "Invoke-Expression", "DownloadString", "DownloadFile", "FromBase64String",  "System.IO.Compression", "System.IO.MemoryStream", "iex ", "iex(", "Invoke-WebRequest", "set-MpPreference", "add-MpPreference", "certutil", "bitsadmin", "csvhost.exe", "ekern.exe", "svhost.exe", ".dmp") or ProcessCommandLine matches regex @"[-/–][Ee^]{1,2}[ncodema^]*\s[A-Za-z0-9+/=]{15,}"))
           or (FileName =~ "curl.exe" and ProcessCommandLine contains "http")
           or (FileName =~ "wget.exe" and ProcessCommandLine contains "http")
           or ProcessCommandLine has_any ("E:jscript", "e:vbscript")
           or ProcessCommandLine has_all ("localgroup Administrators", "/add")
           or ProcessCommandLine has_all ("reg add", "DisableAntiSpyware", @"\Microsoft\Windows Defender")
           or ProcessCommandLine has_all ("reg add", "DisableRestrictedAdmin", @"CurrentControlSet\Control\Lsa")
           or ProcessCommandLine has_all ("wmic", "process call create")
           or ProcessCommandLine has_all ("net", "user ", "/add")
           or ProcessCommandLine has_all ("net1", "user ", "/add")
           or ProcessCommandLine has_all ("vssadmin", "delete", "shadows")
           or ProcessCommandLine has_all ("wmic", "delete", "shadowcopy")
           or ProcessCommandLine has_all ("wbadmin", "delete", "catalog")
           or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("procdump", "tasklist", "findstr"))
```

Log4J Wstomcat Process Execution
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName has "ws_tomcatservice.exe" and FileName !in~("repadmin.exe")
```

Encoded watcher Function
```kusto
DeviceProcessEvents 
| where FileName =~ "powershell.exe" and ProcessCommandLine hasprefix "-e"
| extend SplitString = split(ProcessCommandLine, " ")
| mvexpand SS = SplitString 
| where SS matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend base64_decoded = replace(@'\0', '', make_string(base64_decode_toarray(tostring(SS))))
| where not(base64_decoded has_any(@"software\checker", "set folder to watch"))
| where base64_decoded has_all("$hst", "$prt") or base64_decoded has_any("watcher", @"WAt`CH`Er()")
```

## Microsoft Security Blog
April 18, 2023, [Nation-state threat actor Mint Sandstorm refines tradecraft to attack high-value targets](https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
