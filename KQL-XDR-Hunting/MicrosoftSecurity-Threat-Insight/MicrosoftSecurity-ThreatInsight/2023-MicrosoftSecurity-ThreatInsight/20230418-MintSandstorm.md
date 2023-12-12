# Nation-state threat actor Mint Sandstorm refines tradecraft to attack high-value targets

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
