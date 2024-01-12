# Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability
Since early October 2023, Microsoft has observed two North Korean nation-state threat actors – Diamond Sleet and Onyx Sleet – exploiting CVE-2023-42793, a remote-code execution vulnerability affecting multiple versions of JetBrains TeamCity server. 
TeamCity is a continuous integration/continuous deployment (CI/CD) application used by organizations for DevOps and other software development activities.

## Advanced hunting queries
Command and control using iexpress.exe or wksprt.exe
```kusto
DeviceNetworkEvents
| where (InitiatingProcessFileName =~ "wksprt.exe" and InitiatingProcessCommandLine == "wksprt.exe") 
or (InitiatingProcessFileName =~ "iexpress.exe" and InitiatingProcessCommandLine == "iexpress.exe")
```

Search order hijack using Wsmprovhost.exe and DSROLE.dll
```kusto
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where FileName =~ "DSROLE.dll"
| where not(FolderPath has_any("system32", "syswow64"))
```

Search order hijack using clip.exe and Version.dll
```kusto
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "clip.exe"
| where FileName in~("version.dll")
| where not(FolderPath has_any("system32", "syswow64", "program files", "windows defender\\platform", "winsxs", "platform",
"trend micro"))
```

## Microsoft Security Blog
October 18, 2023, [Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability](https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
