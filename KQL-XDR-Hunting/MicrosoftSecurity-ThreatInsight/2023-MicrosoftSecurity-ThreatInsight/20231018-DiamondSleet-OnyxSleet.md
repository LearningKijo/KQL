# Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability
Since October 2023, Microsoft has identified two North Korean threat actors, Diamond Sleet and Onyx Sleet, exploiting a remote-code execution vulnerability in JetBrains TeamCity server used for DevOps. These actors pose a high risk due to past successful software supply chain attacks. JetBrains released an update, and Microsoft advises affected organizations to apply it. Despite exploiting the same vulnerability, the threat actors use unique tools and techniques. Microsoft suspects opportunistic compromises of vulnerable servers, with both actors deploying malware and employing methods for persistent access. The company actively notifies and supports affected customers to secure their environments.
> 👉 October 18, 2023, [Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability](https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/)

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
