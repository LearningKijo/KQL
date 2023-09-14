# Malware distributor Storm-0324 facilitates ransomware access


### Possible TeamsPhisher downloads

The following query looks for downloaded files that were potentially facilitated by use of the TeamsPhisher tool. Defenders should customize the SharePoint domain name (‘mysharepointname’) in the query.

```powershell
let allowedSharepointDomain = pack_array(
'mysharepointname' //customize Sharepoint domain name and add more domains as needed for your query
);
let executable = pack_array(
'exe',
'dll',
'xll',
'msi',
'application'
);
let script = pack_array(
'ps1',
'py',
'vbs',
'bat'
);
let compressed = pack_array(
'rar',
'7z',
'zip',
'tar',
'gz'
);
let startTime = ago(1d);
let endTime = now();
DeviceFileEvents
| where Timestamp between (startTime..endTime)
| where ActionType =~ 'FileCreated'
| where InitiatingProcessFileName has 'teams.exe'
    or InitiatingProcessParentFileName has 'teams.exe'
| where InitiatingProcessFileName !has 'update.exe'
    and InitiatingProcessParentFileName !has 'update.exe'
| where FileOriginUrl has 'sharepoint'
    and FileOriginReferrerUrl has_any ('sharepoint', 'teams.microsoft')
| extend fileExt = tolower(tostring(split(FileName,'.')[-1]))
| where fileExt in (executable)
    or fileExt in (script)
    or fileExt in (compressed)
| extend fileGroup = iff( fileExt in (executable),'executable','')
| extend fileGroup = iff( fileExt in (script),'script',fileGroup)
| extend fileGroup = iff( fileExt in (compressed),'compressed',fileGroup)
| extend sharePoint_domain = tostring(split(FileOriginUrl,'/')[2])
| where not (sharePoint_domain has_any (allowedSharepointDomain))
| project-reorder Timestamp, DeviceId, DeviceName, sharePoint_domain, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl
```
> Reference : [Malware distributor Storm-0324 facilitates ransomware access](https://www.microsoft.com/en-us/security/blog/2023/09/12/malware-distributor-storm-0324-facilitates-ransomware-access/)

### Key findings & Insights 
After simulating phishing messages using TeamsPhisher, I attempted to fetch raw data through Advanced Hunting in Microsoft 365 Defender.
However, based on the test, the provided KQL query doesn't consistently capture potential TeamsPhisher activities. There are some reasons. 
Firstly,  ActionType was defined as 'FileCreated,' but I observed other ActionTypes scenarios as well, such as 'FileRenamed' and 'FileModified.' 
Additionally, it's true that this attack often starts from Teams. Consequently, the initial KQL query was constructed with 'InitiatingProcessFileName has 'teams.exe'' or 'InitiatingProcessParentFileName has 'teams.exe,'' but most of the time, these processes were browser-related, like 'msedge.exe' and 'chrome.exe.' 
As a result, I edited the original KQL query slightly.

```powershell
let allowedSharepointDomain = pack_array(
'mysharepointname' //customize Sharepoint domain name and add more domains as needed for your query
);
let executable = pack_array(
'exe',
'dll',
'xll',
'msi',
'application'
);
let script = pack_array(
'ps1',
'py',
'vbs',
'bat'
);
let compressed = pack_array(
'rar',
'7z',
'zip',
'tar',
'gz'
);
let startTime = ago(1d);
let endTime = now();
DeviceFileEvents
| where Timestamp between (startTime..endTime)
| where FileOriginUrl has 'sharepoint'
    and FileOriginReferrerUrl has_any ('sharepoint', 'teams.microsoft')
| extend fileExt = tolower(tostring(split(FileName,'.')[-1]))
| where fileExt in (executable)
    or fileExt in (script)
    or fileExt in (compressed)
| extend fileGroup = iff( fileExt in (executable),'executable','')
| extend fileGroup = iff( fileExt in (script),'script',fileGroup)
| extend fileGroup = iff( fileExt in (compressed),'compressed',fileGroup)
| extend sharePoint_domain = tostring(split(FileOriginUrl,'/')[2])
| where not (sharePoint_domain has_any (allowedSharepointDomain))
| project-reorder Timestamp, DeviceId, DeviceName, sharePoint_domain, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
