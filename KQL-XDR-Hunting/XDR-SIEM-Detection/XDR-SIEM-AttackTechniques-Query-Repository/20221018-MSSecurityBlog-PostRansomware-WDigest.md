# WDigest credential harvesting
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

**WDigest**

The actor abused WDigest to cache credentials early in the compromise. This enabled the actor to gain access to domain administrator credentials.

WDigest is a Windows feature that when enabled, caches credentials in clear text. This is often abused by credential access tools, such as Mimikatz. 
To detect if WDigest has been enabled within your network, the registry key HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential will be set to 1. This can be disabled by setting the value to 0.

#### WDigest credential harvesting
Find attempts to turn on WDigest credential caching
```kusto
DeviceRegistryEvents
| where Timestamp  > ago(7d)
| where RegistryKey contains "wdigest" and RegistryValueName == "UseLogonCredential" and RegistryValueData == "1"
| project Timestamp, DeviceId, DeviceName, PreviousRegistryValueData, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
Find processes created with commandlines that attempt to turn on WDigest caching
```kusto
DeviceProcessEvents
| where Timestamp  > ago(7d)
| where ProcessCommandLine has "WDigest" and ProcessCommandLine has "UseLogonCredential" and ProcessCommandLine has "dword" and ProcessCommandLine has "1"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, ProcessCommandLine     
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
