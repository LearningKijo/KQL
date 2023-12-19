# PsExec.exe usage
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

The actor used PsExec.exe to spread the ransomware on the victims' network. 
The actor first executed "open.bat", which executed "net share [C-Z]=[C-Z]:\ /grant:everyone,FULL". 
This shared every drive on the host, granting access to everyone. "A.exe", "Anet.exe", and "Aus.exe" are all variants of the Cuba ransomware.

#### PsExec.exe usage

```kusto
DeviceProcessEvents
| where InitiatingProcessCommandLine contains "psexe"
| distinct ProcessCommandLine
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.