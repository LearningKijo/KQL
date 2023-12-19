# PuTTY Secure Copy usage
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

The actor used PuTTY Secure Copy (PSCP) to remotely exfiltrate network shares to an actor controlled C2. 
This version of PSCP had been renamed to “lsas.exe” in an attempt to masquerade itself as the legitimate “lsass.exe” service. 
PSCP was executed out of C:\Windows\Temp. The actor targeted Staff and Financial related resources.

#### PsExec.exe usage

```kusto
DeviceProcessEvents
| where FileName == "lsas.exe"
| project ProcessCommandLine
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
