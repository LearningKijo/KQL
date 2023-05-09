## KQL : externaldata IoCs threat hunting (WIP)

![image](https://user-images.githubusercontent.com/120234772/236630807-c8eb0d5b-7c7e-4688-b3c3-0001a8851c9f.png)

### Step 1

![image](https://user-images.githubusercontent.com/120234772/236631659-984e9f9e-a12c-41b5-a7df-93cc4973ced1.png)
> Mango Sandstorm, Microsoft Defender Threat Intelligence

## KQL : Hunting queries
```kql
// MangoSandstorm C2C IoCs by MDTI
let MangoSandstorm = externaldata(Type:string, Artifact:string)
[@'https://raw.githubusercontent.com/LearningKijo/KQL/main/KQL-Effective-Use/11-kql-MTDI-MangoSandstorm-IoCs.csv'] with (format='csv', ignorefirstrecord = true);
let Domains = (MangoSandstorm | where Type == "domain"| project Artifact);
let IPaddress = (MangoSandstorm | where Type == "ip"| project Artifact);
let URL = (MangoSandstorm | where Type == "url"| project Artifact);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (Domains) or RemoteUrl in (URL) or RemoteIP in (IPaddress) 
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```
![image](https://github.com/LearningKijo/KQL/assets/120234772/88350645-11ad-4d0b-a5ff-8994a5a5b5eb)


## Reference
[What’s New: MDTI Interoperability with Microsoft 365 Defender](https://techcommunity.microsoft.com/t5/microsoft-defender-threat/what-s-new-mdti-interoperability-with-microsoft-365-defender/ba-p/3799846)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.

