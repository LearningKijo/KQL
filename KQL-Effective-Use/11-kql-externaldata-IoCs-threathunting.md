## KQL : externaldata IoCs threat hunting 
Using KQL's 'externaldata' operator is highly effective for hunting suspicious activities with IoCs. 
Therefore, today I would like to showcase how we can leverage externaldata with Microsoft Defender Threat Intelligence (MDTI).

Additionally, I have summarized the process into three steps for leveraging external data to track Mango Sandstorm activities

![image](https://user-images.githubusercontent.com/120234772/236630807-c8eb0d5b-7c7e-4688-b3c3-0001a8851c9f.png)

### Step 1
At first, collect Mango Sandstorm IoCs in MDTI and import them as a CSV file.

![image](https://user-images.githubusercontent.com/120234772/236631659-984e9f9e-a12c-41b5-a7df-93cc4973ced1.png)
> Mango Sandstorm, Microsoft Defender Threat Intelligence

### Step 2
Next, upload it to an external storage such as GitHub.
```
https://raw.githubusercontent.com/LearningKijo/KQL/main/KQL-Effective-Use/11-kql-MTDI-MangoSandstorm-IoCs.csv
```

![image](https://github.com/LearningKijo/KQL/assets/120234772/7d9f3d7b-ade7-414a-881b-904aa9be11cc)

### Step 3

Lastly, use the 'externaldata' operator to hunt Mango Sandstorm activities in Microsoft 365 Defender.

![image](https://github.com/LearningKijo/KQL/assets/120234772/4b38f341-41f3-45c7-8782-e8d6e6ad9dac)
> Advanced Hunting page, Microsoft 365 Defender portal

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

