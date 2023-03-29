# KQL : XDR Custom Detection Rule with NRT
A custom detection rule in Microsoft 365 Defender is a way to create a specific rule that detects certain types of threats or activities that are unique to your organization. You can configure these rules to trigger alerts or other actions when a specific condition is met, which can help improve your organization's security. Essentially, it allows you to tailor the detection capabilities of Microsoft 365 Defender to meet the specific needs of your organization.

Recently, there was an update about the rule frequency - **Near-Real-Time(NRT)** and I will cover how to use the detection rule with NRT in this article.

#### Reference
1. [Create and manage custom detection rules in Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide)
2. [Respond to threats in near real-time with custom XDR detections](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/respond-to-threats-in-near-real-time-with-custom-detections/ba-p/3761243)



## KQL : Hunting queries
```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "audited"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```
```kql
DeviceEvents
| where Timestamp > ago(5m)
| where ActionType startswith "asr" and ActionType endswith "blocked"
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath
```
## Config : Custom Detection Rule NRT
To configure a custom detection rule in the Microsoft 365 Defender portal, select [Continuous (NRT)](https://learn.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide) to try NRT.

![image](https://user-images.githubusercontent.com/120234772/228133466-69fb1e17-c5f2-4130-ba27-3562ce119c40.png)
> Custom detection rule with NRT

![image](https://user-images.githubusercontent.com/120234772/228149676-e2ac0076-f004-46af-8d6b-7845f6d46830.png)
> Custom detection rule list - ASR audit / block
 
## Alerts : Custom Detection Rule NRT

![image](https://user-images.githubusercontent.com/120234772/228417777-ecde3e84-acdb-4c96-be8b-59cf826b7815.png)
> Generated alert by custom detection rule

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
