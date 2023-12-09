# MDE : URL IoCs Bypass on Edge & 3rd Party Browsers
This query displays MDE Indicator 'Warn' activity, where the IoC prompts a warning that users can bypass, on both Edge and 3rd party browsers over the past 7 days.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) :	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("SmartScreenUserOverride", "NetworkProtectionUserBypassEvent")
| extend Browser = case(
         InitiatingProcessFileName has "msedge", "Edge",
         InitiatingProcessFileName has "chrome", "Chrome", 
         InitiatingProcessFileName has "firefox", "Firefox",
         InitiatingProcessFileName has "opera", "Opera",
"Other 3rd party browser")
| project Timestamp, DeviceId, DeviceName, ActionType, Browser, RemoteUrl
```

> [!Important]
> In DeviceNetworkEvents, URLs may appear as ***'ConnectionSuccess'***, but this is the expected result due to the three-way handshake that occurs before an IoC, such as blocking a URL.
> Technically, end users were blocked from accessing the URL, even if the record shows ***'ConnectionSuccess'***.
> MS docs : [IP/URL Indicators: Network protection and the TCP three-way handshake](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-indicators?view=o365-worldwide#ipurl-indicators-network-protection-and-the-tcp-three-way-handshake)

#### Result 
![image](https://github.com/LearningKijo/KQL/assets/120234772/a1983cde-5645-497e-82d4-8bf4689e2e6f)


#### URL IoCs Bypass 
e.g. Warn – the IoC prompts a warning that the user can bypass
![image](https://github.com/LearningKijo/KQL/assets/120234772/4d05e6a3-520f-4e1f-99bf-978e40321842)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
