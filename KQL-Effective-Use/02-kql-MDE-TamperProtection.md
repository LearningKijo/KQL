# KQL : Tamper Protection 
Tamper Protection is a security feature in Microsoft Defender Antivirus that helps prevent unauthorized changes to security settings and software. It works by preventing other programs, including malware, from modifying critical security features, files, and settings in the Windows operating system. Therefore, in this section, I am going to share testing commands and hunting queries

> **Note** : Tamper Protection mainly works for Microsoft Defender Antivirus. In the case of Microsoft Defender for Endpoint, there is a built-in protection for the EDR sensor that prevents security features from being disabled.



## Microsoft Security blog

- [Make sure Tamper Protection is turned on](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/make-sure-tamper-protection-is-turned-on/ba-p/2695568)
- [When coin miners evolve, Part 1: Exposing LemonDuck and LemonCat, modern mining malware infrastructure](https://www.microsoft.com/en-us/security/blog/2021/07/22/when-coin-miners-evolve-part-1-exposing-lemonduck-and-lemoncat-modern-mining-malware-infrastructure/)
- [When coin miners evolve, Part 2: Hunting down LemonDuck and LemonCat attacks](https://www.microsoft.com/en-us/security/blog/2021/07/29/when-coin-miners-evolve-part-2-hunting-down-lemonduck-and-lemoncat-attacks/)

![image](https://user-images.githubusercontent.com/120234772/223905380-596a4966-d2d8-4340-ae7c-5263ecac5580.png)
> Figure 1. LemonDuck attack chain from the Duck and Cat infrastructures

## Test command
The testing commands are not only for ***Microsoft Defender Antivirus***, but also for ***Microsoft Defender for Endpoint***.

**PowerShell Cmdlets**

```PowerShell
# Microsoft Defender Antivirus
PS : Set-MpPreference -DisableRealtimeMonitoring $true
PS : Set-MpPreference -DisableBlockAtFirstSeen $true
PS : Set-MpPreference -SubmitSamplesConsent 2
PS : Stop-Service -Name "WinDefend"
PS : Stop-Process -Name "MsMpEng"
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Microsoft Defender for Endpoint
PS : Stop-Service -Name "Sense"
PS : Stop-Process -Name "MsSense"
```
**Windows Commands**
```cmd
:: Microsoft Defender Antivirus
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
Cmd : sc stop WinDefend
Cmd : sc config "WinDefend" start= disabled
Cmd : net stop WinDefend
Cmd : reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

:: Microsoft Defender for Endpoint
Cmd : sc stop Sense
Cmd : net stop Sense 
```

## KQL : Hunting queries 
1. Counts how many times 'TamperingAttempt' happened to each device.
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "TamperingAttempt"
| summarize TamperingAttempt = count() by DeviceId, DeviceName
```
2. Counts how many times 'TamperingAttempt' occurred and indicates which registry value impacted each device.
```kql

DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "TamperingAttempt"
| summarize Registry_Value = make_list(RegistryValueName) by DeviceId, DeviceName
```

3. Hunt for registry key activities for Microsoft Defender Antivirus.
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
| project-reorder Timestamp, DeviceId, DeviceName, ActionType, RegistryKey, RegistryValueType, RegistryValueName, RegistryValueData
| sort by Timestamp desc 
```

4. Hunt for disabling activities for Microsoft Defender Antivirus and Microsoft Defender for Endpoint.
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "OtherAlertRelatedActivity"
| where AdditionalFields has "net stop Sense"
or AdditionalFields has "sc stop Sense"
or AdditionalFields has "net stop WinDefend"
or AdditionalFields has "sc stop WinDefend"
| extend Command = split(AdditionalFields, 'line')[1]
| project-reorder Timestamp, DeviceId, DeviceName, Command
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
