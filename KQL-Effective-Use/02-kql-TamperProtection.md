# KQL : Tamper Protection 


```PowerShell
# Microsoft Defender Antivirus
PS : Set-MpPreference -DisableRealtimeMonitoring $true
PS : Set-MpPreference -DisableBlockAtFirstSeen $true
PS : Set-MpPreference -SubmitSamplesConsent 2
PS : Stop-Service WinDefend
PS : Stop-Process -Name MsMpEng
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Microsoft Defender for Endpoint
PS : Stop-Service Sense
```
```cmd
:: Microsoft Defender Antivirus
Cmd : sc config "WinDefend" start= disabled
Cmd : net stop WinDefend
Cmd : reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

::  Microsoft Defender for Endpoint
Cmd : net stop Sense
```
