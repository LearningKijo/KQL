# KQL : Tamper Protection 


```PowerShell
# Microsoft Defender Antivirus
PS : Set-MpPreference -DisableRealtimeMonitoring $true
PS : Set-MpPreference -DisableBlockAtFirstSeen $true
PS : Set-MpPreference -SubmitSamplesConsent 2
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -PropertyType DWORD -Force
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -PropertyType DWORD -Force
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -PropertyType DWORD -Force
PS : Stop-Service -Name "WinDefend"
PS : Stop-Process -Name "MsMpEng"
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Microsoft Defender for Endpoint
PS : Stop-Service -Name "Sense"
PS : Stop-Process -Name "MsSense"
```
```cmd
:: Microsoft Defender Antivirus
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
Cmd : reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
Cmd : sc stop WinDefend
Cmd : sc config "WinDefend" start= disabled
Cmd : net stop WinDefend
Cmd : reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

::  Microsoft Defender for Endpoint
Cmd : sc stop //service
Cmd : net stop Sense 
```
