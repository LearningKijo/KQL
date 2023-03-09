# KQL : Tamper Protection 


```PowerShell
# Microsoft Defender Antivirus
PS : Stop-Service WinDefend
PS : Set-Mppreference 
PS : New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Microsoft Defender for Endpoint

```
```cmd
:: Microsoft Defender Antivirus
Cmd : sc config "WinDefend" start= disabled
Cmd : net stop WinDefend
Cmd : reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```
