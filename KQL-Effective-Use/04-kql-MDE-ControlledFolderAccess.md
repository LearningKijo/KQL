# KQL : Controlled Folder Access (CFA)
Controlled Folder Access is a security feature in Microsoft Defender for Endpoint that helps protect important files from ransomware and other malicious software. It blocks unauthorized changes to designated folders and allows only trusted applications to access them, which helps prevent malware from accessing or modifying sensitive files.

## PowerShell Cmdlet
**PowerShell**
```powershell
# Confirm CFA configuration
Get-MpPreference | Select-Object EnableControlledFolderAccess, ControlledFolderAccessAllowedApplications, ControlledFolderAccessProtectedFolders

# Enable/Disable controlled folder access
Set-MpPreference -EnableControlledFolderAccess AuditMode
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableControlledFolderAccess Disabled

# Customize controlled folder access
Add-MpPreference -ControlledFolderAccessProtectedFolders "c:\apps\"
Add-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"
Remove-MpPreference -ControlledFolderAccessProtectedFolders  "c:\apps\"
Remove-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"
```

> **Note** : **Windows system folders are protected by default**
> ```
> c:\Users\<username>\Documents
> c:\Users\Public\Documents
> c:\Users\<username>\Pictures
> c:\Users\Public\Pictures
> c:\Users\Public\Videos
> c:\Users\<username>\Videos
> c:\Users\<username>\Music
> c:\Users\Public\Music
> c:\Users\<username>\Favorites
> ```
> [Protect important folders from ransomware from encrypting your files with controlled folder access | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders?view=o365-worldwide)

## CFA quick test 
- Download [the CFA test tool](https://demo.wd.microsoft.com/Content/CFAtool.exe).
- Create an executable file with PowerShell script.
```powershell
$filePath = "C:\Users\Public\Documents\example.exe"
$textContent = "This is an example file."

New-Item -Path $filePath -ItemType File -Value $textContent
```

## KQL : Hunting queries
**Controlled Folder Access - Block**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ControlledFolderAccessViolationBlocked"
| summarize TargetFolderPath = make_list(strcat(FolderPath, " | ", InitiatingProcessFileName)) by bin(Timestamp, 1d), DeviceId, DeviceName
| extend Num = array_length(TargetFolderPath)
| project Timestamp, DeviceId, DeviceName, Num, TargetFolderPath
```
**Controlled Folder Access - Audit**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ControlledFolderAccessViolationAudit"
| summarize TargetFolderPath = make_list(strcat(FolderPath, " | ", InitiatingProcessFileName)) by bin(Timestamp, 1d), DeviceId, DeviceName
| extend Num = array_length(TargetFolderPath)
| project Timestamp, DeviceId, DeviceName, Num, TargetFolderPath
```

## KQL : Hunting results
e.g. Controlled Folder Access - Block

![image](https://github.com/LearningKijo/KQL/assets/120234772/9b931ee7-07a6-4185-8608-33f33690a6f2)



#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.

