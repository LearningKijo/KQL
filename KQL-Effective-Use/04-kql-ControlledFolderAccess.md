# KQL : Controlled Folder Access
Controlled Folder Access is a security feature in Microsoft Defender for Endpoint that helps protect important files from ransomware and other malicious software. It blocks unauthorized changes to designated folders and allows only trusted applications to access them, which helps prevent malware from accessing or modifying sensitive files.

## PowerShell Cmdlet
**PowerShell**
```powershell
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

## KQL Hunting queries
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType contains "ControlledFolder"
```
