# KQL : Controlled Folder Access

WIP

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

