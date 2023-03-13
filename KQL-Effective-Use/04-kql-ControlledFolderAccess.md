# KQL : Controlled Folder Access

WIP

**PowerShell**
```powershell
# Enable controlled folder access
Set-MpPreference -EnableControlledFolderAccess AuditMode
Set-MpPreference -EnableControlledFolderAccess Enabled

# Customize controlled folder access
Add-MpPreference -ControlledFolderAccessProtectedFolders "c:\apps\"
Add-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"

# Disable controlled folder access
Set-MpPreference -EnableControlledFolderAccess Disabled
```
