# KQL : Controlled Folder Access

WIP

**PowerShell**
```powershell
# Confirm controlled folder access 
Get-MpPreference | Select EnableControlledFolderAccess, ControlledFolderAccessEnable, ControlledFolderAccessAllowedApplications

# Enable controlled folder access
Set-MpPreference -EnableControlledFolderAccess AuditMode
Set-MpPreference -EnableControlledFolderAccess Enabled

# Customize controlled folder access
Add-MpPreference -ControlledFolderAccessProtectedFolders "c:\apps\"
Add-MpPreference -ControlledFolderAccessAllowedApplications "c:\apps\test.exe"

# Disable controlled folder access
Set-MpPreference -EnableControlledFolderAccess Disabled
```
Use Add-MpPreference to append or add apps to the list. Using the Set-MpPreference cmdlet will overwrite the existing list.
