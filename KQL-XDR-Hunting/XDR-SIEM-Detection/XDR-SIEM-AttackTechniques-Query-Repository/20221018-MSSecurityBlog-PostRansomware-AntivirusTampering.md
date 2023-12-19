# Antivirus tampering
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

Organizations should monitor and respond to antivirus and endpoint detection and response (EDR) alerts where antivirus has been disabled or tampered with. 
Wherever possible, anti-tampering settings should be enabled to prevent actors from being able to interact with and disable antivirus software. 
For more information about Defender for Endpoint tamper protection, visit our docs page: [Protect security settings with tamper protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection?view=o365-worldwide).

Microsoft Defender Antivirus provides [event logging](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) on attempted tampering of the product. 
This can include the disabling of services, such as Real Time Protection (Event ID: 5001). 
An alert will also be created within the Defender for Endpoint portal where customers have the ability to further triage the alert through the [advanced hunting interface](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/faqs-on-tamper-protection?view=o365-worldwide#if-the-status-of-tamper-protection-changes-are-alerts-shown-in-the-microsoft-365-defender-portal). 
Monitoring for the usage of the Windows PowerShell cmdlet can also help discover instances of anti-virus tampering.

#### AntivirusTampering

```kusto
DeviceProcessEvents
| where FileName =~ "PowerShell.exe"
| where ProcessCommandLine has_any ("Get-MpPreference", "Add-MpPreference", "Set-MpPreference")
| project Timestamp, ProcessCommandLine
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
