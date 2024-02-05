# Diamond Sleet supply chain compromise distributes a modified CyberLink installer

Microsoft Threat Intelligence has exposed a supply chain attack by North Korean threat actor Diamond Sleet (ZINC). The attack involved a modified installer of a legitimate application by CyberLink Corp., a multimedia software company. The installer, signed with a valid CyberLink Corp. certificate, downloads a second-stage payload, impacting over 100 devices across multiple countries. Diamond Sleet is attributed to this with high confidence, and the second-stage payload communicates with previously compromised infrastructure. Microsoft has taken steps to mitigate further risks, including informing CyberLink, notifying affected Microsoft Defender for Endpoint customers, reporting the attack to GitHub, and adding the malicious certificate to its disallowed list. Microsoft Defender for Endpoint detects this as Diamond Sleet activity, and Defender Antivirus labels the malware as Trojan:Win32/LambLoad. The blog may be updated with additional insights as the campaign progresses.
> 👉 November 22, 2023, [Diamond Sleet supply chain compromise distributes a modified CyberLink installer](https://www.microsoft.com/en-us/security/blog/2023/11/22/diamond-sleet-supply-chain-compromise-distributes-a-modified-cyberlink-installer/)

## Advanced hunting queries
**Microsoft Defender XDR**  

Microsoft Defender XDR (formerly Microsoft 365 Defender) customers can run the following query to find related activity in their networks:
```kusto
let iocs = dynamic(["166d1a6ddcde4e859a89c2c825cd3c8c953a86bfa92b343de7e5bfbfb5afb8be",
"089573b3a1167f387dcdad5e014a5132e998b2c89bff29bcf8b06dd497d4e63d",
"915c2495e03ff7408f11a2a197f23344004c533ff87db4b807cc937f80c217a1"]);
DeviceFileEvents
| where ActionType == "FileCreated"
| where SHA256 in (iocs)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
```

**Microsoft Defender XDR and Microsoft Sentinel**

This query can be used in both Microsoft Defender XDR advanced hunting and Microsoft Sentinel Log Analytics. It surfaces devices where the modified CyberLink installer can be found.
```kusto
DeviceFileCertificateInfo
| where Signer contains "CyberLink Corp"
| where CertificateSerialNumber == "0a08d3601636378f0a7d64fd09e4a13b"
| where SignerHash == "8aa3877ab68ba56dabc2f2802e813dc36678aef4"
| join DeviceFileEvents on SHA1
| distinct DeviceName, FileName, FolderPath, SHA1, SHA256, IsTrusted, IsRootSignerMicrosoft, SignerHash
```

## Microsoft Security Blog
November 22, 2023, [Diamond Sleet supply chain compromise distributes a modified CyberLink installer](https://www.microsoft.com/en-us/security/blog/2023/11/22/diamond-sleet-supply-chain-compromise-distributes-a-modified-cyberlink-installer/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
