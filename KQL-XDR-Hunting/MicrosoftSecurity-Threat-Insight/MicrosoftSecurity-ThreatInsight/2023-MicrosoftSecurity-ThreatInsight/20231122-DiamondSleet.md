# Diamond Sleet supply chain compromise distributes a modified CyberLink installer
The actor that Microsoft tracks as Diamond Sleet (formerly ZINC) is a North Korea-based activity group known to target media, defense, and information technology (IT) industries globally. 
Diamond Sleet focuses on espionage, theft of personal and corporate data, financial gain, and corporate network destruction. 
Diamond Sleet is known to use a variety of custom malware that is exclusive to the group. 
Recent Diamond Sleet malware is described in Microsoft’s reporting of the group’s weaponization of open source software and exploitation of N-day vulnerabilities. 
Diamond Sleet overlaps with activity tracked by other security companies as Temp.Hermit and Labyrinth Chollima.

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
