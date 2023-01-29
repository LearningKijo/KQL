## Defenders beware: A case for post-ransomware investigations
Microsoft, Detection and Response Team (DART), has recently posted a blog which is covered a post-ransomware incidents. Some people are interested in how we can leverage the power of kusto, KQL for hunting these malicious activities in Microsoft 365 Defender or Microsoft Sentinel. Therefore, in terms of MITRE ATT&CK and threat hunting, I wrote some out-of-the-box queries to hunt for these activities.

> In this blog, we detail a recent ransomware incident in which the attacker used a collection of commodity tools and techniques, such as using living-off-the-land binaries, to launch their malicious code. Cobalt Strike was used for persistence on the network with NT AUTHORITY/SYSTEM (local SYSTEM) privileges to maintain access to the network after password resets of compromised accounts.

![image](https://user-images.githubusercontent.com/120234772/215325221-0adeef14-8c73-4f7d-a85b-ec64dc26d63e.png)

#### Reference : [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)
<br>

## Hunting queries - Post-Ransomware activities

| MITRE ATT&CK | Detail | Link |
| ------------- |-------------| ------------- |
| Initial access  | N/A | N/A |
| Persistence  | Scheduled task <br> Service  <br> SSH connection : OpenSSH <br> Registry : Run and RunOnce | [EndpointMonitoring-Persistence.yaml](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Post-Ransomware-investigations/EndpointMonitoring-Persistence.yaml) ||
| Lateral movement | Impacket (WMI) <br> PsExec <br> Remote desktop protocol(RDP) | In progress |
| Credential access | WDigest <br> NTDSUtil Dumping <br> Volume shadow copy access | In progress |
| Exfiltration | PuTTY Secure Copy (PSCP) | In progress |
| Defense evasion | Disabling antivirus <br> Kernel driver | In progress |
| Discovery | Commands | In progress | 


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
