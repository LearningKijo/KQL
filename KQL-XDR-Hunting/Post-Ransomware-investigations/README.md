## Post ransomware investigations
Microsoft, Detection and Response Team (DART), has recently posted a blog which is covered a post-ransomware incidents. 

> In this blog, we detail a recent ransomware incident in which the attacker used a collection of commodity tools and techniques, such as using living-off-the-land binaries, to launch their malicious code. Cobalt Strike was used for persistence on the network with NT AUTHORITY/SYSTEM (local SYSTEM) privileges to maintain access to the network after password resets of compromised accounts.
#### Reference : [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

In terms of threat hunting, based on MITRE ATT&CK, I wrote some KQL queries to hunt for these activities.


| MITRE ATT&CK | ID | Link |
| ------------- |-------------| ------------- |
| Initial access  | N/A | N/A |
| Persistence  | T1543 <br> T1546 <br> T1547 <br> T1053 | [EndpointMonitoring-Persistence.yaml](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Post-Ransomware-investigations/EndpointMonitoring-Persistence.yaml) ||
| Lateral movement | N/A | N/A |
| Credential access | N/A | N/A |
| Exfiltration | N/A | N/A |
| Defense evasion | N/A | N/A |
| Discovery | N/A | N/A | 


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
