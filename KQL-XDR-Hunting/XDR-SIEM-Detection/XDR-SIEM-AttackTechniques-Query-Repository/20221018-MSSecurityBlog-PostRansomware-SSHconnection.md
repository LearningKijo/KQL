# Monitoring SSH connection 
Microsoft Security Blog title - Defenders beware: A case for post-ransomware investigations

**Scheduled task: OpenSSH**

The actor installed OpenSSH on the client's network to maintain persistence on critical servers, including domain controllers and domain administrator workstations. The actor installed OpenSSH within C:\Windows\OpenSSH, rather than the standard OpenSSH path in System32.

The actor created a scheduled task for a persistent SSH connection to their C2 as "NT AUTHORITY\System". The actor used TCP 443 for their SSH traffic rather than the standard TCP 22. In many organizations, TCP 22 outbound may be blocked, but as TCP 443 is needed for web traffic the port is often open. The actor also enabled port forwarding on TCP 7878 to allow the tunneling of malicious tools through the SSH connection.

The actor was also observed renaming ssh.exe to "C:\Windows\OpenSSH\svchost.exe" in a likely attempt to evade detection.

Four days after the actor deployed the ransomware, the actor returned to the compromised network through their existing OpenSSH persistence to install further persistence SSH services on additional domain controllers and domain administrator workstations.

The actor used OpenSSH's sftp-server to transfer files between their C2 and the compromised host. The actor generated SSH keys on compromised hosts using ssh-keygen.exe, a tool apart of the OpenSSH tool suite. This allowed the actor to SSH using the keys rather than credentials, after credentials had been reset.

#### Monitoring SSH connection 

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has "OpenSSH" 
        or FileName == "ssh.exe" 
        or FileName == "scp.exe"
        or FileName == "sftp.exe"
        or FileName == "sshd.exe"
        or FileName == "ssh-add.exe"
        or FileName == "ssh-agent.exe"
        or FileName == "ssh-keygen.exe"
        or FileName == "ssh-keyscan.exe"
| where ProcessCommandLine has_all ("ssh", "-p")
| project-reorder ProcessCommandLine
```

#### Reference
- October 18, 2022, [Defenders beware: A case for post-ransomware investigations](https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
