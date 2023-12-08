# XDR : Analyzing All Detection MITRE ATT&CK 
This query displays alerts detected in all Defender security products and correlates each of them with MITRE ATT&CK techniques. Each record (MITRE ATT&CK technique) lists the details of alerts detected in each product as dynamic values, including detection time, ID, title and detection source.

#### Table name & Description
- [AlertInfo](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertinfo-table?view=o365-worldwide) : Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity, including severity information and threat categorization

```kusto
AlertInfo
| where TimeGenerated > ago(14d)
| where isnotempty(AttackTechniques)
| extend Parsed = parse_json(AttackTechniques)
| mv-expand Parsed
| extend MITRE_ATTCK = tostring(Parsed)
| extend PackedData = strcat(format_datetime(TimeGenerated,'yyyy-M-dd H:mm:ss'), " : ", AlertId, " : ", Title, " : ", ServiceSource)
| summarize MDE = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Endpoint"),
            MDO = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Office 365"),
            MDI = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Identity"),
            MDA = make_set_if(PackedData, ServiceSource in ("Microsoft Cloud App Security", "App Governance")),
            Entra = make_set_if(PackedData, ServiceSource == "AAD Identity Protection"),
            M365D = make_set_if(PackedData, ServiceSource == "Microsoft 365 Defender") by MITRE_ATTCK
| extend MDE_case = array_length(MDE)
| extend MDO_case = array_length(MDO)
| extend MDI_case = array_length(MDI)
| extend MDA_case = array_length(MDA)
| extend Entra_case = array_length(Entra) 
| extend M365D_case = array_length(M365D) 
| extend SUM = MDE_case + MDO_case + MDI_case + MDA_case + Entra_case + M365D_case
| project MITRE_ATTCK, SUM, MDE, MDO, MDI, MDA, Entra, M365D
| order by SUM desc 
```

#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/d081cb11-c00c-415e-b6e8-bc8d8a90bb35)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
