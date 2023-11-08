# Analyzing MITRE ATT&CK Detection with KQL
Welcome to [KQL-Effective-Use](https://github.com/LearningKijo/KQL/tree/main/KQL-Effective-Use).
Today, I'm thrilled to share two insightful Kusto Query Language (KQL) queries for analyzing MITRE ATT&CK techniques and their related categories.

## KQL : Hunting queries
1. This query displays alerts detected in all Defender security products and correlates each of them with MITRE ATT&CK techniques.
Each record (MITRE ATT&CK technique) lists the details of alerts detected in each product as dynamic values, including detection time, ID, title and detection source.

```kql
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
            MDA = make_set_if(PackedData, ServiceSource == "Microsoft Cloud App Security"),
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
![image](https://github.com/LearningKijo/KQL/assets/120234772/88e5fe0d-85ad-4e29-b795-eee2c0a7a708)


2. This query displays alerts detected in all Defender security products by threat category and by product.
Each record (threat category) lists the details of alerts detected in each product as dynamic values, including detection time, id, title, detection source, and MITRE ATT&CK technique.

```kql
AlertInfo
| where TimeGenerated > ago(14d)
| where isnotempty(AttackTechniques)
| extend Parsed = parse_json(AttackTechniques)
| mv-expand Parsed
| extend MITRE_ATTCK = tostring(Parsed)
| extend PackedData = strcat(format_datetime(TimeGenerated,'yyyy-M-dd H:mm:ss'), " : ", AlertId, " : ", Title, " : ", ServiceSource, " : ", MITRE_ATTCK)
| summarize MDE = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Endpoint"),
            MDO = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Office 365"),
            MDI = make_set_if(PackedData, ServiceSource == "Microsoft Defender for Identity"),
            MDA = make_set_if(PackedData, ServiceSource == "Microsoft Cloud App Security"),
            Entra = make_set_if(PackedData, ServiceSource == "AAD Identity Protection"),
            M365D = make_set_if(PackedData, ServiceSource == "Microsoft 365 Defender") by Category
| extend MDE_case = array_length(MDE)
| extend MDO_case = array_length(MDO)
| extend MDI_case = array_length(MDI)
| extend MDA_case = array_length(MDA)
| extend Entra_case = array_length(Entra) 
| extend M365D_case = array_length(M365D) 
| extend SUM = MDE_case + MDO_case + MDI_case + MDA_case + Entra_case + M365D_case
| project Category, SUM, MDE, MDO, MDI, MDA, Entra, M365D
| order by SUM desc 
```
![image](https://github.com/LearningKijo/KQL/assets/120234772/264875c3-826c-498e-a88a-91cec7496807)


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
