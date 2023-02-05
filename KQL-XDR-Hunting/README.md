## KQL-XDR Threat Hunting
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure%20Data%20Explorer-%230078D4.svg?&style=popout&logo=azure%20data%20explorer&logoColor=white"/></a>

Hi there 👋 Thank you for visiting @LearningKijo. 
In this KQL-XDR-Hunting section, I will provide "out-of-the-box KQL queries" based on the feedback, security blog, new attack and so on.

```
// I will cover mostly these products and topics in KQL.
let MicrosoftProducts = datatable(id: int, value: string)
[
      1, "Microsoft Defender for Endpoints", 
      2, "Microsoft Defender for Office 365", 
      3, "Microsoft Defender for Cloud Apps", 
      4, "Microsoft Defender for Identity", 
      5, "Microsoft Defender Antivirus", 
      6, "Microsoft 365 Defender"
      7, "Threat Hunting"
      8, "Worldwide security breach"
];
MicrosoftProducts
| project id, value
```

### Out-of-the-box KQL queries :

| Products/Threat  | Link |
| ------------- | ------------- |
| XDR | [Microsoft 365 Defender](https://github.com/LearningKijo/KQL/tree/main/KQL-XDR-Hunting/XDR-Microsoft-365-Defender) |
| Endpoint   | [Microsoft Defender for Endpoint](https://github.com/LearningKijo/KQL/tree/main/KQL-XDR-Hunting/Endpoint-Microsoft-Defender-for-Endpoint)  |
| Email  | [Microsoft Defender for Office 365](https://github.com/LearningKijo/KQL/tree/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365)  |
| App | In progress |
| Identity | In progress |
| Ransomware | [Post ransomware investigations](https://github.com/LearningKijo/KQL/tree/main/KQL-XDR-Hunting/Post-Ransomware-investigations) |

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
