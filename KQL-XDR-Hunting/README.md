## KQL-XDR Threat Hunting
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure%20Data%20Explorer-%230078D4.svg?&style=popout&logo=azure%20data%20explorer&logoColor=white"/></a>

Hi there 👋 Thank you for visiting @LearningKijo <br>
I received a number of feedback about threat hunting in Microsoft 365 Defender.<br>
Therefore, I wrote some "out-of-the-box KQL queries" based on the feedback!!

```
// I will cover mostly these products in KQL.
let MicrosoftProducts = datatable(id: int, value: string)
[
      1, "Microsoft Defender for Endpoints", 
      2, "Microsoft Defender for Office 365", 
      3, "Microsoft Defender for Cloud Apps", 
      4, "Microsoft Defender for Identity", 
      5, "Microsoft Defender Antivirus", 
      6, "Microsoft 365 Defender"
];
MicrosoftProducts
| project id, value
```

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
