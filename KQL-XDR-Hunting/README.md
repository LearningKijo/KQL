## Hi there 👋 Thank you for visiting @LearningKijo
I received a number of feedback about threat hunting in Microsoft 365 Defender.<br>
Therefore, I wrote KQL samples based on the feedback!!

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
