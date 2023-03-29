# KQL : MDO remediation actions
Microsoft Defender for Office 365(MDO) is a cloud-based email filtering service designed to protect organizations that use the Microsoft Office 365 platform from various email-based threats such as malware, phishing, and spam. At this time, I would like to focus on the remediation actions available in Microsoft Defender for Office 365, Explorer.

## KQL : Hunting queries
This KQL shows the summary of Microsoft Defender for Office 365 remediation actions.
- Track each cases with **Network Message ID**
- Sort **the users who got a number of actions**- e.g. Soft Delete, Hard Delete, Move to junk folder, Move to deleted items
```kql
    EmailEvents
    | where Timestamp > ago(30d)
    | where LatestDeliveryAction in ("Hard delete", "Soft delete", "Moved to deleted items", "Moved to deleted items")
    | summarize HD_NWId = make_list_if(NetworkMessageId, LatestDeliveryAction == "Hard delete"),  
            SD_NWId = make_list_if(NetworkMessageId, LatestDeliveryAction == "Soft delete"),
            MvToJ_NWId = make_list_if(NetworkMessageId, LatestDeliveryAction == "Moved to deleted items"),
            MvToD_NWId = make_list_if(NetworkMessageId, LatestDeliveryAction == "Moved to deleted items") by RecipientEmailAddress
    | extend HD_case = array_length(HD_NWId)
    | extend SD_case = array_length(SD_NWId)
    | extend MvToJ_case = array_length(MvToJ_NWId)
    | extend MvToD_case = array_length(MvToD_NWId)
    | extend Sum_case = HD_case + SD_case + MvToJ_case + MvToD_case
    | project RecipientEmailAddress, Sum_case, HD_case, SD_case, MvToJ_case, MvToD_case, HD_NWId, SD_NWId, MvToJ_NWId, MvToD_NWId
    | sort by Sum_case desc  
```

## KQL : Hunting results
**e.g. - Case**

![image](https://user-images.githubusercontent.com/120234772/227914685-8f3dafd0-83c6-4e1b-80e0-8cbca1963639.png)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
