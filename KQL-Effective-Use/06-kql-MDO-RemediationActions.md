# KQL : MDO remediation actions
Microsoft Defender for Office 365(MDO) is a cloud-based email filtering service designed to protect organizations that use the Microsoft Office 365 platform from various email-based threats such as malware, phishing, and spam. At this time, I would like to focus on the remediation actions available in Microsoft Defender for Office 365, Explorer.

## KQL : Hunting queries
This KQL shows the summary of Microsoft Defender for Office 365 remediation actions.
- Track each cases with **Network Message ID**
- Sort **the users who got a number of actions**- e.g. Soft Delete, Hard Delete, Move to junk folder, Move to deleted items
```kql
    EmailEvents
    | where Timestamp > ago(30d)
    | where LatestDeliveryAction in ("Hard delete", "Soft delete", "Moved to junk folder", "Moved to deleted items")
    | summarize HardDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @"\", Timestamp,@"\", Subject), LatestDeliveryAction == "Hard delete"),  
                SoftDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @"\", Timestamp,@"\", Subject), LatestDeliveryAction == "Soft delete"),
                MoveToJunk_NetworkID = make_list_if(strcat(NetworkMessageId, @"\", Timestamp,@"\", Subject), LatestDeliveryAction == "Moved to junk folder"),
                MoveToDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @"\", Timestamp,@"\", Subject), LatestDeliveryAction == "Moved to deleted items") by RecipientEmailAddress
    | extend HardDelete_case = array_length(HardDelete_NetworkID)
    | extend SoftDelete_case = array_length(SoftDelete_NetworkID)
    | extend MoveToJunk_case = array_length(MoveToJunk_NetworkID)
    | extend MoveToDelete_case = array_length(MoveToDelete_NetworkID)
    | extend Sum_case = HardDelete_case + SoftDelete_case + MoveToJunk_case + MoveToDelete_case
    | project RecipientEmailAddress, Sum_case, HardDelete_case, SoftDelete_case, MoveToJunk_case, MoveToDelete_case, HardDelete_NetworkID, SoftDelete_NetworkID, MoveToJunk_NetworkID, MoveToDelete_NetworkID
    | order by Sum_case desc 
```

## KQL : Hunting results
**e.g. - Case**

![image](https://user-images.githubusercontent.com/120234772/227914685-8f3dafd0-83c6-4e1b-80e0-8cbca1963639.png)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
