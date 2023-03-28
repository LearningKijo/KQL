# KQL : MDO remediation actions
WIP

## KQL : Hunting queries
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

![image](https://user-images.githubusercontent.com/120234772/227914685-8f3dafd0-83c6-4e1b-80e0-8cbca1963639.png)
