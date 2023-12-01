# MDO User List for Remediation Action
This query tracks MDO remediation actions, such as Soft Delete, Hard Delete, Move to Junk Folder, Move to Deleted Items, with Network Message ID. 
It also sorts the users based on the number of actions they received.

#### Table name & Description
- [EmailEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide) : Microsoft 365 email events, including email delivery and blocking events
 
```kusto
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

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
