# Exposure Management : Device Exposure Levels 
This query provides a list of devices with 'Medium' or 'High' exposure levels, along with Exposure Management affecting source items.

> [!Important]
> [Security Exposure Management is currently in public preview.](https://learn.microsoft.com/en-us/security-exposure-management/cross-workload-attack-surfaces)
 
#### Table name & Description
- [ExposureGraphEdges](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-exposuregraphedges-table?view=o365-worldwide) : Microsoft Security Exposure Management exposure graph edge information provides visibility into relationships between entities and assets in the graph

```kusto
let ExposureItems = (ExposureGraphEdges
| where EdgeLabel == "affecting"
| mv-expand TargetNodeCategories
| where TargetNodeCategories == "device"
| join kind=inner ExposureGraphNodes on $left.TargetNodeId == $right.NodeId
| mv-expand EntityIds
| extend EntityType = tostring(EntityIds.type)
| where EntityType == "DeviceInventoryId"
| extend EntityID = tostring(EntityIds.id)
| summarize Item = make_set(SourceNodeName) by EntityID
| extend Case = array_length(Item));
DeviceInfo
| where ExposureLevel in ("Medium", "High")
| summarize arg_max(Timestamp, *) by DeviceId, DeviceName 
| join kind=inner ExposureItems on $left.DeviceId ==  $right.EntityID
| project Timestamp, DeviceId, DeviceName, OSPlatform, ExposureLevel, Case, Item
| order by Case desc 
```
#### Result
![image](https://github.com/LearningKijo/KQL/assets/120234772/ff7c75e9-e9df-43f6-88d5-bddc0c1d5bbc)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
