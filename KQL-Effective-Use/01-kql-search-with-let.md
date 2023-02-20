## KQL - search operator with let statement
Firstly, "search" is very useful and effective operator in KQL when you look for some key word or data. <br>
> Searches a text pattern in multiple tables and columns.<br>
[search operator - Azure Data Explorer | Microsoft Learn!](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/searchoperator?pivots=azuredataexplorer)

If you have ever used advanced hunting in Microsoft 365 Defender and selected "Go hunt" option in a device page, you might be seen KQL - seeking a device with let statement and search operator. 
However, the question is that I haven't ever seen the search scenario with let. I looked at MS docs, [Search operator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/searchoperator?pivots=azuredataexplorer), and [Let statement](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/letstatement#create-a-view-or-virtual-table). These were slightly covered the example, but not fully the use case, especially in Microsoft 365 Defender. Therefore, at this time, I´m going to focus on the use case : seach operator with let statement. 

#### Question: When do we use this query? 
If you would like to search something with "specific tables" and "timeline", then the query - let & search would be a great way to use!!

#### Ex) "Go hunt" from a device page in Microsoft 365 Defender <br>
This query hunts "DeviceA" with a time range by filtering some tables such as DeviceEvent, DeviceInfo and so on.

```
let deviceName = "DeviceA";
let deviceId = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
let selectedTimestamp = datetime(2022-11-22T10:22:11.2370000Z);
search in (IdentityLogonEvents,IdentityQueryEvents,IdentityDirectoryEvents,DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents)
Timestamp between ((selectedTimestamp - 1h) .. (selectedTimestamp + 1h))
and
(DeviceName == deviceName
//or DeviceId == deviceId
// Events affecting this target device
//or RemoteDeviceName == deviceName
//or TargetDeviceName == deviceName
//or DestinationDeviceName == deviceName
)
| take 100
``` 
<br>

#### Point 1 -  after you write let statement, please be careful to not forget ";" in the end.
```
let deviceName = "DeviceA";
let deviceId = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
let selectedTimestamp = datetime(2022-11-22T10:22:11.2370000Z);
```
#### Point 2 - you can flexibly choose the timestamp - without let or with let. 
```
// Timestamp with let statement 
let selectedTimestamp = datetime(2022-11-22T10:22:11.2370000Z);
Timestamp between ((selectedTimestamp - 1h) .. (selectedTimestamp + 1h))

// Timestamp without let statement 
Timestamp between (datetime(2022-11-22) .. datetime(2022-11-23))
```
#### Point 3 - when you want to filter with multiple conditions, you can use "and"
```
Timestamp between ((selectedTimestamp - 1h) .. (selectedTimestamp + 1h))
and
(DeviceName == deviceName)
```

## Example
```
// search mimikatz activities 

let IoC_FileName = "mimikatz";
let IoC_SHA256 = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50";
let IoC_SHA1 = "d1f7832035c3e8a73cc78afd28cfd7f4cece6d20";
let IoC_MD5 = "e930b05efe23891d19bc354a4209be3e";
let StartTimestamp = datetime(2022-12-01);
let EndTimestamp = datetime(2022-12-17);
search in (DeviceProcessEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceImageLoadEvents,DeviceEvents)
Timestamp between ((StartTimestamp) .. (EndTimestamp))
and 
(FileName has IoC_FileName
or InitiatingProcessFileName has IoC_FileName
or ProcessCommandLine has IoC_FileName
or InitiatingProcessCommandLine has IoC_FileName
or MD5 == IoC_MD5
or SHA1 == IoC_SHA1
or SHA256 == IoC_SHA256
or InitiatingProcessMD5 == IoC_MD5
or InitiatingProcessSHA1 == IoC_SHA1
or InitiatingProcessSHA256 == IoC_SHA256
)
```
