# LDAP query activities captured by MDE table
This query helps filter weekly LDAP query activities captured by Microsoft Defender for Endpoint sensor.

#### Table name & Description
- [DeviceEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide) : 	Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "LdapSearch"
| extend Parsed = parse_json(AdditionalFields)
| extend AttributeList = Parsed.AttributeList
| extend DistinguishedName = Parsed.DistinguishedName
| extend ScopeOfSearch = Parsed.ScopeOfSearch
| extend SearchFilter = Parsed.SearchFilter
| project Timestamp, DeviceName, AttributeList, DistinguishedName, ScopeOfSearch, SearchFilter
```


#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
