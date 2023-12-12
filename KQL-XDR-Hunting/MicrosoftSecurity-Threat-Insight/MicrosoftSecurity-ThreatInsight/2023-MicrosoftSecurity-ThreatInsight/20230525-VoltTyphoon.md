# Volt Typhoon targets US critical infrastructure with living-off-the-land techniques

## Advanced hunting queries
**Find commands creating domain controller installation media** -
This query can identify domain controller installation media creation commands similar to those used by Volt Typhoon.
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_all ("ntdsutil", "create full", "pro")
```

**Find commands establishing internal proxies** - 
This query can identify commands that establish internal proxies similar to those used by Volt Typhoon.
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_all ("portproxy", "netsh", "wmic", "process call create", "v4tov4")
```

**Find detections of custom FRP executables** - This query can identify alerts on files that match the SHA-256 hashes of known Volt Typhoon custom FRP binaries.
```kusto
AlertEvidence
| where SHA256 in 
('baeffeb5fdef2f42a752c65c2d2a52e84fb57efc906d981f89dd518c314e231c', 
'b4f7c5e3f14fb57be8b5f020377b993618b6e3532a4e1eb1eae9976d4130cc74', 
'4b0c4170601d6e922cf23b1caf096bba2fade3dfcf92f0ab895a5f0b9a310349', 
'c0fc29a52ec3202f71f6378d9f7f9a8a3a10eb19acb8765152d758aded98c76d', 
'd6ab36cb58c6c8c3527e788fc9239d8dcc97468b6999cf9ccd8a815c8b4a80af', 
'9dd101caee49c692e5df193b236f8d52a07a2030eed9bd858ed3aaccb406401a', 
'450437d49a7e5530c6fb04df2e56c3ab1553ada3712fab02bd1eeb1f1adbc267', 
'93ce3b6d2a18829c0212542751b309dacbdc8c1d950611efe2319aa715f3a066', 
'7939f67375e6b14dfa45ec70356e91823d12f28bbd84278992b99e0d2c12ace5', 
'389a497f27e1dd7484325e8e02bbdf656d53d5cf2601514e9b8d8974befddf61', 
'c4b185dbca490a7f93bc96eefb9a597684fdf532d5a04aa4d9b4d4b1552c283b', 
'e453e6efc5a002709057d8648dbe9998a49b9a12291dee390bb61c98a58b6e95', 
'6036390a2c81301a23c9452288e39cb34e577483d121711b6ba6230b29a3c9ff', 
'cd69e8a25a07318b153e01bba74a1ae60f8fc28eb3d56078f448461400baa984', 
'17506c2246551d401c43726bdaec800f8d41595d01311cf38a19140ad32da2f4', 
'8fa3e8fdbaa6ab5a9c44720de4514f19182adc0c9c6001c19cf159b79c0ae9c2', 
'd17317e1d5716b09cee904b8463a203dc6900d78ee2053276cc948e4f41c8295', 
'472ccfb865c81704562ea95870f60c08ef00bcd2ca1d7f09352398c05be5d05d', 
'3e9fc13fab3f8d8120bd01604ee50ff65a40121955a4150a6d2c007d34807642')
```


## Microsoft Security Blog
May 24, 2023, [Volt Typhoon targets US critical infrastructure with living-off-the-land techniques](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
