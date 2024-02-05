# Microsoft Security Threat Insight 2023
<a href="https://twitter.com/kj_ninja25"><img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/kj_ninja25"></a>
<a href="https://www.linkedin.com/in/kijo-girardi/"><img src="https://img.shields.io/badge/-Linkedin-0077B5.svg?logo=linkedin&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure%20Data%20Explorer-%230078D4.svg?&style=popout&logo=azure%20data%20explorer&logoColor=white"/></a>

I have seen a variety of valuable insights on nation-based threat actors from MSTIC, DART, the Product Team, and others. While I may not be able to list them all precisely, I would like to keep them here as KQL query logs.

> [!Note]
> This repository primarily focuses on ***Threat Actors*** from the year 2023 , and therefore, does not include specific attack techniques.
> For details on each KQL, attack backgrounds, etc., please refer to the accompanying blog.

## Blizzard
| Date            | Name            | Microsoft Security Blog / KQL |
|:----------------|:----------------|:------------------------------|
| June 14         | Cadet Blizzard  | [Cadet Blizzard emerges as a novel and distinct Russian threat actor](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230614-CadetBlizzard.md) |

## Typhoon
| Date            | Name            | Microsoft Security Blog / KQL |
|:----------------|:----------------|:------------------------------|
| May 24          | Volt Typhoon    | [Volt Typhoon targets US critical infrastructure with living-off-the-land techniques](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230525-VoltTyphoon.md) |
| August 24       | Flax Typhoon | [Flax Typhoon using legitimate software to quietly access Taiwanese organizations](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230824-FlaxTyphoon.md) |

## Sandstorm
| Date            | Name            | Microsoft Security Blog / KQL |
|:----------------|:----------------|:------------------------------|
| April 7         | Mango Sandstorm | [MERCURY and DEV-1084: Destructive attack on hybrid environments](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230407-MangoSandstorm.md) |
| April 18        | Mint Sandstorm | [Nation-state threat actor Mint Sandstorm refines tradecraft to attack high-value targets](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230418-MintSandstorm.md) |

## Sleet
| Date            | Name            | Microsoft Security Blog / KQL |
|:----------------|:----------------|:------------------------------|
| October 18      | Diamond Sleet <br> Onyx Sleet | [Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20231018-DiamondSleet-OnyxSleet.md)
| November 22     | Diamond Sleet   | [Diamond Sleet supply chain compromise distributes a modified CyberLink installer](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20231122-DiamondSleet.md) |

## Storm
| Date            | Name            | Microsoft Security Blog / KQL |
|:----------------|:----------------|:------------------------------|
| September 12    | Storm-0324   | [Malware distributor Storm-0324 facilitates ransomware access](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/MicrosoftSecurity-Threat-Insight/MicrosoftSecurity-ThreatInsight/2023-MicrosoftSecurity-ThreatInsight/20230912-Storm-0324.md) |

```
Actor category 
      - Typhoon    : China
      - Sandstorm  : Iran
      - Rain       : Lebanon
      - Sleet      : North Korea
      - Blizzard   : Russia
      - Hail       : South Korea
      - Dust       : Turkey
      - Cyclone    : Vietnam

Financially motivated 
      - Tempest    : Financially motivated

Private sector offensive actors
      - Tsunami    : PSOAs

Influence operations
      - Flood      : Influence operations

Groups in development
      - Storm      : Groups in development
```
> [!Important]
> Microsoft has shifted to a new naming taxonomy for threat actors aligned with the theme of weather. With the new taxonomy, we intend to bring better clarity to customers and other security researchers already confronted with an overwhelming amount of threat intelligence data and offer a more organized, articulate, and easy way to reference threat actors so that organizations can better prioritize and protect themselves.
> [How Microsoft names threat actors](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
