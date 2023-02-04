# KQL - learning resources
<img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout">
KQL stands for "Kusto Query Language" and this is very effective when you want to hunt for specific activities and data. Also, Microsoft Sentinel (SOAR) and Microsoft 365 Defender (Advanced Hunting) are great examples for using KQL. However, leveraging KQL might be a bit challenging if you don't have SQL or programming background. When I have started learning KQL, I had no idea how to begin as a learning process due to no programming/SQL experience. Throughout my KQL journey, I would like to share some of the best resources for learning KQL. At the same time, I would like to share some sample queries in this KQL repository.

> Kusto Query Language is a powerful tool to explore your data and discover patterns, identify anomalies and outliers, create statistical modeling, and more. The query uses schema entities that are organized in a hierarchy similar to SQL's: databases, tables, and columns.
> https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/

![image](https://user-images.githubusercontent.com/120234772/216594925-eb0c7249-0ac1-426e-bab8-539f50eafbe0.png)
> e.g. Microsoft 365 Defender portal | Advanced Hunting  

## Microsoft 365 Defender / Webcast 
This webinar was definitely helpful for people who are going to start learning KQL in Microsoft 365 Defender. Each series of webinar covers the fundamental KQL and the great use case. As I mostly focus on XDR in Microsoft 365 Defender in my work, I started watching these webinars initially.

Webcast 1 - 4 series 
1. [M365 Defender (MTP) webinar: Tracking the Adversary E1: KQL Fundamentals](https://www.youtube.com/watch?v=0D9TkGjeJwM).
2. [M365 Defender (MTP) webinar: Tracking the Adversary E2: Joins](https://www.youtube.com/watch?v=LMrO6K5TWOU).
3. [M365 Defender (MTP) webinar: Tracking the Adversary, E3: Summarizing, Pivoting, and Visualizing Data](https://www.youtube.com/watch?v=UKnk9U1NH6Y).
4. [M365 Defender (MTP) webinar: Tracking the Adversary E4 Let’s hunt! Applying KQL to incident tracking](https://www.youtube.com/watch?v=2EUxOc_LNd8&list=RDCMUCGTUbqE3SJiLgtvWjIkSQuQ&index=3). <br>

GitHub Microsoft-365-Defender-Hunting-Queries <br>
https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Webcasts/TrackingTheAdversary

## Microsoft Sentinel webinar / KQL part 1-3 
After Microsoft 365 Defender / Webcast, I also continued to explore more deeper about KQL. For people using Microsoft Sentinel and Azure Data Explorer, these webinars may be an excellent starting point for learning KQL.

1. [Azure Sentinel webinar: KQL part 1 of 3 - Learn the KQL you need for Azure Sentinel!](https://www.youtube.com/watch?v=EDCBLULjtCM)
2. [Azure Sentinel webinar: KQL part 2 of 3 - KQL hands-on lab exercises!](https://www.youtube.com/watch?v=YKD_OFLMpf8)
3. [Azure Sentinel webinar: KQL part 3 of 3 - Optimizing Azure Sentinel KQL queries performance!](https://www.youtube.com/watch?v=jN1Cz0JcLYU)

## KQL cheat sheet
1. [Azure Data Explorer KQL cheat sheets](https://techcommunity.microsoft.com/t5/azure-data-explorer-blog/azure-data-explorer-kql-cheat-sheets/ba-p/1057404)
2. [Microsoft Threat Protection advanced hunting cheat sheet](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/microsoft-threat-protection-advanced-hunting-cheat-sheet/ba-p/1505100) 

## KQL reference (MS docs)
1. [KQL quick reference | Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
2. [String operators - Azure Data Explorer | Microsoft Learn!](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/datatypes-string-operators)
3. [Query best practices - Azure Data Explorer | Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)

## Microsoft 365 Defender, Advanced Hunting (MS docs)
Learn the schema tables - App, Endpoint, Identity and Email in Microsoft 365 Defender.
1. [Data tables in the Microsoft 365 Defender advanced hunting schema](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide)<br>

Also, there are a number of out-of-the-box queries.<br>

2. [Hunt for threats across devices, emails, apps, and identities with advanced hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-emails-devices?view=o365-worldwide)

## KC7 
In KC7, you will be able to learn KQL step by step. After the initial training, you will be a member of SOC team and take a first case with real hunting experience. At the end of this KC7, you will be confident how you are going to hunt some suspicious activities by KQL.
1. KC7 Website (https://kc7cyber.com/) 
2. KC7 GitHub (https://github.com/kkneomis/kc7)
3. KC7 setup video : [KC7 Loading cybersecurity data into Azure Data Explorer](https://www.youtube.com/watch?v=aHJxEHIHq0k) <br>

For importing data, you can get it from here (https://github.com/kkneomis/kc7_data/tree/main/envolvelabs)

## Kusto Detective Agency
Kusto Detective Agency is an interactive big data contest and gives you 5 missions. You will be one of the detectives in the team and deal with (find out the answer) missions by using KQL.
1. Kusto Detective Agency website (https://detective.kusto.io/)
2. Kusto Detective Agency short video : [Kusto Detective Agency - an interactive big data contest](https://www.youtube.com/watch?v=BaW0qsxxYRc)
> Welcome to the Kusto Detective agency, rookie!  Be prepared to flex your investigative muscles as you use your big data skills to solve our most challenging cases.  Prizes and awards are up for grabs if you are successful!

## Microsoft 365 Defender sample query
https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
