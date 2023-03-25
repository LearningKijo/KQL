# KQL - information center 💻
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure%20Data%20Explorer-%230078D4.svg?&style=popout&logo=azure%20data%20explorer&logoColor=white"/></a>
<a href="https://www.linkedin.com/in/kijo-niimura/"><img src="https://img.shields.io/badge/-Linkedin-0077B5.svg?logo=linkedin&style=popout"></a>

KQL stands for "Kusto Query Language" and is a powerful language for hunting specific activities and data. Microsoft Sentinel (SOAR) and Microsoft 365 Defender (Advanced Hunting) are great examples of using KQL. However, leveraging KQL might be a bit challenging if you don't have SQL or programming background. When I started learning KQL, I had no idea how to begin as a learning process due to no programming/SQL experience. Throughout my KQL journey, I would like to share some of the best resources for learning KQL. At the same time, I would like to provide **"Hunting Queries"** in KQL-XDR-Hunting repository.

### LearningKijo/KQL repo architecture

| # | Folder | About |
|:---|:---|:---|
|1 |KQL/[README.md](https://github.com/LearningKijo/KQL/blob/main/README.md) | KQL introduction & learning resource. |
|2 |KQL/[KQL-XDR-Hunting](https://github.com/LearningKijo/KQL/tree/main/KQL-XDR-Hunting)| Provide **out-of-the-box KQL hunting queries** - App, Email, Identity and Endpoint. |
|3 |KQL/[KQL-Effective-Use](https://github.com/LearningKijo/KQL/tree/main/KQL-Effective-Use)| Provide **product feature based KQL** and advanced KQL tips in XDR & SIEM. |

![image](https://user-images.githubusercontent.com/120234772/216594925-eb0c7249-0ac1-426e-bab8-539f50eafbe0.png)
> e.g. Microsoft 365 Defender portal | Advanced Hunting  

# KQL Webinar 
### Microsoft 365 Defender / Webcast 
This webinar is an excellent resource for those who are new to KQL in Microsoft 365 Defender. Each webinar in the series covers the fundamentals of KQL and demonstrates great use cases. As my work mainly focuses on XDR in Microsoft 365 Defender, I found these webinars particularly helpful and informative.

Webcast 1 - 4 series 
1. [M365 Defender (MTP) webinar: Tracking the Adversary E1: KQL Fundamentals](https://www.youtube.com/watch?v=0D9TkGjeJwM).
2. [M365 Defender (MTP) webinar: Tracking the Adversary E2: Joins](https://www.youtube.com/watch?v=LMrO6K5TWOU).
3. [M365 Defender (MTP) webinar: Tracking the Adversary, E3: Summarizing, Pivoting, and Visualizing Data](https://www.youtube.com/watch?v=UKnk9U1NH6Y).
4. [M365 Defender (MTP) webinar: Tracking the Adversary E4 Let’s hunt! Applying KQL to incident tracking](https://www.youtube.com/watch?v=2EUxOc_LNd8&list=RDCMUCGTUbqE3SJiLgtvWjIkSQuQ&index=3). <br>

> **Note** : [GitHub Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/tree/master/Webcasts/TrackingTheAdversary)

### Microsoft Sentinel webinar / KQL part 1-3 
After attending the Microsoft 365 Defender Webcast, I continued to explore KQL in greater depth. For those using Microsoft Sentinel and Azure Data Explorer, these webinars can provide an excellent starting point for learning KQL.

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
In KC7, you will learn KQL step by step. After the initial training, you will become a member of the SOC team and gain real-world hunting experience with your first case. By the end of KC7, you will be confident in your ability to hunt down suspicious activities using KQL.

**Get started !!**
[Practice Pivoting and Analysis - KC7 (kc7cyber.com)](https://kc7cyber.com/modules/practice-pivoting-and-analysis/)

![image](https://user-images.githubusercontent.com/120234772/225783624-91b8c734-fb39-4a92-9997-8451b3c9e5ba.png)


## Kusto Detective Agency
Kusto Detective Agency is an interactive big data contest and gives you 5 missions. You will be one of the detectives in the team and deal with (find out the answer) missions by using KQL.
1. Kusto Detective Agency website (https://detective.kusto.io/)
2. Kusto Detective Agency short video : [Kusto Detective Agency - an interactive big data contest](https://www.youtube.com/watch?v=BaW0qsxxYRc)
> Welcome to the Kusto Detective agency, rookie!  Be prepared to flex your investigative muscles as you use your big data skills to solve our most challenging cases.  Prizes and awards are up for grabs if you are successful!

![image](https://user-images.githubusercontent.com/120234772/226299505-b04ff9ab-9e46-4121-8a4f-f4fcabb60e04.png)


## Microsoft 365 Defender sample query
https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender

#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
