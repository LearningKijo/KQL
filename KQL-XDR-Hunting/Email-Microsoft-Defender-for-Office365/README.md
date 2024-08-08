# Email-related KQL queries
<a href="https://twitter.com/kj_ninja25"><img alt="X (formerly Twitter) Follow" src="https://img.shields.io/twitter/follow/kj_ninja25"></a>
<a href="https://www.linkedin.com/in/kijo-girardi/"><img src="https://img.shields.io/badge/-Linkedin-0077B5.svg?logo=linkedin&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure-KQL-00B2FF.svg?logo=microsoftazure&style=popout"></a>
<a href="https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/"><img src="https://img.shields.io/badge/Azure%20Data%20Explorer-%230078D4.svg?&style=popout&logo=azure%20data%20explorer&logoColor=white"/></a>

Thank you for visiting @LearningKijo KQL repository. 
In this repository, I am excited to share email-based out-of-the-box queries related to ***Microsoft Defender for Office 365 (MDO)*** and ***Exchange Online Protection (EOP)***.

| Product | KQL query | Comments |
|:--------|:----------|:----------|
| MDO     | [01-Email-Audit-SafeAttachments-GlobalSetting.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/01-Email-Audit-SafeAttachments-GlobalSetting.md) |
| EOP     | [02-EOP-Detection-Daily-Percentage.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/02-EOP-Detection-Daily-Percentage.md) |
| MDO     | [03-MDO-Detection-Daily-Percentage.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/03-MDO-Detection-Daily-Percentage.md) |
| EOP     | [04-EOP-MalwareDetection-Filtering.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/04-EOP-MalwareDetection-Filtering.md) |
| EOP     | [05-EOP-PhishingDetection-Filtering.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/05-EOP-PhishingDetection-Filtering.md) |
| MDO     | [06-MDO-MalwareDetection-Filtering.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/06-MDO-MalwareDetection-Filtering.md) |
| MDO     | [07-MDO-PhishingDetection-Filtering.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/07-MDO-PhishingDetection-Filtering.md) |
| MDO     | [08-MDO-UserList-for-RemediationAction.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/08-MDO-UserList-for-RemediationAction.md) |
| MDO/EOP | [09-Email-MalwareDetection-byAccount.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/09-Email-MalwareDetection-byAccount.md) |
| MDO     | [10-UserInsights-ClickedSuspiciousURLs-PhishMalware-Emails.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/10-UserInsights-ClickedSuspiciousURLs-PhishMalware-Emails.md) |
| MDO/EOP | [11-Email-Weekly-DetectionTrend.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/11-Email-Weekly-DetectionTrend.md) |
| MDO/EOP | [12-Email-MalwarePhishing-Detection-Trends.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/12-Email-MalwarePhishing-Detection-Trends.md)  | Visualize Targeted Email Accounts |
| EOP     | [13-Email-Spam-Detection-Trend.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/13-Email-Spam-Detection-Trend.md)  | Visualize Targeted Email Accounts |
| MDO     | [14-MDO-QRcode-VolumeInboundEmails.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/14-MDO-QRcode-VolumeInboundEmails.md) | from [MS blog](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730) |
| MDO     | [15-MDO-QRcode-DeliveredEmail.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/15-MDO-QRcode-DeliveredEmail.md) | from [MS blog](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730) |
| MDO     | [16-Emails-QRcode-SuspiciousKeywordsSubject.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/16-Emails-QRcode-SuspiciousKeywordsSubject.md) | from [MS blog](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730) |
| MDO     | [17-MDO-DetectedURL-Insights.md](https://github.com/LearningKijo/KQL/blob/main/KQL-XDR-Hunting/Email-Microsoft-Defender-for-Office365/MDO-EOP-Query-Repository/17-MDO-DetectedURL-Insights.md) | 
#### Disclaimer
The views and opinions expressed herein are those of the author and do not necessarily reflect the views of company.
