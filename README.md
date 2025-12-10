# Incident Report: Unauthorized Cloud Infrastructure Access & Endpoint Anomalies
**Project:** BOTSv3 Incident Analysis (COMP3010)  
**Author:** Matthew Fish  
**Date:** 05 December 2025  
**Reporting Authority:** Chief Information Security Officer (CISO), Frothly Security Operations Center  
**Classification:** INTERNAL / CONFIDENTIAL

---

## Table of Contents
1. [Introduction](#1-introduction)
2. [SOC Roles & Incident Handling Methodology](#2-soc-roles--incident-handling-methodology)
    * [2.1 Application of the NIST Cycle](#21-application-of-the-nist-cycle)
3. [Environment Setup & Dataset Ingestion](#3-environment-setup--dataset-ingestion)
4. [Incident Investigation (Guided Analysis)](#4-incident-investigation-guided-analysis)
    * [4.1 IAM Account Auditing](#41-iam-account-auditing-question-1)
    * [4.2 MFA Compliance Check](#42-mfa-compliance-check-question-2)
    * [4.3 Web Server Asset Identification](#43-web-server-asset-identification-question-3)
    * [4.4 S3 Bucket Permissions Analysis](#44-s3-bucket-permissions-analysis-question-4)
    * [4.5 Attribution of Actions](#45-attribution-of-actions-question-5)
    * [4.6 Data Exposure Scope](#46-data-exposure-scope-question-6)
    * [4.7 Unauthorized Artifact Upload](#47-unauthorized-artifact-upload-question-7)
    * [4.8 Endpoint Anomalies](#48-endpoint-anomalies-question-8)
5. [Conclusion & Strategic Recommendations](#5-conclusion--strategic-recommendations)
6. [References](#6-references)
7. [Appendix A: Video Presentation](#7-appendix-a-video-presentation)
8. [Appendix B: AI Declaration](#8-appendix-b-ai-declaration)

---

## 1. Introduction 

This report presents a forensic investigation into security anomalies within Frothly’s cloud and endpoint infrastructure using the BOTSv3 dataset in Splunk. The scope is limited to AWS CloudTrail, S3 access logs, and Windows endpoint telemetry, with a focus on identifying misconfigurations and behaviours consistent with insider misuse or credential compromise. The primary audience is the CISO and SOC team, and the report is written as an internal incident record to inform SOC process improvements.

The report is structured as follows: Section 2 links the investigation to SOC roles and the NIST incident lifecycle; Section 3 documents Splunk setup and dataset ingestion; Section 4 provides guided analysis answering the BOTSv3 question set; Section 5 consolidates conclusions and presents a prioritised action plan. 

---

## 2. SOC Roles & Incident Handling Methodology 

Security Operations Centers (SOC) rely on a tiered structure to manage alert fatigue and ensure critical threats are escalated appropriately [1]. 
* **Tier 1 Analysts (Triage):** Monitor SIEM alerts to distinguish false positives from genuine security events. 
* **Tier 2 Analysts (Incident Responders):** This investigation assumes the role of a Tier 2 analyst. The focus is not merely viewing alerts, but correlating data across multiple sourcetypes (AWS, Endpoint, Network) to reconstruct the attack timeline. 
* **Tier 3 Analysts (Threat Hunters):** Proactively search for threats that evade automated detection rules. 

### 2.1 Application of the NIST Cycle

BOTSv3 simulates Frothly's production environment, including AWS web workloads, S3 storage, and corporate endpoints. Aligned with the **NIST SP 800-61 Rev 3** lifecycle, this investigation aims to [2]:

* **Identify & Protect:** Audit user accounts and endpoints to uncover 'Least Privilege' violations.

* **Detect & Respond:** Analyze logs to determine exactly how an S3 bucket was exposed, who was responsible, and what data was at risk.

* **Recover & Govern:** Assess the failures in configuration and governance that caused the breach to propose strategic improvements for future resilience.


---

## 3. Environment Setup & Dataset Ingestion

### 3.1 Environment Setup

A local Splunk Enterprise instance was deployed on an Ubuntu virtual machine to mimic how a SOC would typically host a centralised SIEM in a controlled environment. The VM approach isolates the BOTSv3 lab from production resources while still allowing realistic log volume and query performance. Splunk was installed under /opt to follow Linux best practice for third‑party software and keep application files separate from the OS.

```bash
# Commands used for installation
wget -O splunk-8.x.x-linux-2.6-amd64.tgz 'https://download.splunk.com/...'
sudo tar -xvzf splunk-*.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
```

![Figure 1: Verification of Splunk services running on localhost.](Images/SplunkServer.png)

### 3.2 Dataset Ingestion

The BOTSv3 dataset was downloaded from the official Splunk GitHub repository and installed as a dedicated app, with all events indexed into a separate botsv3 index. This separation prevents test data from polluting the default index and allows focused searches using index=botsv3 across multiple sourcetypes such as aws:cloudtrail, aws:s3:accesslogs, WinHostMon, hardware and access_combined. Basic validation was performed by checking index event counts, confirming that expected sourcetypes were present, and running sample searches to ensure CloudTrail, S3 and endpoint logs were ingested correctly before starting the investigation.

![Figure 2: BOTSv3 dataset being retrieved from the Git repository.](Images/BOTSv3Github.png)
![Figure 3: The extracted dataset directory.](Images/BOTSv3DataSet.png)
![Figure 4: Dataset ingested as an app.](Images/BOTSv3AppsInstall.png)
![Figure 5: Confirmation of indexed events within the BOTSv3 dataset.](Images/BOTSv3Index.png)

---

## 4. Incident Investigation (Guided Analysis)

### 4.1 IAM Account Auditing (Question 1)

**Objective:** Identify all IAM users accessing AWS services to audit for Least Privilege violations.

**Analysis:** Querying **aws:cloudtrail** for **userIdentity.type="IAMUser"** allows us to isolate human actors from automated service roles. The **stats** command grouped these by username.

```bash 
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" userIdentity.type="IAMUser"
| stats values(eventSource) as “Services Accessed” by userIdentity.userName 
```

**Finding:** The users **bstoll,btun,splunk_access,** and **web_admin** were identified accessing AWS services. Knowing exactly which IAM users access AWS services allows the SOC to baseline normal behaviour, detect misuse of generic accounts like web_admin, and investigate suspicious or dormant accounts that suddenly become active.

![Figure 6: Statistical table of IAM users and the specific AWS services they accessed.](Images/Question1.png)

### 4.2 MFA Compliance Check (Question 2)

**Objective:** Detect AWS API activity performed without Multi-Factor Authentication (MFA).

**Analysis:** To identify AWS API activity occurring without MFA, I performed a keyword search using **mfa** against the **aws:cloudtrail** sourcetype. I explicitly excluded ConsoleLogin events to isolate programmatic API calls from web interface logins. This revealed the nested JSON path **userIdentity.sessionContext.attributes.mfaAuthenticated**. 

**Finding: 2,155 events** were generated with **mfaAuthenticated=false**. This volume of non-MFA activity represents a violation of the Protect function of the NIST CSF (Identity Management). In a Zero Trust architecture, the assumption that a valid API key implies a trusted user is known as "Implicit Trust"—a vulnerability that allowed the attacker to bypass verification. Monitoring this field enables the SOC to build alerts for high‑risk API activity, prioritise incident response on compromised keys, and drive enforcement of stronger authentication policies [6]. 

```bash
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" eventName!="ConsoleLogin" | stats count by userIdentity.sessionContext.attributes.mfaAuthenticated 
```

![Figure 7: The nested JSON path identifying MFA status.](Images/Question2.0.png)
![Figure 8: Count of events where MFA authentication was absent.](Images/Question2.1.png)

### 4.3 Web Server Asset Identification (Question 3)

**Objective:** Characterize the hardware profile of the web servers.

**Analysis:** Using **sourcetype="hardware"**, I identified hosts named **gacrux**. To verify that the 'gacrux' endpoints identified in the hardware logs were indeed the web servers, I analysed the naming convention and cross-referenced the hostname with the *access_combined* sourcetype. This revealed that these hosts were generating Apache web logs. Furthermore, I observed high-frequency HTTP GET requests from the User-Agent **ELB-HealthChecker/2.0**. This specific traffic pattern confirms that these instances are registered targets behind an AWS Elastic Load Balancer [5], actively serving HTTP traffic.  

**Finding:** I found the CPU_TYPE listed as **Intel Xeon CPU E5-2676 v3**. Mapping hardware profiles and hostnames to web‑facing services gives the SOC an accurate asset inventory, which is essential for scoping incidents, correlating web logs to specific servers, and spotting performance anomalies that may indicate attacks such as cryptojacking or DoS.

```bash
# Query: 
index=botsv3 sourcetype=”hardware” 
index=botsv3 sourcetype="access_combined" host="gacrux.i-0920036c8ca91e501" http*
```

![Figure 9: List of different web servers](Images/Question3.png)
![Figure 10: Hardware log analysis identifying the CPU type.](Images/Question3.1.png)

### 4.4 S3 Bucket Permissions Analysis (Question 4)

**Objective:** Identify the specific API call that exposed data to the public.

**Analysis:** I began by searching for **eventName='PutBucketAcl'**, which tracks changes to S3 bucket permissions. This returned two events. Instead of guessing, I analysed the 'Interesting Fields' sidebar to find parameters related to access control.

**Finding:** I discovered the field requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI. Checking the values for this field, I spotted http://acs.amazonaws.com/groups/global/AllUsers - this AWS identifier for public access. I added this to my search to confirm the single relevant event, pointing to Event ID **ab45689d-69cd-41e7-8705-5350402cf7ac**.

While detecting PutBucketAcl events allows for reactive containment, the fact that this command succeeded reveals a systemic governance failure. Modern AWS environments utilize "S3 Block Public Access" settings at the account level to override such ACLs. The success of this action proves that Frothly's SOC lacks a Cloud Security Posture Management (CSPM) tool [7] to enforce baseline compliance, allowing a simple configuration error to escalate into a public data breach

```bash
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" 
requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI="http://acs.amazonaws.com/groups/global/AllUsers" 
```

![Figure 11: The SPL query for S3 buckets](Images/Question4.0.png)
![Figure 12: The fields sidebar showing the ACL URI JSON Path](Images/Question4.1.png)
![Figure 13: JSON payload identifying the specific Event ID granting 'AllUsers' access.](Images/Question4.2.png)

### 4.5 Attribution of Actions (Question 5)

**Objective:** Determine the actor responsible for the configuration change.

**Analysis:** Examining the userIdentity object within the Event ID identified in Section 4.4.

**Finding:** The user **bstoll** (Bud) executed the command. This allows the SOC to pivot the investigation: is Bud a malicious insider, or were his non-MFA credentials (identified in Section 4.2) compromised?

![Figure 14: Attribution of the 'PutBucketAcl' event to user 'bstoll'.](Images/Question5.png)

### 4.6 Data Exposure Scope (Question 6)

**Objective:** Identify the exposed resource.

**Analysis:** The requestParameters field in the log entry specified the target bucket.

**Finding:** The bucket name is **frothlywebcode** which implies source code exposure, risking API keys or IP theft (**MITRE ATT&CK T1530** [3]). The identification allows the SOC to estimate business impact and prioritise remediation.

![Figure 15: Target resource identification confirming the bucket 'frothlywebcode'.](Images/Question6.png)

### 4.7 Unauthorized Artifact Upload (Question 7)

**Objective:** Confirm if the exposure was exploited.

**Analysis:** I queried aws:s3:accesslogs for the .txt extension and PUT method to find successful uploads by external parties.

**Finding:** A file named **OPEN_BUCKET_PLEASE_FIX.txt** was uploaded. The filename suggests a "Gray Hat" security researcher.  Confirming that external actors were able to write into the bucket proves that integrity was breached, which helps the SOC justify immediate containment, deeper threat hunting for potential payloads, and long‑term hardening of cloud storage controls.

```bash
# Query: 
index=botsv3 sourcetype="aws:s3:accesslogs" .txt PUT 
```

![Figure 16: Access logs confirming the upload of the text file.](Images/Question7.png)

### 4.8 Endpoint Anomalies (Question 8)

**Objective:** Detect configuration drift in endpoints.

**Analysis:** Using sourcetype="WinHostMon", I grouped hosts by OS version. However, the standard host field only provided the short hostname, leaving the domain uncertain. To resolve this, I performed some investigative digging through the raw log entries for BSTOLL-L.

**Finding:** The ComputerName field reveals the full path BSTOLL-L.froth.ly; unlike most hosts running Windows 10 Pro, this endpoint runs Windows 10 Enterprise, indicating an administrator workstation linked to the same user and timeframe as the risky cloud activity. This makes it a high-value assest and priority for SOC containment. If compromised, BSTOLL-L.froth.ly could hold credentials enabling lateral movement [4] across the domain, escalating the breach from a cloud misconfiguration to a full domain compromise.

```bash
# Query: 
index=botsv3 sourcetype="WinHostMon" | stats count by host, OS Version 
index=botsv3 host="BSTOLL-L" computername
```

![Figure 17: OS Version comparison identifying the outlier endpoint.](Images/Question8.png)
![Figure 18: The full bstoll computername.](Images/Question8.1.png)

---

## 5. Conclusion & Strategic Recommendations

The investigation confirms that a preventable cloud misconfiguration, executed by the user bstoll from the high‑privilege endpoint BSTOLL-L.froth.ly, exposed the frothlywebcode S3 bucket to the public internet and allowed at least one external write operation. This occurred in an environment where MFA was not enforced for API activity and no automated control prevented or rolled back risky ACL changes, significantly increasing the likelihood and impact of credential theft and data exposure.

From a SOC point of view, the case highlights the need to link Tier 1 CloudTrail monitoring with Tier 2 correlation across cloud, S3 and endpoint logs, and Tier 3 hunting for similar misconfigurations and lateral movement paths. Key lessons are to default‑deny S3 access, enforce MFA on all privileged API usage, and treat administrator endpoints such as BSTOLL-L.froth.ly as high‑value assets needing additional monitoring and control.

### 5.1 Immediate containment (0–24 hours)
* Block public access on frothlywebcode and verify no other buckets grant *AllUsers/AuthenticatedUsers* ACLs.
* Rotate credentials for bstoll and related IAM roles, and remove unapproved uploads such as *OPEN_BUCKET_PLEASE_FIX.txt* after preserving evidence.

### 5.2 Short‑term recovery (next 1–2 weeks)
* Enforce an IAM condition that denies API actions unless MFA is true for all human users and high‑risk roles.
* Isolate **BSTOLL-L.froth.ly** for full forensic analysis, including malware scanning, credential dump checks, and review of administrative tool usage.
* Develop and deploy rules that alert on *PutBucketAcl* granting public access, high‑volume non‑MFA API activity, and changes originating from privileged endpoints.

### 5.3 Long‑term SOC improvements (1–3 months)
* Implement a CSPM capability to continuously detect and auto‑remediate public S3 buckets and other misconfigurations [7].
* Conduct a least‑privilege review of IAM users and roles, ensuring developers cannot modify global ACLs without change control and dual authorisation.
* Integrate scenarios like this BOTSv3 incident into SOC runbooks and training so Tier 1–3 analysts can rapidly recognise similar patterns and execute coordinated response and recovery.

---

## 6. References

* [1] Security Operations Center (SOC) roles and Responsibilities (no date) Palo Alto Networks. Available at: https://www.paloaltonetworks.co.uk/cyberpedia/soc-roles-and-responsibilities (Accessed: 07 December 2025). 
* [2] Nelson, A. et al. (2025) Incident Response Recommendations and Considerations for Cybersecurity Risk Management, NIST. Available at: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf (Accessed: 07 December 2025). (accessed Dec. 7, 2025). 
* [3] Borges, D. and @1njection (2017) Remote Services: SMB/windows admin shares, Remote Services: SMB/Windows Admin Shares, Sub-technique T1021.002 - Enterprise | MITRE ATT&CK®. Available at: https://attack.cloudfall.cn/techniques/T1021/002/ (Accessed: 07 December 2025). 
* [4] AppOmni et al. (2019) Data from cloud storage, Data from Cloud Storage, Technique T1530 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1530/ (Accessed: 07 December 2025). 
* [5] (No date) How elb works - elastic load balancing. Available at: https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/how-elastic-load-balancing-works.html (Accessed: 07 December 2025). 
* [6] G, Alistair. (22/01/2025) How attackers bypass multi-factor authentication. Available at: https://www.bugcrowd.com/blog/mfa-security-part-1-how-attackers-bypass-multi-factor-authentication/ (Accessed: 07 December 2025). 
* [7] (12/01/2025) What is Cloud Security Posture Management (CSPM). Available at: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management (Accessed: 07 December 2025).

---

## 7. Appendix A: Video Presentation

https://youtu.be/WJN0MkBIe7c

---

## 8. Appendix B: Generative AI Declaration
