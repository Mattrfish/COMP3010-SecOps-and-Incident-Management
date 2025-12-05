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
3. [Environment Setup & Data Ingestion](#3-environment-setup--data-ingestion)
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

This report presents a forensic investigation into security anomalies within Frothly’s cloud and endpoint infrastructure using the BOTSv3 dataset in Splunk. The scope is limited to AWS CloudTrail, S3 access logs, and Windows endpoint telemetry, with a focus on identifying misconfigurations and behaviours consistent with insider misuse or credential compromise. The primary audience is the Chief Information Security Officer (CISO) and security management team, and the report is written as an internal incident record to inform SOC process improvements.

​BOTSv3 simulates a production environment in which Frothly hosts web workloads on AWS, stores application code in S3, and joins endpoints to the froth.ly domain. Within this context, the investigation aims to:

* ​Identify IAM users and endpoints involved in risky or anomalous activity.

* Determine how an S3 bucket became publicly accessible and whether it was abused.

* Assess the impact of missing MFA controls and endpoint configuration drift on overall SOC risk.

The report is structured as follows: Section 2 links the investigation to SOC tiers and the NIST incident lifecycle; Section 3 documents Splunk setup and dataset ingestion; Section 4 provides guided analysis answering the BOTSv3 question set; Section 5 consolidates conclusions and presents a prioritised action plan. 

---

## 2. SOC Roles & Incident Handling Methodology 

Security Operations Centers (SOC) rely on a tiered structure to manage alert fatigue and ensure critical threats are escalated appropriately [1]. 
* **Tier 1 Analysts (Triage):** Monitor SIEM alerts (e.g., Splunk) to distinguish false positives from genuine security events. 
* **Tier 2 Analysts (Incident Responders):** This investigation assumes the role of a Tier 2 analyst. The focus is not merely viewing alerts, but correlating data across multiple sourcetypes (AWS, Endpoint, Network) to reconstruct the attack timeline. 
* **Tier 3 Analysts (Threat Hunters):** Proactively search for threats that evade automated detection rules. 

### Application of the NIST Cycle 

This investigation follows the **NIST SP 800-61** Incident Response Lifecycle [2]: 
1. **Preparation:** The environment was prepared by ingesting BOTSv3 data into a localized Splunk instance (See Section 3). 
2. **Detection & Analysis:** Utilizing Splunk Search Processing Language (SPL) to query *aws:cloudtrail* and *hardware* logs to identify the scope of the breach. 
3. **Containment, Eradication & Recovery:** (Detailed in Section 5) Proposing immediate revocation of public S3 access and credential rotation. 
4. **Post-Incident Activity:** Documenting the "Lessons Learned" to prevent recurrence through stricter IAM policies.

---

## 3. Installation & Data Preparation

### Environment Setup

### 3.1 Splunk Installation 

A local instance of Splunk Enterprise was deployed on an Ubuntu Virtual Machine. The installer was extracted to `/opt`, adhering to Linux best practices for unbundled software.

```bash
# Commands used for installation
wget -O splunk-8.x.x-linux-2.6-amd64.tgz 'https://download.splunk.com/...'
sudo tar -xvzf splunk-*.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
```

![Figure 1](Images/SplunkServer.png)
*Figure 1: Verification of Splunk services running on localhost.*

### 3.2 Dataset Ingestion

The BOTSv3 dataset was retrieved from the official Splunk GitHub repository and ingested as a standalone Splunk App. Segregating this data into a specific index (botsv3) ensures efficient query performance and prevents data pollution of the main index.

![Figure 2](Images/BOTSv3Github.png)
*Figure 2: BOTSv3 dataset being retrieved from the Git repository.*
![Figure 3](Images/BOTSv3DataSet.png)
*Figure 3: The extracted dataset directory.*

```bash
cp -r botsv3_data_set /opt/splunk/etc/apps/
```
![4](Images/BOTSv3AppsInstall.png)
*Figure 4: Dataset ingested as an app.*
![5](Images/BOTSv3Index.png)
*Figure 5: Confirmation of indexed events within the BOTSv3 dataset.*

---

## 4. Incident Investigation (Guided Analysis)

### 4.1 IAM Account Auditing (Question 1)

**Objective:** Identify all IAM users accessing AWS services to audit for Least Privilege violations.

**Analysis:** Querying ``aws:cloudtrail`` for ``userIdentity.type="IAMUser"`` allows us to isolate human actors from automated service roles. The ``stats`` command grouped these by username.

```bash 
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" userIdentity.type="IAMUser"
| stats values(eventSource) by “Services Accessed” by userIdentity.userName 
```

**Finding:** The users *bstoll,btun,splunk_access,and web_admin* were identified accessing AWS services. Monitoring this list is critical for detecting dormant accounts that suddenly become active. Specifically, the presence of generic accounts like web_admin performing actions is a security risk, as it obscures individual accountability.

![Figure 6](Images/Question1.png)
Figure 6: Statistical table of IAM users and the specific AWS services they accessed.

### 4.2 MFA Compliance Check (Question 2)

**Objective:** Detect AWS API activity performed without Multi-Factor Authentication (MFA).

**Analysis:** To identify AWS API activity occurring without MFA, I performed a keyword search using *mfa* against the *aws:cloudtrail* sourcetype. I explicitly excluded ConsoleLogin events to isolate programmatic API calls from web interface logins. This revealed the nested JSON path **userIdentity.sessionContext.attributes.mfaAuthenticated**. 

**Finding: 2,155 events** were generated with *mfaAuthenticated=false*. This high volume of non-MFA activity represents a critical vulnerability. If an attacker compromises a key (like *bstoll*'s), they have unimpeded access to the cloud environment.

MFA is a critical layer of security. SOC analysts need to monitor MFA for bypasses, credential compromises, and insider abuse. Programmatic access (API Keys) lacking MFA is often the primary vector for automated attacks; unlike a console login which requires human interaction, a compromised API key without MFA allows scripts to exfiltrate data at machine speed.

```bash
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" eventName!="ConsoleLogin" | stats count by userIdentity.sessionContext.attributes.mfaAuthenticated 
```

![Figure 7](Images/Question2.0.png)
*Figure 8: The nested JSON path identifying MFA status.*
![Figure 8](Images/Question2.1.png)
*Figure 8: Count of events where MFA authentication was absent.*

### Web Server Asset Identification (Question 3)

**Objective:** Characterize the hardware profile of the web servers.

**Analysis:** Using *sourcetype="hardware"*, I identified hosts named *gacrux*. To verify that the 'gacrux' endpoints identified in the hardware logs were indeed the web servers, I analysed the naming convention and cross-referenced the hostname with the *access_combined* sourcetype. This revealed that these hosts were generating Apache web logs. Furthermore, I observed high-frequency HTTP GET requests from the User-Agent *ELB-HealthChecker/2.0*. This specific traffic pattern confirms that these instances are registered targets behind an AWS Elastic Load Balancer [5], actively serving HTTP traffic.  

**Finding:** I found the CPU_TYPE listed as **Intel Xeon CPU E5-2676 v3**.

An accurate Asset Inventory is a foundational SOC requirement. Understanding hardware allows analysts to distinguish between legitimate resource usage and malicious activity. For example, if a web server known to run high-performance CPUs suddenly experiences 100% utilization during low-traffic periods, it is a strong indicator of Cryptojacking (unauthorized crypto-mining) or a Denial of Service (DoS) attack.

```bash
# Query: 
index=botsv3 sourcetype=”hardware” 
index=botsv3 sourcetype="access_combined" host="gacrux.i-0920036c8ca91e501" http*
```

![Figure 9](Images/Question3.png)
*Figure 9: List of different web servers*
![Figure 10](Images/Question3.1.png)
*Figure 10: Hardware log analysis identifying the CPU type.*

### 4.4 S3 Bucket Permissions Analysis (Question 4)

**Objective:** Identify the specific API call that exposed data to the public.

**Analysis:** I began by searching for *eventName='PutBucketAcl'*, which tracks changes to S3 bucket permissions. This returned two events. Instead of guessing, I analysed the 'Interesting Fields' sidebar to find parameters related to access control.

**Finding:**I discovered the field requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI. Checking the values for this field, I spotted http://acs.amazonaws.com/groups/global/AllUsers - this AWS identifier for public access. I added this to my search to confirm the single relevant event, pointing to Event ID **ab45689d-69cd-41e7-8705-5350402cf7ac**.

Misconfigured S3 buckets are a leading cause of data breaches. SOC analysts must set up real-time alerts for PutBucketAcl events that grant "AllUsers" access. Rapid detection allows the SOC to revoke public access before sensitive data is exfiltrated by scanners or bots. 

```bash
# Query: 
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" 
requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI="http://acs.amazonaws.com/groups/global/AllUsers" 
```

![Figure 11](Images/Question4.0.png)
*Figure 11: The SPL query for S3 buckets*
![Figure 12](Images/Question4.1.png)
*Figure 12: The fields sidebar showing the ACL URI JSON Path*
![Figure 13](Images/Question4.2.png)
*Figure 13: JSON payload identifying the specific Event ID granting 'AllUsers' access.*

### 4.5 Attribution of Actions (Question 5)

**Objective:** Determine the actor responsible for the configuration change.

**Analysis:** Examining the userIdentity object within the Event ID identified in Section 4.4.

**Finding:** The user **bstoll** (Bud) executed the command. This allows the SOC to pivot the investigation: is Bud a malicious insider, or were his non-MFA credentials (identified in Section 4.2) compromised?

![Figure 14](Images/Question5.png)
*Figure 14: Attribution of the 'PutBucketAcl' event to user 'bstoll'.*

### 4.6 Data Exposure Scope (Question 6)

**Objective:** Identify the exposed resource.

**Analysis:** The requestParameters field in the log entry specified the target bucket.

**Finding:** The bucket name is frothlywebcode.

**Risk Assessment:** The name implies this bucket contains source code. Exposure of source code often leads to the discovery of hardcoded API keys or intellectual property theft. This behavior maps to **MITRE ATT&CK T1530** (Data from Cloud Storage) [3], where adversaries access data from unsecured cloud buckets.

![Figure 15](Images/Question6.png)
*Figure 15: Target resource identification confirming the bucket 'frothlywebcode'.*

### 4.7 Unauthorized Artifact Upload (Question 7)

**Objective:** Confirm if the exposure was exploited.

**Analysis:** I queried aws:s3:accesslogs for the .txt extension and PUT method to find successful uploads by external parties.

**Finding:** A file named OPEN_BUCKET_PLEASE_FIX.txt was uploaded.

**Damage Assessment:** The filename suggests a "Gray Hat" security researcher. However, the fact that a write operation was possible confirms that integrity has been lost. If a researcher could upload a text file, a malicious actor could have utilized this same open door to upload webshells, ransomware payloads, or command-and-control scripts.

```bash
# Query: 
index=botsv3 sourcetype="aws:s3:accesslogs" .txt PUT 
```

![Figure 16](Images/Question7.png)
Figure 16: Access logs confirming the upload of the text file.

### 4.8 Endpoint Anomalies (Question 8)

**Objective:** Detect configuration drift in endpoints.

**Analysis:** Using sourcetype="WinHostMon", I grouped hosts by OS version. However, the standard host field only provided the short hostname, leaving the domain uncertain. To resolve this, I performed some investigative digging through the raw log entries for BSTOLL-L

**Finding:** After scanning through the event details, I located the ComputerName field, which explicitly listed the full network path as BSTOLL-L.froth.ly. While most hosts run Windows 10 Pro, the endpoint BSTOLL-L.froth.ly is running Microsoft Windows 10 Enterprise. 

**Significance:** Enterprise editions are typically reserved for administrators. The combination of an Admin machine (BSTOLL-L), used by a user (bstoll) who fails to use MFA (Section 4.2), and who recently exposed sensitive cloud data (Section 4.4), marks this endpoint as the priority target for containment. If this endpoint is compromised, it likely holds cached credentials that could facilitate Lateral Movement (MITRE T1021) [4] across the internal network, escalating the breach from a cloud misconfiguration to a full domain compromise.

```bash
# Query: 
index=botsv3 sourcetype="WinHostMon" | stats count by host, OS Version 
index=botsv3 host="BSTOLL-L" computername
```

![Figure 17](Images/Question8.png)
*Figure 17: OS Version comparison identifying the outlier endpoint.*
![Figure 18](Images/Question8.1.png)
*Figure 18: The full bstoll computername.*

---

## 5. Conclusion & Strategic Recommendations

The investigation confirms that a preventable cloud misconfiguration, executed by the user bstoll from the high‑privilege endpoint BSTOLL-L.froth.ly, exposed the frothlywebcode S3 bucket to the public internet and allowed at least one external write operation. This occurred in an environment where MFA was not enforced for API activity and no automated control prevented or rolled back risky ACL changes, significantly increasing the likelihood and impact of credential theft and data exposure.

From a SOC perspective, the case illustrates how Tier 1 monitoring of CloudTrail anomalies must be supported by Tier 2 correlation across cloud, S3, and endpoint logs, and by Tier 3 threat hunting for similar misconfigurations and lateral movement opportunities. Key lessons learned are the need for default‑deny S3 policies, mandatory MFA on all privileged access paths, and explicit monitoring of administrator endpoints that deviate from the standard build.

### 5.1 Root Cause Analysis

* **Primary Cause:** Human error (misconfiguration of S3 ACLs).

* **Contributing Factor:** Lack of technical guardrails (MFA was not enforced for API calls).

* **Contributing Factor:** Lack of automated remediation (No CSPM tool blocked the public access change).

### 5.2 Business Impact

* **Data Loss Prevention (DLP):** The exposure of "webcode" puts the organization at risk of Intellectual Property theft.

* **Reputation:** Publicly writable buckets allow attackers to host malware on Frothly's domain, leading to domain blacklisting.

### 5.3 Remediation Action Plan (Lessons Learned)

**Immediate Containment (0-24 hours)**
* **Revoke Access:** Apply “Block Public Access” controls to frothlywebcode and verify that no other buckets grant AllUsers or AuthenticatedUsers ACLs.
* **Credential Rotation:** Force a password reset and rotate passwords and access keys for bstoll and any shared IAM roles used from BSTOLL-L.froth.ly, and revoke unused credentials
* **Sanitize Storage:** Triage S3 access logs for the exposure window, remove unapproved uploads such as OPENBUCKETPLEASEFIX.txt, and preserve artefacts for legal and compliance review.​

**Short-Term Recovery (next 1-2 weeks**
* **Enforce MFA:** Implement an IAM policy denying all actions unless *aws:MultiFactorAuthPresent* is true. This directly addresses the vulnerability found in Section 4.2.
* **Endpoint Isolation:** Isolate BSTOLL-L.froth.ly for full forensic analysis, including malware scanning, credential dump checks, and review of administrative tool usage.

**Long-Term SOC improvements (1-3 months)**
* **Implement CSPM:** Implement a Cloud Security Posture Management (CSPM) capability (for example via AWS Config or equivalent) to continuously detect and auto‑remediate public S3 buckets and other high‑risk misconfigurations.
* **Least Privilege Review:** Conduct a least‑privilege review of IAM users and roles, ensuring developers cannot modify global ACLs without change control and dual authorisation.
* **Training and Awareness:** Integrate scenarios like this BOTSv3 incident into SOC runbooks and training so Tier 1–3 analysts can rapidly recognise similar patterns and execute coordinated response and recovery.

---

## 6. References

* [1] https://www.paloaltonetworks.co.uk/cyberpedia/soc-roles-and-responsibilities
* [2] https://auditboard.com/blog/nist-incident-response
* [3] https://attack.mitre.org/techniques/T1530/
* [4] https://attack.cloudfall.cn/techniques/T1021/
* [5] https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/how-elastic-load-balancing-works.html

---

## 7. Appendix A: Video Presentation


---

## 8. Appendix B: Generative AI Declaration
