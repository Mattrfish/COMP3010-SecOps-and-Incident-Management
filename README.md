# BOTSv3 Incident Analysis 

## Introduction

In everyday cybersecurity, a Security Operations Center (SOC) is essential for 24/7 threat detection and incident response. Because modern networks generate massive amounts of data, SOC teams rely on SIEM (Security Information and Event Management) systems like Splunk. These tools allow analysts to collect and analyse logs to spot suspicious activity that humans might otherwise miss.

The BOTSv3 (Boss of the SOC version 3) exercise simulates this realistic environment, allowing users to gain hands-on experience through "Capture the Flag" tasks. The investigation targets the digital infrastructure of a fictional brewery called "Frothly." This complex dataset gathers data from various services, including Amazon AWS, Microsoft Azure, and internal endpoint logs.

The objective of this SOC simulation is to complete the assigned set of BOTSv3’s “200-level” questions using Splunk Search Processing Language (SPL). The specific focus of this investigation is on AWS cloud infrastructure events (specifically IAM access and S3 bucket misconfigurations) and endpoint hardware analysis. The goal is to use the Cyber Kill Chain methodology to reconstruct the incident.The scope of this report is strictly limited to these assigned questions. It is assumed that the provided log data is accurate and serves as the single source of truth for this timeline.

---

## SOC Roles & Incident Handling Reflection

A professional SOC is usually structured into different levels to efficiently manage security alerts. 

* **Level 1 Analysts:** Responsible for reviewing SIEM alerts to identify if they are false positives or genuine threats. 
* **Level 2 Analysts:** Handle escalated, high-priority incidents requiring deep investigation. 
* **Level 3 Analysts:** These are highly experienced analysts who search for threat indications (threat hunting), while the **SOC Manager** oversees operations and reports to the CISO. [1]

Additional roles include security engineers who are responsible for implementing security solutions and malware analysts who reverse engineer malware to improve security detection.

In this BOTSv3 exercise, I am simulating the responsibilities of a **Level 2/3 analyst**. I am not reacting to alerts like a level 1 analyst would; instead I am using Splunk SPL to search for indicators of compromise (IOCs) and reconstruct the attack timeline. 

This analysis follows the **NIST Incident Response Lifecycle** which has four connected stages: 
1. **Prevention:** The incident stems from a failure in the Prevention phase, specifically due to Frothly's misconfigured AWS cloud permissions and inadequate access controls.
2. **Detection and Analysis:** This is the primary focus of the exercise. It involves interrogating Splunk logs to distinguish between benign network noise and genuine threats, confirming the scope of the breach.
3. **Response:** The analysis provides the details of the incident so that threats can be contained and eradicated at this stage. 
4. **Recovery:** This stage focusses on "lessons learned". By defining the root cause, patches can be implemented to ensure these specific vulnerabilities are not re-exploited. [2]

---

## Installation & Data Preparation

### Environment Setup

To facilitate this investigation, a localized Splunk Enterprise instance was deployed on an Ubuntu Virtual Machine. This approach mirrors a standard SOC analyst's sandbox environment, allowing for safe log analysis without impacting production servers.

1. Splunk Installation:
The Splunk Enterprise installer (.tgz) was retrieved via the github. The package was extracted to the /opt directory. This directory is the industry-standard location for unbundled software on Linux systems, ensuring that the security tools remain separate from the core operating system files.

```bash
# Commands used for installation
wget -O splunk-8.x.x-linux-2.6-amd64.tgz 'https://download.splunk.com/...'
sudo tar -xvzf splunk-*.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
```

2. Service Initialization:
The Splunk service was started on localhost:8000.

![](Images/SplunkServer.png)

### Dataset Ingestion

The BOTSv3 dataset was retrieved from the official Splunk GitHub repository. Proper data ingestion is critical in a SOC to ensure time-stamps are parsed correctly and logs are searchable.

1. Retrieving Data:
The dataset was downloaded and extracted. In a real-world SOC, data is usually ingested via Forwarders, but for this simulation, the data was uploaded directly as a Splunk App.

![](Images/BOTSv3Github.png)
![](Images/BOTSv3DataSet.png)

2.Indexing & App Configuration:
The extracted data folder was moved to the Splunk apps directory. This ensures that all the specific field extractions and sourcetypes for the BOTSv3 data are automatically applied when Splunk restarts.

```bash
# Command used to install the BOTSv3 App
cp -r botsv3_data_set /opt/splunk/etc/apps/
```
![](Images/BOTSv3AppsInstall.png)

Segregating this data into its own index is best practice.

![](Images/BOTSv3Index.png)

---

## Guided Questions

---

## Conclusion and Recommendations

---

## Video Presentation

---

## References

[1] https://www.paloaltonetworks.co.uk/cyberpedia/soc-roles-and-responsibilities
[2] https://auditboard.com/blog/nist-incident-response

---

## Apendix: Generative AI Declaration