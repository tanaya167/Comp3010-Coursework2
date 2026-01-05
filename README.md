## Comp3010 Coursework2
 # BOTSv3 Incident Analysis

 ## Introduction
 The role of the Security Operations Centre (SOC) is to detect, analyse and respond to security incidents in real time.  This investigation was conducted from the perspective of a security operations centre analyst(SOC) using Splunk as a Security Information and Event Management(SIEM) platform. Splunk was used to query and analyse data to identify misconfigurations, suspicious activity and potential risks within an enterprise environment.  (Scapicchio, M., Downie, A. and Finio, M. 2025)
 
The dataset used was the Boss of the SOC Dataset Version 3 (BOTSv3). It is a pre-indexed sample security dataset and Capture the flag (CTF) platform crated by Splunk to train and test cybersecurity skills. It simulates a realistic security incident inside a fictional brewing company called “Frothly”. BOTSv3 provides a large group of logs including network, endpoint, email and cloud service data from environments like Amazon AWS and Microsoft Azure.  analyse these logs using Splunk’s Search processing Language (SPL) to investigate the attack and answer the guided questions that have been provided. 

The objectives of this investigation include analysing the logs provided by the BOTSv3  dataset  by using Splunk’s Search processing Language (SPL) to investigate the attack and answer the selected set of guided 200-level BOTSv3 questions by constructing Splunk queries, analysing results and presenting evidence to support my findings. . The investigation was focused on identifying AWS user activity, detecting insecure cloud configurations, analysing endpoint system information, and demonstrating how such findings are relevant to SOC operations and incident response.

The scope of this investigation was limited to questions 1–8 of the provided guided question set, using only the data available within the BOTSv3 dataset and does not include live threats or incident response in real time. It is assumed that the dataset is complete, accurate, and representative of Frothly’s operational environment during the simulated timeframe. All findings are based solely on the logs present within Splunk. 

This report will present the technical setup, including the installation of Splunk and the retrieval and preparation of the dataset. Also provided is a reflection on the SOC roles and incident handling, the findings of the investigation and evidence. This report will demonstrate how Splunk can be used to support effective security monitoring and incident handling. 

 
 ## SOC Roles & Incident Handling Reflection
 The SOC is responsible for continuously monitoring, detecting, analysing and responding to security incidents. A SOC team is normally organised into three tiers. Tier 1 is mainly focused on monitoring and detecting security incidents. Tier 2 performs a deeper analysis of the incident, try to the determine the root cause, potential impact and come up with strategies to fix those problems. Tier 3 deals with more difficult security issues, they react to incidents and look for threats before they become an issue. They also come up with mitigation strategies to prevent future incidents. (Oguntoyinbo , M. 2025) 
 
In relation to the BOTSv3 exercise, the investigation is mostly conducted from the perspective of tier 1 and 2. Tier 1 responsibilities are reflected through the initial detection of security incidents using Splunk queries, such as such as identifying anomalous AWS API activity, misconfigured S3 bucket permissions, and endpoint inconsistencies. Tier 2 responsibilities are reflected through the deeper analysis to determine the root cause, affected assets and potential impact of the incident. 
There are currently a variety of incident handling methodologies, they primarily provide a series of steps that aim to rectify an incident within an individual organisation. The incident response life cycle presented by the National Institute of Standards and Technology (NIST) contains the following four steps:

- Preparation
  
- Detection and Analysis
  
- Containment, Eradication and Recovery
  
- Post-incident Activity
  
 (Osorno, M., Millar, T. and Rager, D. 2011)
 
Another example of an Incident response life cycle is the from the Chairman of the Joint Chiefs of Staff Manual (CJCSM). This method follows the following steps:

- Detection of Events 

- Preliminary Analysis and Identification

- Preliminary Response Action

- Incident Analysis

- Response and Recovery

- Post-Incident Analysis
  
(Osorno, M., Millar, T. and Rager, D. 2011)


Prevention and preparation for incidents include compiling a list of IT assets such as networks, servers and endpoints. Followed by establishing which ones are important or hold sensitive data.  The types of security events that should be investigated will then be identified and a detailed response plan will be created for common types of incidents. (Cynet 2025) Within the BOTSv3 exercise, questions such as Q2 – API activity without MFA align with this stage, as it requires you to identify which field is important. Further analysis of this question is provided in the Guided Questions section.

Detection involves gathering data from IT systems, security tools, publicly available information and people inside and outside the organisation. Followed by recognising signs of future incidents and any data that determines whether an attack has taken place or is currently taking place. (Cynet 2025) Regarding the BOTSv3 exercise, questions such as Q1 – IAM user activity and Q4 – S3 public access event align with this stage. Both these questions require recognising signs of incidents using CloudTrail logs. Further analysis of these questions is provided in the Guided Questions section.

Response usually involves containment to stop the attack before it causes damage. This response strategy depends on the level of damage the incident could potentially cause. As part of this containment stage, the attacking host will be identified and its IP address validated. This is to allow communication from the attacker to be blocked, be able to identify the threat actor to understand their mode of operation and search for and block other communication channels they may be using. (Cynet 2025) In relation to the BOTSv3 exercise, questions such as Q5 – Bud’s Username and Q6 – Name of the public S3 bucket align with this stage. This is because these questions require you to identify the attacking host and also identify the affected asset. Further analysis of these questions is provided in the Guided Questions section. 

After responding to the incident, the next stage is eradication and recovery. All elements of the incident should be removed from the environment. For example, identifying all affected hosts, removing malware and closing or resetting passwords for breached user accounts. Once the threat has been eradicated, the systems will be restored and normal operations recovered as soon as possible, taking steps to prevent the same assets from being attacked again. (Cynet 2025) Regarding the BOTSv3 exercise, questions such as Q7 – Name of text file align with this stage as it requires you to confirm what data was affected to be able to know what data needs to be removed. Further analysis of this question is provided in the Guided Questions section.


 ## Installation & Data Preparation
 ### Splunk Installation
 - Installed the 10.0.1 version of Splunk Enterprise.
 - I used the following commands:
   sudo dpkg -i splunk-10.0.1-c486717c322b-linux-amd64.tgz
   sudo ./splunk start --accept-license

 ### Dataset Ingestion
 - downloaded BOTSv3 dataset from Github
 - Extracted and moved into Splunk
 - I used the following commands:
   cp -r botsv3_data_set /opt/splunk/etc/apps/
   ./splunk start
 - I searched the following in splunk to confirm the events were visible:
   index=botsv3 earliest=0

## Guided Questions 
Questions 1-7 of the BOTSv3 guided questions answered and screenshots uploaded as evidence. Question 8 still to be completed.
### Q1 - List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? 
**Query:**

index=botsv3 sourcetype=aws:cloudtrail userIdentity.userName =* | stats values(userIdentity. userName) as IAM_Users
| eval IAM_Users=mvsort(IAM_Users) | eval IAM_Users=mvjoin(IAM_Users,",")

**Answer:**

bstoll,btun,splunk_access,web_admin
### Q2 - What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)? 
**Query:**

index=botsv3 sourcetype=aws:cloudtrail | search NOT eventName=ConsoleLogin | search userIdentity.sessionContext.sessionIssuer. type =* | table _time, userIdentity. userName, userIdentity. sessionContext. attributes
.mfaAuthenticated, eventName

**Answer:**

userIdentity.sessionContext.attributes.mfaAuthenticated
### Q3 - What is the processor number used on the web servers? 
**Query:**

index=botsv3 sourcetype=hardware

**Answer:**

E5-2676
### Q4 - What is the event ID of the API call that enabled public access? 
**Query:**

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl | table _time, eventID, userIdentity.userName, requestParameters, responseElements

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl | table _time, eventID, userIdentity.userName, requestParameters,
responseElements, eventName

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl AllUsers| table _time, eventID, userIdentity. userName, requestParameters,
responseElements, eventName

**Answer:**

ab45689d-69cd-41e7-8705-5350402cf7ac
### Q5 -	What is Bud's username?
**Query:**

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl AllUsers

**Answer:**

bstoll
### Q6 - 6.	What is the name of the S3 bucket that was made publicly accessible?
**Query:**

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl userIdentity.userName=bstoll | table _time, requestParameters. bucketName, eventID

**Answer:**

frothlywebcode
### Q7 - What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? 
**Query:**

index=botsv3 sourcetype=aws: s3:accesslogs earliest=08/20/2018:14:01:46 latest=08/20/2018:14:57:54 | search
frothlywebcode | search txt | search REST.PUT. OBJECT

**Answer:**

OPEN_BUCKET_PLEASE_FIX.txt

## Conclusion,References and Presentation





   
   
 
