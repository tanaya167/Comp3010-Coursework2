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
To complete the BOTSv3 questions, Splunk Enterprise was installed on to an Ubuntu virtual machine to replicate a SOC SIEM environment. A Linux-based  virtual machine was chosen as Linux platforms are widely recognised in security operations infrastructure due to their stability, security and integration flexibility with SIEM systems. These systems, such as Ubuntu, allow for structured logging, secure log collection and transfer and enhanced incident monitoring and analysis, which all reflect important SOC infrastructure practices. (Team, W. 2025)

Splunk was installed from the official Splunk website as the BOTSv3 GitHub repo recommended to do so. The installation instructions declare to “Unzip/untar the downloaded file into $SPLUNK_HOME/etc/apps”. Therefore, the package chosen was the .tgz instead of the .deb or .rpm package, which install software on a Linux system. The .tgz archive contains the requires dataset structure for Splunk ingestion which makes it the best choice for this setup. In SOC environments, data sources are not typically collected as operating system installation packages, they are generally files generated by systems and centralized for analysis, storage and retention.[3] 
After installation was complete, access to the Splunk web interface was verified through the browser. 

The BOTSv3 dataset was downloaded from the Splunk BOTSv3 GitHub repository and the dataset was ingested using the installation method provided by the repository. This method required BOTSv3 to be deployed as a Splunk app and loads all required indexes, source types and dashboards. By doing this, the dataset is ingested in an organised way and easy to follow which reflects the deployment of data sources by SOCs in real world environments. 

To validate that the dataset had been ingested properly and available for analysis, searches were performed across the BOTSv3 index to confirm the presence of events. This is shown below in figure 7, using the query “index=botsv3 earliest=0”. 


## Guided Questions 
### Q1 - List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? 

This question examines the IAM users that accessed AWS services in Frothly's environment by looking at CloudTrail logs. 

**Query:**

`index=botsv3 sourcetype=aws:cloudtrail userIdentity.userName =* 
| stats values(userIdentity.userName) as IAM_Users
| eval IAM_Users=mvsort(IAM_Users) 
| eval IAM_Users=mvjoin(IAM_Users,",")`

**Answer:**

`bstoll,btun,splunk_access,web_admin`

A central part of SOC detection includes identifying IAM users accessing AWS services. Searching through CloudTrail logs allows analysts to recognise and act against unauthorized access, compromised accounts and specific users.  This question is a strong example of the detection stage of the incident handling lifecycle, highlighting possible incidents and unusual behaviour using CloudTrail logs. It also supports the response stage of the lifecycle, as identifying users is essential when investigating and containing cloud based incidents. 
### Q2 - What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)? 

This question investigates which field is crucial for identifying that API activity has occurred without MFA. 

**Query:**

`index=botsv3 sourcetype=aws:cloudtrail 
| search NOT eventName=ConsoleLogin 
| search userIdentity.sessionContext.sessionIssuer.type =* 
| table _time, userIdentity.userName, userIdentity.sessionContext. attributes.mfaAuthenticated, eventName`

**Answer:**

`userIdentity.sessionContext.attributes.mfaAuthenticated`

SOC preparation and prevention involve collecting IT assets, such as endpoints, networks and servers and determining which hold sensitive and important information. This question supports this first stage of the incident handling lifecycle as it involves establishing which field holds the information needed to determine if API activity has occurred without MFA. Analyst can use the uncovered information to then consider possible attacks that could happen and produce appropriate response plans. 
### Q3 - What is the processor number used on the web servers? 

This question is about determining the processor number used on the web servers to understand a normal baseline of the system characteristics. 

**Query:**

`index=botsv3 sourcetype=hardware`

**Answer:**

`E5-2676`

As discussed in question 2, SOC preparation and prevention involve collecting IT assets, such as endpoints, networks and servers. This question supports this first stage of the incident handling lifecycle as it involves determining what assets exist and establishing a normal baseline of how the systems are configured. Analyst can use this information to then detect abnormal systems and unexpected changes. 
### Q4 - What is the event ID of the API call that enabled public access? 

This question is investigating the root cause of the incident by finding the specific event ID of the API call that allowed public access to an S3 bucket. 

**Query:**

`index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl 
| table _time, eventID, userIdentity.userName, requestParameters,
responseElements, eventName`

`index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl AllUsers
| table _time, eventID, userIdentity. userName, requestParameters,
responseElements, eventName`

**Answer:**

`ab45689d-69cd-41e7-8705-5350402cf7ac`

As discussed in question 1, SOC detection involves searching through CloudTrail logs allows to recognise and act against unauthorized access, compromised accounts and specific users. It requires analysts to recognise signs of incidents. This question also reflects the detection stage of the incident handing lifecycle as it involves finding and analysing the first sign of the incident which will then become critical when writing an incident report. 
### Q5 -	What is Bud's username?

This question examines which of the IAM users listed in question 1 made the API call that initiated the incident. 

**Query:**

`index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl AllUsers`

**Answer:**

`bstoll`

The SOC response stage of the incident handling lifecycle involves containing the attack before it causes damage. This is first done through identifying the attacking host, which is exactly what is performed in this question. The user has now been identified and actions such as disabling the account can be performed to contain the attack.
### Q6 - 6.	What is the name of the S3 bucket that was made publicly accessible?

This question investigates which asset was affected by this incident by identifying the specific S3 bucket. 

**Query:**

`index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl userIdentity.userName=bstoll 
| table _time, requestParameters. bucketName, eventID`

**Answer:**

`frothlywebcode`

In the previous question the attacking host was identified. Following on from that, this question continues the response stage by identifying the affected asset which tells analysts what data is under threat, which systems need repairing and how serious the attack is. 
### Q7 - What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? 

This question examines if data was actually uploaded while the S3 bucket was vulnerable.

**Query:**

`index=botsv3 sourcetype=aws: s3:accesslogs earliest=08/20/2018:14:01:46 latest=08/20/2018:14:57:54 
| search frothlywebcode 
| search txt 
| search REST.PUT. OBJECT`

**Answer:**

`OPEN_BUCKET_PLEASE_FIX.txt`

The SOC eradication and recovery stage involves identifying all affected data and hosts, removing malware, disabling breached user accounts and then restoring systems. This question supports this stage as it involves determining if data was uploaded while  the S3 bucket was publicly accessible, if the incident was a data breach and the impact of the incident. This question confirms data was uploaded and now means that the data can be eradicated. 
### Q8 - What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

This question investigates the anomalous endpoint that is running a different operating system edition.

**Query:**

`index=botsv3 
| stats count by sourcetype`

`index=botsv3 sourcetype=WinHostMon 
| stats values(os) by host` 

`index=botsv3 earliest=0 sourcetype=WinHostMon "windows 10" 
| stats count by OS, host 
| stats values(host) by os`

`index=botsv3 host=BSTOLL-L`

**Answer:**

`BSTOLL-L.froth.ly`

The SOC detection stage as previously discussed involves identifying anomalies and outliers to be able to determine if an incident has occurred. This question supports this stage of the  incident handling lifecycle as it involves comparing OS editions, hosts and FQDNs to detect the anomalous endpoint. This question reveals an anomalous OS version which could indicate compromised hosts, unapproved systems or misconfiguration. 
## Conclusion,References and Presentation





   
   
 
