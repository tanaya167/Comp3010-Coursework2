# Comp3010 Coursework2
 BOTSv3 Incident Analysis

 ## Splunk Installation & Dataset Ingestion
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

## BOTSv3 Guided Questions 1-7
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





   
   
 
