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
   
   
 
