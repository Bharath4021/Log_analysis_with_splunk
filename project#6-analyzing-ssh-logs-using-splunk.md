# Analyzing ssh Log Files Using Splunk

## Introduction
SSH (Secure Shell) is a cryptographic protocol used for securely accessing and managing remote devices over an unsecured network. It ensures encrypted communication between a client and server, protecting data from eavesdropping and tampering.

## Project Overview
In this project, I explore SSH log file analysis to detect suspicious activities, such as unauthorized access attempts or potential brute force attacks. By examining SSH logs, I aim to identify patterns and abnormal login behaviors, helping to secure the network. 

## Prerequisites
- Installed and configured Splunk SIEM
- Sample SSH log file
- Basic understanding of SPL queries

## Steps to Upload Sample SSH Log Files to Splunk SIEM
- I logged into my Splunk instance via my browser using my admin/user credentials.
- I navigated to the “Add Data” option (found under Settings > Data > Add Data) in the Splunk search bar.
- I chose “Upload” (selecting “Files & Directories” for local files) and clicked “Browse” to locate my SSH log files.
- After selecting the files, I defined the sourcetype (using “SSH logs” or letting Splunk auto-detect) and chose an index (either the default “main” or a custom one like “SSH_logs”).
- Finally, I reviewed my settings and clicked “Submit” to complete the upload.


## Step to Verify Uploaded File
After uploading the SSH log files, I navigated to the Search app and ran a query filtered by my chosen index and sourcetype (e.g., index=*_logs sourcetype= SSH_logs) to display sample events. I carefully reviewed the event details to ensure that the content, timestamps, and fields were correctly indexed and free of errors.

## Steps to Extract Fields from SSH Log Files
- Navigate to Field Extractions in Splunk.
- Select Extract New Fields.
- Choose a sample event from the uploaded ssh logs.
- Click on Regular Expression.
- Identify the required fields and name them appropriately (e.g., IP Address, Status Code, Request Method, etc.).
- Validate the extracted fields and save them.

## Steps to Analyze SSH Log File in Splunk SIEM
### Identify Failed Login Attempts
index=_* OR index=* sourcetype=ssh_log action = "failure" | stats count by action, src_ip, dest_ip
- I use this query to spot brute force or dictionary attacks by tracking failed SSH logins. It helps me find source IPs with more than five failed attempts, which could mean someone's trying to break in. Once I get those IPs, I check their origin, look them up in threat intel feeds, and see if they’ve tried hitting other systems. If they’re suspicious, I block them or monitor them further.
### Monitor Successful Logins from Unusual IP Addresses
index=_* OR index=* sourcetype=ssh_log action = "sucess" | stats count by src_ip, action, dest_ip | lookup geo_ip.csv src_ip as src_ip OUTPUT country as src_ip | where src_country != "Expected Country"
- Monitors successful SSH logins from unusual IP addresses. It searches all indexes for logs where the action is "success." Then, it counts the number of successful logins per source IP, destination IP, and action. A lookup is performed using a geo_ip.csv file to determine the country of the source IP. Finally, it filters results to show only login from countries that are not the "Expected Country." This helps detect potential unauthorized access from unusual locations, which could indicate compromised credentials or unauthorized remote access attempts.

## Conclusion 
By analyzing SSH log files using Splunk SIEM, I was able to detect suspicious activities such as failed login attempts and successful logins from unusual locations. The project demonstrated how Splunk’s powerful search capabilities and field extractions help in identifying brute force attacks, compromised accounts, and unauthorized access attempts. Using geo-IP lookups, I was able to filter logins by country, improving security monitoring. This approach enhances proactive threat detection, enabling quick response to potential incidents. Overall, SSH log analysis in Splunk is a crucial method for strengthening network security and preventing unauthorized access to critical systems.













