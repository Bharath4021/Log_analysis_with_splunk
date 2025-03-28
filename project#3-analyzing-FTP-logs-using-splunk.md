# Analyzing FTP Log Files Using Splunk

## Introduction
FTP (File Transfer Protocol) is a standard network protocol used to transfer files between a client and a server over a TCP/IP network (such as the internet or a private network). FTP logs can provide critical information about the use of an FTP server, including user access, file transfers, command usage, and any unusual behavior. Analyzing FTP logs can help identify potential security risks like unauthorized access, data exfiltration, or FTP abuse (e.g., anonymous logins or activity outside of business hours).

## Project Overview
In this project, I leveraged Splunk to analyze FTP logs for security insights. I uploaded sample FTP log files, verified their integrity, and extracted essential fields such as source IPs, usernames, commands, and timestamps. I then executed security-focused queries to detect anomalies, including suspicious login attempts, unusual file transfers, and off-hours activity, thereby enhancing overall monitoring and threat detection effectively.

## Prerequisites
- Installed and configured Splunk SIEM
- Sample DNS log file
- Basic understanding of SPL queries

## Steps to Upload Sample DNS Log Files to Splunk SIEM
- I logged into my Splunk instance via my browser using my admin/user credentials.
- I navigated to the “Add Data” option (found under Settings > Data > Add Data) in the Splunk search bar.
- I chose “Upload” (selecting “Files & Directories” for local files) and clicked “Browse” to locate my FTP log files.
- After selecting the files, I defined the sourcetype (using “ftplogs” or letting Splunk auto-detect) and chose an index (either the default “main” or a custom one like “ftp_logs”).
- Finally, I reviewed my settings and clicked “Submit” to complete the upload.


## Step to Verify Uploaded File
After uploading the FTP log files, I navigated to the Search app and ran a query filtered by my chosen index and sourcetype (e.g., index=ftp_logs sourcetype=ftplogs) to display sample events. I carefully reviewed the event details to ensure that the content, timestamps, and fields were correctly indexed and free of errors.

## Steps to Extract Fields from FTP Log Files
- Navigate to Field Extractions in Splunk.
- Select Extract New Fields.
- Choose a sample event from the uploaded FTP logs.
- Click on Regular Expression.
- Identify the required fields and name them appropriately (e.g., IP Address, Status Code, Request Method, etc.).
- Validate the extracted fields and save them.

## Steps to Analyze FTP Log Files in Splunk SIEM
### Detect Brute Force or Credential Stuffing Attacks
index=_* OR index=* sourcetype=ftplogs status_code="APPE" |  stats count by src, user  | where count <100
- I noticed a source IP (192.168.23.103) using the APPE command 40 times, which is unusual. This could indicate an attacker trying to inject a payload by appending malicious data to files. I would immediately investigate this IP’s behavior, correlate with other logs, check for file modifications, and look for any data transfer using PORT commands following the APPE activity. I would also search for any login attempts and alert the incident response team if this activity is unauthorized.
### Track File Transfers
index=_* OR index=* sourcetype=ftplogs (status_code=APPE OR status_code=PORT) |  stats count by src, user,status_code
- This query is used to identify suspicious FTP activity by focusing on the APPE and PORT commands. I group the data by source IP, user, and command, and count how many times each command was used. This helps me quickly identify potential attacks like FTP file injection, data exfiltration, or port misuse. For example, if I see a high number of APPE commands from one source IP, I will immediately investigate for possible malicious file modification attempts.
### Identify Use of Anonymous or Default Accounts
index=_* OR index=* sourcetype=ftplogs  user="anonymous" | stats count by src , _time
- This query helps detect the use of anonymous FTP access, which can be a security concern if used improperly. If I see multiple logins from the same source IP, especially at unusual times, I would investigate further for any signs of unauthorized access or misuse.
### Check FTP Usage Outside Business Hours
index=_* OR index=* sourcetype=ftplogs  | eval hour=strftime(_time,"%H") | where hour<7 OR hour>20 | stats count by src_ip, user, _time
- This query is designed to monitor FTP access outside of business hours, which could point to abnormal or malicious activity. I would flag any significant FTP sessions occurring at odd hours, as attackers may try to exfiltrate data when there is less supervision.

## Conclusion 
By leveraging Splunk to analyze FTP logs, I successfully detected potential security threats such as brute force attacks, unauthorized file transfers, anonymous logins, and off-hours activity. These insights improve monitoring and help prevent data breaches or misuse of FTP services.











