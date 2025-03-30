# Analyzing DHCP Log Files Using Splunk

## Introduction
Dynamic Host Configuration Protocol (DHCP) is a network protocol used by devices to automatically obtain an IP address and other network configuration information from a DHCP server. This process eliminates the need for manually assigning IP addresses to each device on a network. DHCP makes network management more efficient and reduces human errors in assigning static IP addresses.

## Project Overview
In this project, I analyzed DHCP logs using Splunk to detect network anomalies like DHCP starvation attacks, unauthorized DHCP servers, and rogue devices. I used Splunk queries to track IP allocations, identify suspicious DHCP activity, and detect devices making excessive requests. This helped improve network security by identifying potential threats and ensuring proper DHCP operations, allowing administrators to take proactive security measures.

## Prerequisites
- Installed and configured Splunk SIEM
- Sample DHCP log file
- Basic understanding of SPL queries

## Steps to Upload Sample DHCP Log Files to Splunk SIEM
- I logged into my Splunk instance via my browser using my admin/user credentials.
- I navigated to the “Add Data” option (found under Settings > Data > Add Data) in the Splunk search bar.
- I chose “Upload” (selecting “Files & Directories” for local files) and clicked “Browse” to locate my DHCP log files.
- After selecting the files, I defined the sourcetype (using “DHCPlogs” or letting Splunk auto-detect) and chose an index (either the default “main” or a custom one like “dhcp_logs”).
- Finally, I reviewed my settings and clicked “Submit” to complete the upload.


## Step to Verify Uploaded File
After uploading the DHCP log files, I navigated to the Search app and ran a query filtered by my chosen index and sourcetype (e.g., index=*_logs sourcetype=dhcplogs) to display sample events. I carefully reviewed the event details to ensure that the content, timestamps, and fields were correctly indexed and free of errors.

## Steps to Extract Fields from dhcp Log Files
- Navigate to Field Extractions in Splunk.
- Select Extract New Fields.
- Choose a sample event from the uploaded DHCP logs.
- Click on Regular Expression.
- Identify the required fields and name them appropriately (e.g., IP Address, Status Code, Request Method, etc.).
- Validate the extracted fields and save them.


## Steps to Analyze DHCP Log Files in Splunk SIEM
### Identifying Unauthorized Devices:
index=_* OR index=* sourcetype="dhcp.log file" | stats count by client_ip , mac_ip1 , server_ip | sort -count
#### lookup command 
index=_* OR index=* sourcetype="dhcp.log file" | lookup client_ip.csv client_ip AS client_ip OUTPUT client_ip AS matched_ip | eval Unauthorized=if(isnull(matched_ip), "Yes", "No")  | where isnull(matched_ip) | stats count by client_ip, server_ip, Unauthorized | table client_ip, server_ip, Unauthorized, count | sort -count

- This Splunk query is designed to identify and count unauthorized IP addresses in DHCP logs. It begins by searching all logs (index=*) with a focus on the DHCP log file (sourcetype="dhcp.log file"). The query then uses the lookup command to compare each client IP in the DHCP logs with a reference list stored in a CSV file (client_ip.csv). If there is a match, the query adds a field called matched_ip.
Next, the eval command is used to create a new field called Unauthorized. If the matched_ip field is NULL (meaning the IP address doesn’t appear in the CSV file), the query marks it as "Yes", indicating it is unauthorized. If a match is found, the value will be "No". The where isnull(matched_ip) statement filters out all authorized IPs, focusing only on those that are unauthorized.The stats count command then groups the data by client IP, server IP, and Unauthorized status, counting how many times each unauthorized IP appears in the logs. Finally, the table command displays the results, showing the client IP, server IP, Unauthorized status, and the count of occurrences. The results are sorted in descending order by count, highlighting the most frequent unauthorized IPs.
This query provides a clear and concise way to detect and track unauthorized devices in your network based on DHCP logs.

### Detecting Rogue DHCP Servers:
Rogue DHCP servers can assign unauthorized IPs or malicious configurations. The following query helps detect suspicious DHCP servers that may be rogue.
index=_* OR index=* sourcetype="dhcp.log file" | stats count by server_ip | where count > 1 | table server_ip, count
- This query helps identify multiple DHCP servers that are being used within the network. It flags suspicious DHCP activity, where a device might be acting as a rogue server, potentially causing network issues or security risks.

### Investigating Network Anomalies (e.g., DHCP Starvation):
- A DHCP starvation attack occurs when an attacker floods the network with DHCP requests, exhausting the available IP pool. This can also be an indicator of MITM attacks. Use this query to detect unusual spikes in DHCP requests.

index=_* OR index=* sourcetype="dhcp.log file"| stats count by client_ip | where count > 30 | table client_ip, count

- This Splunk query is designed to identify client IP addresses that have made more than 30 DHCP requests, which can be a sign of unusual or suspicious activity. The query starts by searching through all logs (index=*) for DHCP log entries (sourcetype="dhcp.log file"). The stats count by client_ip command then counts how many times each client IP appears in the logs, essentially showing how many DHCP requests were made by each device. Next, where count > 30 filter limits the results to only show those client IPs that have made more than 30 requests. This could indicate abnormal behavior, such as a DHCP starvation attack where an attacker tries to exhaust the DHCP server's available IP addresses. Finally, the table client_ip, count command displays the results in a table format, showing the client IP and the number of DHCP requests made by that IP. By running this query, you can easily identify devices that might be misbehaving or trying to overload the DHCP server. This is useful for network administrators to monitor unusual network activity or potential security threats.

## Conclusion
In this project, I successfully analyzed DHCP logs using Splunk to detect network anomalies, including unauthorized devices, rogue DHCP servers, and DHCP starvation attacks. By leveraging Splunk queries, I identified suspicious IP activities, tracked IP allocations, and improved network security monitoring. This project enhances incident response capabilities, helping administrators proactively detect and mitigate threats, ensuring a secure and well-managed DHCP infrastructure.











