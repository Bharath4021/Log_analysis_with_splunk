# Analyzing Teredo Tunnel Log Files Using Splunk

## Introduction
A tunnel in networking is a method of transmitting data securely across a network by encapsulating one type of traffic inside another. Tunnels are often used for security, bypassing restrictions, or enabling communication between different network protocols.
### Types of Tunnels
#### VPN Tunnels (Virtual Private Network)
- Encrypts traffic between a client and a server.
- Common types: IPsec, OpenVPN, WireGuard.
#### GRE (Generic Routing Encapsulation) Tunnel
- Encapsulates packets to allow communication between different networks.
#### IP-in-IP Tunnel
- Encapsulates IP packets inside other IP packets for secure routing.
#### Teredo Tunnel (as seen in your log)
- Used for IPv6 traffic over IPv4 networks.
- Can be abused for bypassing firewalls.
#### SOCKS/SSH Tunnel
- Used to securely forward traffic through a remote machine. Can be abused for bypassing firewalls.


## Project Overview
In this project, I worked with Teredo tunneling log files to explore its role in enabling IPv6 communication over IPv4 networks. I analyzed the security risks associated with Teredo, such as its potential to bypass firewalls, facilitate data exfiltration, and support command-and-control communication. Using Splunk, I monitored Teredo traffic, created queries to detect unusual outbound traffic, and flagged untrusted IPs, helping identify potential security threats linked to Teredo tunneling.

## Prerequisites
- Installed and configured Splunk SIEM
- Sample teredo tunnel log file
- Basic understanding of SPL queries

## Steps to Upload Sample teredo tunnel Log Files to Splunk SIEM
- I logged into my Splunk instance via my browser using my admin/user credentials.
- I navigated to the “Add Data” option (found under Settings > Data > Add Data) in the Splunk search bar.
- I chose “Upload” (selecting “Files & Directories” for local files) and clicked “Browse” to locate my teredo tunnel log files.
- After selecting the files, I defined the sourcetype (using “teredo logs” or letting Splunk auto-detect) and chose an index (either the default “main” or a custom one like “teredo_logs”).
- Finally, I reviewed my settings and clicked “Submit” to complete the upload.


## Step to Verify Uploaded File
AAfter uploading the teredo log files, I navigated to the Search app and ran a query filtered by my chosen index and sourcetype (e.g., index=*_logs sourcetype= teredologs) to display sample events. I carefully reviewed the event details to ensure that the content, timestamps, and fields were correctly indexed and free of errors.

## Steps to Extract Fields from teredo tunnel Log Files
- Navigate to Field Extractions in Splunk.
- Select Extract New Fields.
- Choose a sample event from the uploaded DHCP logs.
- Click on Regular Expression.
- Identify the required fields and name them appropriately (e.g., IP Address, Status Code, Request Method, etc.).
- Validate the extracted fields and save them.

## Steps to Analyze teredo tunnel Log File in Splunk SIEM
### Detecting Teredo Traffic in Firewall Logs
index=_* OR index=* sourcetype=tunnel_logs | stats count by tunnel_kind,src_ip,dest_ip
- This query helps me summarize and analyze tunnel usage across my network. It gives me a high-level view of tunnel activities, breaking them down by type, source, and destination. By running this, I can spot potential security risks or anomalous behaviors related to tunnel-based traffic, like unexpected tunnel types or unusual connections between internal and external systems.
### Detecting Unusual Outbound Traffic (Teredo Tunnels)
index=_* OR index=* sourcetype=tunnel_logs | lookup dest_ips.csv dest_ip AS dest_ip OUTPUT dest_ip AS trusted_ip | eval untrusted_ip=if(isnull(trusted_ip), "yes", "no") | where isnull(trusted_ip)| table src_ip, dest_ip, dest_port,untrusted_ip
- If you find untrusted IPs, it doesn’t necessarily mean they are IPv6 addresses (even if they are part of a tunnel), but rather that they are not in your trusted list, and further investigation is needed to determine whether they pose a security risk.
## Conclusion 
In this project, I successfully explored the role of Teredo tunneling in enabling IPv6 communication over IPv4 networks and identified the security risks associated with its use, such as firewall bypassing, data exfiltration, and supporting malicious command-and-control communication. By leveraging Splunk for log analysis, I was able to monitor and detect unusual outbound traffic, untrusted IPs, and other potential threats related to Teredo tunnels. Through this hands-on experience, I gained valuable skills in extracting and analyzing tunnel log data, applying SPL queries to detect anomalies, and enhancing my ability to identify and mitigate security risks in network environments.













