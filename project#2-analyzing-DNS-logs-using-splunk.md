# Analyzing DNS Log Files Using Splunk

## Introduction
DNS (Domain Name System) is essential for converting human-readable domain names into machine-readable IP addresses, enabling proper website access. DNS traffic is critical for network communication and can reveal security threats like DNS tunneling, DDoS amplification, and domain generation algorithms. SOC engineers rely on DNS logs to detect suspicious behavior, track malicious domains and IP addresses, and safeguard against attacks such as DNS spoofing and cache poisoning. By analyzing DNS logs, they can identify anomalies that may indicate botnets, phishing, or malware activity, helping to protect the network.

## Project Overview
In this project, I will use Splunk SIEM to analyze DNS log files and detect potential security threats or abnormal patterns in DNS queries. I will upload sample DNS log files to Splunk, extract necessary fields from the logs, run queries to identify any suspicious activity or patterns,and interpretation of DNS traffic.

## Prerequisites
- Installed and configured Splunk SIEM
- Sample DNS log file
- Basic understanding of SPL queries

## Steps to Upload Sample DNS Log Files to Splunk SIEM
•	In the top menu, click on the "Settings" icon.
•	Under the Data section, click on "Add Data."
•	Select the "Upload" option and choose the DNS log file you wish to import.
•	Choose the appropriate source type for the DNS log file. If no predefined source type exists, you can create a custom one.
•	Verify the settings, ensure there are no errors, and confirm the upload of the DNS log file to Splunk.


## Step to Verify Uploaded File
Verify that the file has been uploaded correctly using the following query to get all the events related to the DNS.log uploaded file:
index=* sourcetype="DNS.log"

## Steps to Extract Fields from DNS Log Files
- Navigate to Field Extractions in Splunk.
- Select Extract New Fields.
- Choose a sample event from the uploaded DNS logs.
- Click on Regular Expression.
- Identify the required fields and name them appropriately (e.g., IP Address, Status Code, Request Method, etc.).
- Validate the extracted fields and save them.

## Steps to Analyze DNS Log Files in Splunk SIEM
### Basic DNS Commands
#### Finding the Most Queried Domains
index=_* OR index=* sourcetype="dns log file"|stats count by quary | sort -count
- Identifies the most frequently accessed domains.
#### Identify the Most Active Clients (Source IPs)
index=_* OR index=* sourcetype="dns log file"| stats count by src_ip | sort – count
- Finds which devices are generating the most DNS traffic.
#### Detect Failed DNS Queries (NXDOMAIN)
index=_* OR index=* sourcetype="dns log file" response_status="NXDOMAIN" | stats count by src_ip, dest_ip, quary, response_status | sort – count
- Detects misconfigured applications, non-existent domains, or malware activity.
### Security Threat Detection

#### Detect Malicious Domains (Using Threat Intelligence)
index=_* OR index=* sourcetype="dns log file" | lookup threat_intel.csv domain AS query OUTPUT description, risk_score | search risk_score > 7
- Cross-checks queries against known malicious domain lists.

#### Identify DNS Tunneling (Data Exfiltration)
index=_* OR index=* sourcetype="dns log file" | eval query_length=len(quary) | where query_length > 60 | stats count by quary, src_ip | sort – count
- Looks for unusually long DNS queries that could indicate tunneling.

#### Find Fast Flux Domains (Frequent IP Changes)
index=_* OR index=* sourcetype="dns log file" | stats dc(dest_ip) as ip_count by quary | where ip_count > 5
- This Splunk query searches through all DNS log files and identifies DNS queries that are linked to multiple different destination IP addresses. It uses the stats dc(dest_ip) function to count the number of unique destination IPs (ip_count) associated with each DNS query (quary). After counting, it filters the results to show only those queries that are connected to more than 5 unique IPs. This is useful in threat hunting because if a single domain name is resolving to many different IPs, it could indicate suspicious activity such as fast-flux DNS, botnet behavior, or domain generation algorithms (DGA) used by malware.

#### DNS Beaconing Detection (Malware C2 Communication)

index=_* OR index=* sourcetype="dns log file" | bucket _time span=5m | stats count by _time, quary, src_ip | sort -_time

- This Splunk query is used to detect DNS Beaconing, a technique often used by malware to communicate with a Command & Control (C2) server at regular time intervals. The query searches across all indexes (index=_* OR index=*) and filters the logs where the sourcetype is specified as "dns log file", which refers to DNS log data. It uses the bucket _time span=5m command to divide the log data into 5-minute time intervals, making it easier to observe repeated query patterns over time. The stats count by _time, query, src_ip command is used to count how many times a specific DNS query (query) was made by a particular source IP (src_ip) during each time bucket. Lastly, sort -_time organizes the results in reverse chronological order so that the latest activity appears first.
The main purpose of this query is to help analysts identify suspicious DNS behavior, specifically devices that are repeatedly querying the same domain at regular intervals, which is a common indicator of malware trying to maintain communication with a C2 server. Detecting this pattern is critical in threat hunting and incident response, as it can reveal compromised systems within a network.

#### Detect DGA (Domain Generation Algorithm) Domains
index=_* OR index=* sourcetype="dns log file" | eval domain_entropy=len(replace(quary, "[^A-Za-z]", "")) | where domain_entropy > 15 | stats count by query, src_ip
- Detects randomly generated domains used by malware.

#### Monitor DNS Queries to Blacklisted Countries
index=_* OR index=* sourcetype="dns log file" | lookup geoip.csv ip AS dest_ip OUTPUT country | search country IN ("Russia", "China", "North Korea") | stats count by src_ip, query, country
- Finds outbound traffic to high-risk regions.

## Conclusion 
In this project, I used Splunk SIEM to analyze DNS log files and detect security threats in DNS queries. By uploading the logs, extracting necessary fields, and running specific queries, I identified suspicious patterns such as failed queries, malicious domains, DNS tunneling, and DNS beaconing. The project emphasized the role of DNS log analysis in identifying abnormal behavior like botnets or malware activity. Through Splunk’s querying and visualization tools, I was able to gain valuable insights into DNS traffic, helping to enhance network security by detecting and responding to potential threats early in the process.







