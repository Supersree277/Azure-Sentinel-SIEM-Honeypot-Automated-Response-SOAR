# Azure Sentinel SIEM: Honeypot & Automated Response (SOAR)


## Project Overview
The primary objective of this initiative was to deploy a Cloud Honeypot within the Azure ecosystem, designed specifically to attract and log real-world cyber threats. Rather than just collecting data, the project aimed to ingest these logs into Microsoft Sentinel (SIEM) to visualize global attack patterns on a live map.

I also wanted to explore SOAR (Security Orchestration, Automation, and Response) capabilities to enhance the lab's functionality. This involved constructing an automated playbook intended to detect specific incident types, specifically Brute Force attempts, and subsequently trigger a notification workflow via Microsoft Teams that includes the attacker's IP address.


## Technologies Used
* **Microsoft Azure**: Virtual Machines, Virtual Network, Network Security Groups.
* **Microsoft Sentinel**: SIEM (Security Information and Event Management).
* **Azure Log Analytics Workspace (LAW)**: Ingesting and querying logs (KQL).
* **Azure Logic Apps**: Orchestration and automation (SOAR).
* **PowerShell**: Scripting to disable firewalls, handle legacy Azure module schemas, and configure the VM.
* **Python**: Ingestion pipeline using `azure-monitor-query`, `azure-identity`, and SQLite ORM logic.
* **SQL / SQLite**: Relational schema design, session management, and aggregated metric reporting.
* **REST APIs**: AbuseIPDB v2 API integration for reputation scoring and metadata enrichment.
* **KQL (Kusto Query Language)**: Writing custom analytics rules and log parsing filters.
---



## Step-by-Step Implementation

### Phase 1: The Setup (Virtual Machine & Network)
The first step seemed pretty straightforward: spinning up a generic Windows 10 Virtual Machine in Azure. Since the goal was to make an effective honeypot, it needed to be fully exposed to the internet.


![Creating VM](Images/image1)
*Initial attempt at creating the Virtual Network.*

**Challenge Encountered:** The deployment did not go smoothly at first; I encountered errors likely caused by Azure for Students policy restrictions regarding specific geographic regions. Troubleshooting involved verifying which regions were permitted and subsequently redeploying the resources in `East US 2`.



![Policy Error](Images/image2)
*Troubleshooting region policy errors.*



### Phase 2: Making it Vulnerable (The Honeypot)
With the VM successfully running, the priority shifted to lowering its defenses. I utilized a PowerShell script to strip away the Windows Firewall on all profiles, which essentially invites potential attackers to attempt connections via RDP (Remote Desktop Protocol).


![Disabling Firewall](Images/image3)
*Running `NetSh Advfirewall set allprofiles state off` to expose the VM.*



To confirm the exposure was successful, I pinged the VM from my local machine. While the initial pings timed out (before I turned off the firewall), the pings succeeded once the script was executed, showing the VM was accessible from the public internet.


![Ping Test](Images/image4)
*Successful ping indicating the VM is reachable from the public internet.*




### Phase 3: Log Ingestion & Sentinel Configuration
Acting as a repository for the collected security events, a **Log Analytics Workspace (LAW)** was established. I connected the VM to this workspace and enabled **Microsoft Defender for Cloud**, which allows for the collection of data.


![Defender Plans](Images/image5)
*Enabling Defender plans to capture comprehensive security logs.*

I configured a **Data Collection Rule (DCR)** to specifically ingest *All Security Events* from the Windows VM, ensuring I captured every failed login attempt.



![Data Collection Rule](Images/image6)

### Phase 4: Attack Visualization (The Map)

Using KQL (Kusto Query Language), I queried the `SecurityEvent` logs to identify failed login attempts (EventID 4625). I then connected this data to a **Workbook** in Sentinel to visualize the physical location of the attackers.



![Initial Map](Images/image7)
*The map after 2 days of exposure. I started seeing hits from the US, China, and Europe.*



### Phase 5: Automation (SOAR) Integration

This was the most complex phase. My goal was to send an email alert whenever a brute force attack was detected.

**Challenge Encountered:** The Logic App failed to connect to Gmail/Outlook due to university security policies blocking third-party API connections for student accounts.



![Email Policy Error](Images/image8)

*Workflow validation failed due to organizational policy restrictions on email connectors.*



**Resolution:** I pivoted to using **Microsoft Teams**. I reconfigured the playbook to post a message as a *Flow Bot* into a private Teams channel.



![Teams Logic](Images/image9)
*Redesigned Logic App workflow using Microsoft Teams.*



### Phase 6: The "ActionConditionFailed" Error

After setting up the Logic App, I ran a test, but the messages weren't sending. The run history showed the action was *Skipped.*



![Logic App Error](Images/image10)
*Troubleshooting the skipped actions in Azure Run History.*



**Root Cause:** The incident trigger in Sentinel was not successfully mapping the *Attacker IP* to the *Entity* field. The Logic App was looking for an IP to ban/report, found `null`, and skipped the step.



**Fix:** I wrote a custom Analytics Rule in Sentinel with strict Entity Mapping:

```kusto

SecurityEvent 
| where EventID == 4625 
| summarize FailureCount = count() by IpAddress, EventID 
| where FailureCount >= 10
```



I mapped the `IpAddress` column to the `IP` Entity in the rule configuration.



![Entity Mapping](Images/image11)
*Configuring the Analytics Rule to correctly map IP addresses to Entities.*



### Final Results

After fixing the entity mapping and generating a fresh brute-force attack (by spamming failed logins via RDP), the system worked perfectly.



1.  **Sentinel** detected the attack.

2.  The **Automation Rule** triggered the playbook.

3.  **Teams** received the alert with the attacker's IP.



![Final Success](Images/image12)
*Successful automated alert delivered to Microsoft Teams.*



By the end of the lab, the map was lighting up with thousands of attacks from all over the world, proving the effectiveness of the honeypot.



![Final Map](Images/image13)
*Final visualization of global attacks.*



## Phase 7: The Upgrade (Active Defense)
*Project Update (Jan 2026):* After successfully monitoring attacks for a week, I decided to revisit the project to implement the "SOAR" (Response) capabilities. The goal was to transition from "Passive Logging" to "Active Defense" by automatically blocking the IP addresses of attackers.

### 1. Architecture Design
I configured a **Logic App** (Playbook) to act as the orchestrator. The workflow uses the following logic:
1. **Trigger:** When a Microsoft Sentinel Incident is created.
2. **Action:** Extract the IP address entity from the incident.
3. **Notification:** Send a message to Microsoft Teams to alert the security analyst (me).
4. **Remediation:** Trigger an Azure Automation Runbook (PowerShell) to block the IP.

![Logic App Workflow](Images/image14)
*The updated Logic App chain: Trigger -> Get IPs -> Loop -> Teams Alert -> Blocking Script.*

### 2. Challenges & Solutions
**Challenge 1: The "Parking Spot" Conflict**
* *Issue:* My remediation script was hardcoded to create a block rule at **Priority 100**. However, my existing "Honeypot Allow All" rule was also sitting at Priority 100. The script failed because two rules cannot share the same priority.
* *Solution:* I manually moved the "Allow All" rule to Priority 200, reserving the highest priority (100) specifically for the automation blocklist.

**Challenge 2: Deprecated Azure Modules (The Version Conflict)**
* *Issue:* My student Azure environment was running an older version of the `Az.Network` module. The standard command to update NSG rules (`SourceAddressPrefixes`) failed because the property did not exist in the older schema.
* *Solution:* I engineered a "Compatibility Mode" PowerShell script. I forced the array of attacker IPs into the legacy `SourceAddressPrefix` (singular) parameter, which the older module version accepted.

![Automation Job Success](Images/image15)
*The Automation Job log showing the successful execution of the V5 "Legacy Mode" script.*

### 3. The PowerShell Logic
The Runbook performs the following steps:
1. Authenticates using a Managed Identity.
2. Retrieves the current Network Security Group (NSG).
3. Checks if the "Sentinel-Blocklist-Auto" rule exists.
   * *If yes:* It appends the new attacker IP to the existing list.
   * *If no:* It creates the rule and adds the first IP.
4. Updates the NSG configuration in Azure.

### 4. Final Results
The system successfully blocked malicious IPs from China and the Netherlands automatically.
* **Time to Response:** Reduced from minutes/hours (manual) to ~3 seconds (automated).
* **Verification:** The NSG "Inbound Security Rules" now shows a `Sentinel-Blocklist-Auto` rule containing a growing list of blocked IPs.

![Automation Job Success](Images/image16)
*Evidence of the Automation working: The NSG rule automatically populated with the attacker IPs.*





## Phase 8: The V2 Upgrade (Threat Intelligence Pipeline & Local Database)
*Project Update (Fall 2026):* After running the honeypot and watching the automated response work, I realized two major limitations with relying fully on the cloud dashboard:

1. **The Retention Cliff:** Azure Log Analytics workspaces drop logs after 30 to 90 days on standard student tiers. Once retention expired, my raw telemetry vanished, including all the attacks that I had at the beginning of the year.
2. **Context Blindspots:** Event 4625 told me someone failed a login, but gave me zero external context on who they were, what ASN or ISP they were leasing from, or whether they were an established threat actor.

To solve this, I decided to bridge cloud security with software engineering. I built a Python pipeline to pull logs directly from Azure Monitor, correlate malicious IPs against an external threat intelligence platform (AbuseIPDB), store the enriched data into a relational database, and query it from a local CLI.

```text
┌─────────────────────────────────────────────────────────┐
│              Azure Cloud Honeypot (West US 3)           │
│  [Windows Server 2022] ──(Failed Logons)──> Event 4625  │
└────────────────────────────┬────────────────────────────┘
                             │ Azure Monitor Agent (AMA)
                             ▼
┌─────────────────────────────────────────────────────────┐
│        Azure Log Analytics Workspace (LAW-Cyber-Lab)    │
│            KQL Parsing & RFC 1918 IP Validation         │
└────────────────────────────┬────────────────────────────┘
                             │ Python SDK (azure-monitor-query)
                             ▼
┌─────────────────────────────────────────────────────────┐
│       Automated Threat Intelligence Ingestion Engine    │
│               [pipeline/enrichment_pipeline.py]         │
└──────────────┬───────────────────────────┬──────────────┘
               │ REST API Query            │ Normalized Upsert
               ▼                           ▼
┌─────────────────────────────┐ ┌─────────────────────────┐
│     AbuseIPDB REST API      │ │  SQLite Threat Database │
│ - Reputation Confidence     │ │   [threat_intelligence] │
│ - ISP / Country Metadata    │ │ - attackers (PK: IP)    │
│ - Historical Abuse Reports  │ │ - attack_events (FK)    │
└─────────────────────────────┘ └───────────┬─────────────┘
                                            │ SQL Queries
                                            ▼
                                ┌─────────────────────────┐
                                │ CLI Analytical Engine   │
                                │ [pipeline/threat_CLI.py]│
                                │ --top 5 | --high-risk 50│
                                └─────────────────────────┘
```
*High-level data flow: honeypot telemetry → Log Analytics → enrichment pipeline → SQLite → CLI.*

### 1. Ingestion Pipeline & Cloud Telemetry (`enrichment_pipeline.py`)
To get fresh telemetry for this phase, I verified that port 3389 was open on the Network Security Group and confirmed inbound connectivity using `Test-NetConnection`.

![RDP Port Exposure](Images/Image17)
*Exposing RDP port 3389 publicly via NSG rules to bait threat actors.*

![TCP Reachability Test](Images/Image18)
*Verifying end-to-end TCP reachability on RDP port 3389 using Test-NetConnection.*

Instead of manually exporting CSVs, I wrote `enrichment_pipeline.py` using the `azure-monitor-query` SDK and authenticated with `DefaultAzureCredential`. To avoid pulling internal test traffic, I built RFC 1918 filtering directly into the KQL query:

```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress) and IpAddress != "-" 
| where ipv4_is_private(IpAddress) == false
| summarize AttackCount = count(), LastSeen = max(TimeGenerated) by IpAddress
| top 10 by AttackCount desc
```

![Log Analytics Query Results](Images/Image19)
*Validating real-time brute-force logon failures (Event 4625) inside Log Analytics Workspace.*

### 2. Live IOC Enrichment & The Zero-Score Anomaly
The script passes extracted IPs to the AbuseIPDB REST API v2, gathering each actor's Abuse Confidence Score, registered ISP, country code, and historical report count.

```text
[*] Processing 120.25.120.254 (Hits: 1480)...
    └── Saved 120.25.120.254 (CN) to local database.
[*] Processing 156.236.110.101 (Hits: 1039)...
    └── Saved 156.236.110.101 (HK) to local database.
[*] Processing 185.204.169.233 (Hits: 1)...
    └── Saved 185.204.169.233 (DE) to local database.
```

**Real-World Takeaway (The Zero-Score Anomaly):** While pulling data, IP `156.236.110.101` hit my honeypot over 1,000 times from Hong Kong, but returned an Abuse Confidence Score of **0%** with zero reports.

* Attackers frequently cycle through cheap or bulletproof VPS providers, run short automated sweeps, and tear down instances before threat databases register community reports.
* This showed me firsthand why static reputation feeds cannot be trusted alone; how aggressively an IP is currently attacking matters just as much as what a public database says about it.

![IOC Enrichment Output](Images/Image20)
*Ingesting Azure telemetry, enriching external indicators, and resolving the zero-score anomaly.*

### 3. Database Architecture (`database.py`)
Rather than dumping everything into flat text files, I split the database into a normalized two-table relational schema (attackers and attack_events) linked by foreign keys. This prevented repetitive IP metadata from bloating the database every time a brute-force sweep occurred, while Python context managers handled clean commits to prevent file-locking crashes:

* **`attackers` Table (Master):** Stores `ip_address` (Primary Key), country, ISP, abuse score, total reports, and timestamps.
* **`attack_events` Table (Telemetry):** Stores `event_id` (Primary Key), `ip_address` (Foreign Key linked to `attackers` with `ON DELETE CASCADE`), attack volume, target port (3389), and logged timestamp.

```sql
CREATE TABLE IF NOT EXISTS attackers (
    ip_address TEXT PRIMARY KEY,
    country TEXT,
    isp TEXT,
    abuse_score INTEGER,
    total_reports INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    attack_count INTEGER,
    target_port INTEGER DEFAULT 3389,
    recorded_at TIMESTAMP,
    FOREIGN KEY (ip_address) REFERENCES attackers (ip_address) ON DELETE CASCADE
);
```

**Transaction Handling & Upserts:** I wrapped connection handling inside Python's `@contextmanager` to ensure connections close cleanly and prevent database locking on Windows. To avoid primary key collision errors on repeated pipeline runs, I implemented SQLite's `ON CONFLICT(ip_address) DO UPDATE SET` logic to update metadata cleanly.

![SQLite Schema Validation](Images/Image21)
*Inspecting normalized relational records and foreign key associations inside SQLite Viewer.*

### 4. Threat Hunting Analytical CLI (`threat_CLI.py`)
To query the database without opening a raw database console, I built `threat_CLI.py` using `argparse`.

**Top Attackers by Volume (`--top`):** Runs an inner JOIN between both tables, grouping by actor and summing counts to reveal total brute-force volume across runs.

```powershell
python pipeline/threat_CLI.py --top 5
```

![Threat CLI Top Attackers](Images/Image22)
*Running `--top 5` to aggregate hit volume and surface persistent threat campaigns.*

**Filtering Malicious Thresholds (`--high-risk`):** Filters indicators against a minimum AbuseIPDB confidence score to quickly isolate high-priority threats.

```powershell
python pipeline/threat_CLI.py --high-risk 50
```

![Threat CLI High-Risk Query](Images/Image23)
*Running `--high-risk 50` to isolate high-confidence malicious actors.*

### 5. Final Results
My pipeline successfully pulled, enriched, and stored active brute-force telemetry entirely outside the Azure portal!
* **Data Permanence:** Threat indicators and attack counts are preserved locally, eliminating reliance on Azure's log retention window.
* **Actionable Intelligence:** Confirmed hits from established malicious hosts (like Arvancloud in Germany at a 100% abuse score) alongside brand-new scanning hosts with 0% reputation scores.
* **Rapid Triage:** The CLI provides command-line flags (--top, --high-risk) to quickly inspect top threat actors and high-risk indicators directly from the terminal without writing raw SQL queries.

### Setup & Execution
Clone the repository:
```powershell
git clone https://github.com/Supersree277/Azure-Sentinel-SIEM-Honeypot-Automated-Response-SOAR-.git
cd Azure-Sentinel-SIEM-Honeypot-Automated-Response-SOAR-
```

Set up virtual environment & install dependencies:
```powershell
python -m venv venv
.\venv\Scripts\Activate
python -m pip install -r requirements.txt
```

Configure environment variables:
```powershell
$env:AZURE_WORKSPACE_ID="your-log-analytics-workspace-guid"
$env:ABUSEIPDB_API_KEY="your-abuseipdb-api-key"
```

Execute pipeline & query CLI:
```powershell
python pipeline/enrichment_pipeline.py
python pipeline/threat_CLI.py --top 5
python pipeline/threat_CLI.py --high-risk 50
```














## Skills Learned

* **Cloud Infrastructure:** Hands-on experience deploying and configuring Azure resources, including Virtual Machines, Virtual Networks, and Network Security Groups.
* **SIEM Administration:** Configuring Microsoft Sentinel, connecting data sources (Log Analytics Workspace), and managing Data Collection Rules (DCR).
* **KQL (Kusto Query Language):** Writing custom queries to filter event logs, extract IP entities, and isolate external non-RFC 1918 traffic.
* **Azure Automation & SOAR:** Configuring Automation Accounts, Runbooks, Managed Identities, and integrating PowerShell with Logic Apps for sub-3-second automated incident response.
* **PowerShell Scripting:** Writing resilient scripts to handle legacy Azure module version conflicts, input sanitization (Regex), and error handling (`try/catch`).
* **Software & Pipeline Engineering:** Building modular Python ingestion pipelines using official cloud SDKs (`azure-monitor-query`), integrating third-party REST APIs (AbuseIPDB), and managing environment dependencies.
* **Relational Database Design:** Designing two-table schemas linked by foreign keys in SQLite, preventing file locks with Python context managers, and writing idempotent `UPSERT` queries.
* **Threat Hunting & CLI Tooling:** Engineering interactive command-line triage tools using `argparse` and SQL aggregation queries (`JOIN`, `GROUP BY`, `SUM`) to surface attack velocity and high-risk indicators.
* **Troubleshooting:** Resolving real-world cloud deployment blockers, including subscription policy restrictions, API connector firewalls, and schema version mismatches.

## Future Improvements

* **Automated IP Expiration (Pruning):** Build a scheduled runbook to expire and unblock IPs after 30 days so the Azure NSG rule doesn't hit its maximum prefix capacity limit.
* **Multi-Port Honeypot Ingestion:** Expand the KQL ingestion logic and database schema to track attacks across other bait ports, such as SSH (22) and SMB (445).
* **STIX/TAXII Threat Sharing:** Add an export module to package local threat indicators into standardized STIX/TAXII feeds to share with external threat intelligence platforms or MISP.
* **Automated Alert Digest:** Configure a weekly script to generate and email a markdown/PDF summary of new high-risk indicators discovered.



<sub>Project Start: 12/19/2025<sub>

<sub>Project End (Part I - Cloud Honeypot & SIEM): 12/24/2025<sub>

<sub>Project End (Part II - SOAR Automated Blocking): 01/02/2026<sub>

<sub>Project End (Part III - Threat Intel Pipeline & Database Engine): 09/13/2026<sub>

