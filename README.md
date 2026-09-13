# Azure Sentinel SIEM: Honeypot & Automated Response (SOAR)


## Project Overview
The primary objective of this initiative was to deploy a Cloud Honeypot within the Azure ecosystem, designed specifically to attract and log real-world cyber threats. Rather than just collecting data, the project aimed to ingest these logs into Microsoft Sentinel (SIEM) to visualize global attack patterns on a live map.

I also wanted to explore SOAR (Security Orchestration, Automation, and Response) capabilities to enhance the lab's functionality. This involved constructing an automated playbook intended to detect specific incident types, specifically Brute Force attempts, and subsequently trigger a notification workflow via Microsoft Teams that includes the attacker's IP address.


## Technologies Used
* **Microsoft Azure**: Virtual Machines, Virtual Network, Network Security Groups.
* **Microsoft Sentinel**: SIEM (Security Information and Event Management).
* **Azure Log Analytics Workspace (LAW)**: Ingesting and querying logs (KQL).
* **Azure Logic Apps**: Orchestration and automation (SOAR).
* **PowerShell**: Scripting to disable firewalls and configure the VM.
* **KQL (Kusto Query Language)**: Writing custom analytics rules.

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
1.  **Trigger:** When a Microsoft Sentinel Incident is created.
2.  **Action:** Extract the IP address entity from the incident.
3.  **Notification:** Send a message to Microsoft Teams to alert the security analyst (me).
4.  **Remediation:** Trigger an Azure Automation Runbook (PowerShell) to block the IP.

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
1.  Authenticates using a Managed Identity.
2.  Retrieves the current Network Security Group (NSG).
3.  Checks if the "Sentinel-Blocklist-Auto" rule exists.
    * *If yes:* It appends the new attacker IP to the existing list.
    * *If no:* It creates the rule and adds the first IP.
4.  Updates the NSG configuration in Azure.

### 4. Final Results
The system successfully blocked malicious IPs from China and the Netherlands automatically.
* **Time to Response:** Reduced from minutes/hours (manual) to ~3 seconds (automated).
* **Verification:** The NSG "Inbound Security Rules" now shows a `Sentinel-Blocklist-Auto` rule containing a growing list of blocked IPs.*



![Automation Job Success](Images/image16)
*Evidence of the Automation working: The NSG rule automatically populated with the attacker IPs.*


## Skills Learned

* **Cloud Infrastructure:** Hands-on experience deploying and configuring Azure resources, including Virtual Machines, Virtual Networks, and Network Security Groups.
* **SIEM Administration:** Configuring Microsoft Sentinel, connecting data sources (Log Analytics Workspace), and managing data collection rules.
* **KQL (Kusto Query Language):** Writing complex queries to filter logs, extract key data (IP addresses), and generate custom analytics rules.
* **Azure Automation:** Configuring Runbooks, Managed Identities, and integrating PowerShell scripts with Logic Apps for custom infrastructure management.
* **PowerShell Scripting:** Writing resilient scripts to handle Azure module version conflicts, input sanitization (Regex), and error handling (try/catch) for production-grade reliability.
* **SOAR & Automation:** Designing automated workflows using Azure Logic Apps to bridge the gap between security detection and incident response.
* **Network Security:** Understanding firewall management (Windows Defender Firewall) and public/private IP networking concepts.
* **Troubleshooting:** Diagnosing and resolving real-world deployment issues, including region-specific policy restrictions, API connector limitations, and module version conflicts.



## Future Improvements

* **Email Integration:** Integrate Outlook or Gmail connectors to send detailed email reports to security admins (currently restricted by Azure for Students policy).
* **IP Retention Policy:** Implement logic to clear blocked IPs after a set period (e.g., 30 days) to prevent the NSG from hitting its maximum capacity limit.
* **Advanced Analytics:** Develop more sophisticated KQL rules to detect other attack vectors beyond Brute Force (e.g., Port Scanning, Privilege Escalation).
* **Threat Intelligence:** Connect Sentinel to external threat intelligence feeds to correlate attacker IPs with known malicious actors.





<sub>Project Start: 12/19/2025</sub>



<sub>Project End (Part I): 12/24/2025</sub>


<sub>Project End (Part II): 1/2/2026</sub>

