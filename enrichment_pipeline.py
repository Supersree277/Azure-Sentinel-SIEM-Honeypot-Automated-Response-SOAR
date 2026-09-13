import os
import requests
from datetime import timedelta
from requests.exceptions import RequestException
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# ================= SECURE CONFIGURATION =================
# Pull secrets from environment variables
WORKSPACE_ID = os.environ.get("AZURE_WORKSPACE_ID")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

if not WORKSPACE_ID or not ABUSEIPDB_API_KEY:
    raise ValueError(
        "Missing required configuration! Please set AZURE_WORKSPACE_ID "
        "and ABUSEIPDB_API_KEY environment variables."
    )
# =======================================================

def get_azure_attackers(workspace_id: str, days_back: int = 30):
    """Queries Azure Log Analytics for external failed RDP logins (Event 4625)."""
    print(f"[*] Querying Azure Log Analytics for the past {days_back} days...")
    client = LogsQueryClient(DefaultAzureCredential())
    
# Native KQL query referencing the top-level IpAddress column directly
    kql_query = """
    SecurityEvent
    | where EventID == 4625
    | where isnotempty(IpAddress) and IpAddress != "-" 
    | where ipv4_is_private(IpAddress) == false
    | summarize AttackCount = count(), LastSeen = max(TimeGenerated) by IpAddress
    | top 10 by AttackCount desc
    """

    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=kql_query,
            timespan=timedelta(days=days_back)
        )
        
        attackers = []
        for table in response.tables:
            for row in table.rows:
                attackers.append({
                    "ip": row[0],
                    "attack_count": row[1],
                    "last_seen": str(row[2])
                })
        return attackers
    except Exception as e:
        print(f"[-] Azure Query Error: {e}")
        return []

def enrich_ip(ip_address: str, api_key: str):
    """Queries AbuseIPDB API for threat reputation details."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json()["data"]
            return {
                "abuse_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "total_reports": data.get("totalReports")
            }
        else:
            print(f"[-] AbuseIPDB returned HTTP {res.status_code} for IP {ip_address}")
            return None
    except RequestException as e:
        print(f"[-] Network or API request failed for {ip_address}: {e}")
        return None

from database import init_db, get_db_session, save_threat_record

def main():
    init_db()
    
    attackers = get_azure_attackers(WORKSPACE_ID, days_back=30)
    print(f"[+] Retrieved {len(attackers)} unique external attacker IPs from Azure.\n")
    
    # Open ONE persistent session for all writes
    with get_db_session() as conn:
        for attacker in attackers:
            ip = attacker["ip"]
            count = attacker["attack_count"]
            last_seen = attacker["last_seen"]
            
            print(f"[*] Processing {ip} (Hits: {count})...")
            enrichment = enrich_ip(ip, ABUSEIPDB_API_KEY)
            
            if enrichment:
                save_threat_record(conn, ip, enrichment, count, last_seen)
                print(f"    └── Saved {ip} ({enrichment['country']}) to local database.")

if __name__ == "__main__":
    main()