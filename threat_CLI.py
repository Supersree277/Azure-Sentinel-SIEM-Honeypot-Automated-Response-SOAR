import argparse
import sqlite3

DB_NAME = "threat_intelligence.db"

def query_top_attackers(limit: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    query = """
    SELECT 
        a.ip_address, 
        a.country, 
        a.isp, 
        a.abuse_score, 
        SUM(e.attack_count) as total_hits
    FROM attackers a
    JOIN attack_events e ON a.ip_address = e.ip_address
    GROUP BY a.ip_address
    ORDER BY total_hits DESC
    LIMIT ?;
    """
    
    rows = cursor.execute(query, (limit,)).fetchall()
    conn.close()
    
    print(f"\n{'IP Address':<18} | {'CC':<4} | {'Abuse %':<8} | {'Total Hits':<10} | {'ISP'}")
    print("-" * 75)
    for row in rows:
        ip, country, isp, score, hits = row
        print(f"{ip:<18} | {country:<4} | {score:<8} | {hits:<10} | {isp[:30]}")
    print()

def query_high_risk(min_score: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    query = """
    SELECT ip_address, country, isp, abuse_score, total_reports
    FROM attackers
    WHERE abuse_score >= ?
    ORDER BY abuse_score DESC;
    """
    
    rows = cursor.execute(query, (min_score,)).fetchall()
    conn.close()
    
    print(f"\n[!] Flagged High-Risk Indicators (Score >= {min_score}%):")
    print(f"{'IP Address':<18} | {'CC':<4} | {'Score':<6} | {'Reports':<8} | {'ISP'}")
    print("-" * 65)
    for row in rows:
        ip, country, isp, score, reps = row
        print(f"{ip:<18} | {country:<4} | {score:<6} | {reps:<8} | {isp[:25]}")
    print()

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Query Engine")
    parser.add_argument("--top", type=int, help="Display top N attackers by brute-force volume")
    parser.add_argument("--high-risk", type=int, help="Filter IPs by minimum AbuseIPDB confidence score")
    
    args = parser.parse_args()
    
    if args.top:
        query_top_attackers(args.top)
    elif args.high_risk:
        query_high_risk(args.high_risk)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()