import re
import json
from collections import Counter
from datetime import datetime

def analyze_apache_logs(filename, output_json="threat_report.json"):
    # Defining a list of known attack signatures (IOCs) that attackers mostly use.
    attack_keywords = [
        'etc/passwd', 'cmd.exe', 'eval(', 'base64', 
        'script', 'union select', 'UNION SELECT', 
        '/admin', '/wp-login', '/phpmyadmin', 'wp-login', 'administrator', 'admin.php', 'xmlrpc', 'bash_history',
            'bot', 'spider', 'crawler', 'hack', 'exploit', 'malware'
    ]
    
    # Counting to know how many alerts we find per day and store it.   
    
    threat_count = Counter()
    total_alerts = 0
    detailed_alerts = [] 

    try:
        # It is very important to ignore errors when reading logs because some lines may contain non-UTF-8 characters.
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                # Extracting the date from the log line using regex..
                date_match = re.search(r'\[(.*?)\]', line)
                date_string = date_match.group(1) if date_match else "Unknown Date"
                
                # This is to deal with uppercase or lowercase. 

                line_lower = line.lower()
                
                # Check if ANY of the attack keywords exist in the line.
                if any(keyword.lower() in line_lower for keyword in attack_keywords):
                    total_alerts += 1
                    threat_count[date_string] += 1
                    
                    # Save the log line and date for the JSON report.
                    detailed_alerts.append({
                        "date": date_string,
                        "matched_log": line.strip()
                    })
                    
        # This is the output. 
        print("--- APACHE THREAT HUNTING REPORT ---")
        print(f"Total suspicious events detected: {total_alerts}\n")
        
        if total_alerts > 0:
            print("Top 5 days with the most suspicious activity:")
            # This "most_common(5) automatically sorts the Counter and fetches the highest numbers.
            for date, count in threat_count.most_common(5):
                print(f"🚨 {date} | {count} alerts")
        else:
            print("✅ No obvious attack signatures found.")
            
        
        report_data = {
            "scan_metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "log_file_analyzed": filename,
                "total_alerts": total_alerts
            },
            "top_attacked_days": dict(threat_count.most_common(5)),
            "raw_alerts": detailed_alerts
        }
        
        # Store the result in JSON format for further analysis or reporting.
        with open(output_json, 'w') as json_file:
            json.dump(report_data, json_file, indent=4)
            
        print(f"\n📁 Detailed report saved to: {output_json}")

    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found. Make sure it's in the same folder.")

if __name__ == "__main__":
    analyze_apache_logs('Apache_2k.log')