*(Make sure to replace `[PASTE YOUR IMAGE LINK HERE]` with the `<img src="...">` link you generated earlier!)*

---

### 2. Apache Threat Hunter (`README.md`)
*(For your `Apache-Threat-Hunter` repository)*

```markdown
# 🕵️‍♂️ Apache Web Server Threat Hunter

## 📌 Project Overview
In a Security Operations Center (SOC), analysts must parse massive amounts of web server logs to find malicious activity. This Python script automates the triage of Apache web logs by hunting for known attack signatures (such as SQL injection attempts, directory traversal, and vulnerability scanning) and generating a structured JSON report.

## 🛠️ Technical Skills Demonstrated
*   **Log Parsing & Regex:** Used Regular Expressions to extract timestamps from raw, unstructured log lines.
*   **Threat Intelligence:** Applied static keyword matching for common web exploits (e.g., `etc/passwd`, `UNION SELECT`).
*   **Data Aggregation:** Utilized Python `collections.Counter` to group alerts by date and identify the top days of malicious activity.
*   **Automated Reporting:** Exported findings into a structured JSON file, simulating how SOC tools feed data into SIEMs (like Splunk or Elastic).

## 📁 Dataset Used
This project uses the **Apache_2k.log** dataset from the open-source **[Loghub Repository](https://github.com/logpai/loghub)**. It contains real-world Apache web server logs. *(Note: The raw log file is not included in this repository to keep it lightweight. Download it from Loghub to test the script).*

## 🚀 How to Run
1. Download `Apache_2k.log` from Loghub and place it in the same directory as the script.
2. Run the script:
   ```bash
   python threat_hunting.py