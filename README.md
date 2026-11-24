#  Apache Web Server Threat Hunter

## Project Overview
In a Security Operations Center (SOC), analysts must parse massive amounts of web server logs to find malicious activity. This Python script automates the triage of Apache web logs by hunting for known attack signatures (such as SQL injection attempts, directory traversal, and vulnerability scanning) and generating a structured JSON report.

## Technical Skills Demonstrated
*   **Log Parsing & Regex:** Used Regular Expressions to extract timestamps from raw, unstructured log lines.
*   **Threat Intelligence:** Applied static keyword matching for common web exploits (e.g., `etc/passwd`, `UNION SELECT`).
*   **Data Aggregation:** Utilized Python `collections.Counter` to group alerts by date and identify the top days of malicious activity.
*   **Automated Reporting:** Exported findings into a structured JSON file, simulating how SOC tools feed data into SIEMs (like Splunk or Elastic).

## Dataset Used
This project utilizes the **Apache_2k.log** dataset from the open-source **[Loghub Repository](https://github.com/logpai/loghub)** to simulate real-world server logs. 

*Note: To demonstrate the script's detection capabilities, a simulated directory traversal attack payload (`/etc/passwd`) was manually injected into the log file. The script successfully triggered an alert and generated a JSON report based on this controlled test case.*

## How to Run
1. Clone this repository.
2. Use the included `sample_Apache_log.txt` file which contains the simulated attack payload.
3. Open `treat_hunting.py` and ensure the filename on the last line is set to `'sample_Apache_log.txt'`.
4. Run the script:
   ```bash
   python treat_hunting.py
```
```
<img width="960" height="514" alt="pas3" src="https://github.com/user-attachments/assets/96ca6e3d-12e4-4c09-a301-3fc520b17e21" />
