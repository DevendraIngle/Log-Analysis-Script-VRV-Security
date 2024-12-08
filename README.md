# Log File Analysis

This project analyzes web server logs, identifies suspicious activities, and generates reports in **CSV** or **PDF** format. It summarizes key findings like frequently accessed URLs, IP addresses, and failed login attempts.

## Features
- **Log Parsing**: Extracts IP addresses, request methods, URLs, and status codes.
- **Suspicious Activity Detection**: Detects failed login attempts.
- **Report Generation**: Creates CSV and PDF reports summarizing the analysis.

## Requirements
- Python 3.x
- Libraries:
  - `pandas` (for CSV generation)
  - `reportlab` (for PDF generation)

Install dependencies by running:
```bash
pip install pandas reportlab
```
## Usage
- **Step 1: Prepare the Log File**
Ensure that your log file (e.g., sample.log) is available and formatted correctly (standard web server log format, such as Apache or Nginx).

- **Step 2: Run the Scripts**
Generate CSV Report:
Run the following command to generate a CSV report:

```bash
python log_file_analysis.py
```
This will create a log_analysis_report.csv file with the analysis results.

Generate PDF Report:
Run the following command to generate a PDF report:

```bash
python log_file_analysis_pdf.py
```
This will create a log_analysis_report.pdf file summarizing the analysis in text format.

- **Step 3: Review the Results**
- **CSV Report:**
Open the log_analysis_report.csv file in any spreadsheet application (e.g., Excel) to view:

IP addresses with request counts.
Most frequently accessed endpoints.
Suspicious IP addresses based on failed login attempts.
- **PDF Report:**
Open the log_analysis_report.pdf file in any PDF viewer to see a textual summary of:

Total requests processed.
Top 5 IP addresses with the highest request counts.
Most frequently accessed URLs.
Suspicious activities based on failed login attempts.
### Example Output
- **CSV Report Example**
```bash
IP Address         Request Count
192.168.1.1        1500
192.168.1.2        1200
```
- **Most Frequently Accessed Endpoint**

```bash
Endpoint           Access Count
/index.html        1500

```
- **Suspicious Activity Detected**
```bash
IP Address         Failed Login Count
192.168.1.3        15
```
- **PDF Report Example**
```bash
Total Requests: 5000
Top 5 IP Addresses:
- 192.168.1.1: 1500 requests
- 192.168.1.2: 1200 requests

Most Frequently Accessed URL: /index.html (1500 requests)

Suspicious Activity:
- 192.168.1.3: 15 failed login attempts
```
