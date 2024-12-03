# vrv_security_task
 Processes log files to extract and analyze key information. 
# Web Traffic Analyzer

## Overview
The **Web Traffic Analyzer** is a Python tool designed to analyze web server log files. It extracts actionable insights such as:
- Identifying the most frequently accessed resources on the server.
- Detecting suspicious activities, such as failed login attempts.
- Tracking the number of requests made by individual IP addresses.

The tool processes web server logs, identifies key patterns, and generates a detailed report, both on the console and in a CSV file.

## Features
- **Traffic Analysis**: Tracks requests from different IP addresses and displays the top 5 IPs with the most requests.
- **Resource Popularity**: Identifies the most frequently accessed resource on the server.
- **Security Monitoring**: Detects potential security threats by tracking failed login attempts, and flags suspicious IP addresses.
- **Report Generation**: Outputs analysis results to the terminal and generates a CSV report (`log_analysis_results.csv`).

## Installation

### Prerequisites
- Python 3.x (Tested with Python 3.7 and above)
- Required Python libraries:
  - `re`
  - `csv`
  - `sys`

### Steps to Set Up
1. Clone the repository:
   ```bash
   git clone https://github.com/hpk22/vrv_security_task
### Running the analyser
   ```bash
   python log_analysis.py 

