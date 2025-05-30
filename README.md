# SNAPBACK_2025
# Snapback Clone

## Overview
Snapback Clone is a web application built with Flask that allows users to scan a target URL. The application performs the following tasks:
- Takes a screenshot of the target URL.
- Identifies the web service running on the target URL.
- Simulates a brute-force attack using predefined credentials.
- Performs passive Vulnerability assessment

## Features
- **Screenshot Capture**: Uses Playwright to take screenshots of the target URL.
- **Service Fingerprinting**: Identifies the web service running on the target URL.
- **Brute-Force Simulation**: Tests predefined credentials against the target URL.
- **Vulnerabilities Checked **:XSS (Cross-Site Scripting) Detection, SQL Injection Detection, Security Headers Check, Sensitive Files Detection:
## Prerequisites
- Python 3.6 or higher
- Flask
- Requests
- Playwright

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd snapback-clone
   ```

2. Install the required dependencies:
   ```bash
   pip install flask requests playwright
   ```

3. Install Playwright browser binaries:
   ```bash
   playwright install
   ```

## Usage
1. Start the Flask application:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to `http://127.0.0.1:5000`.

3. Enter a target URL in the input field and click "Start Scan".
![Screenshot 2025-05-18 094500](https://github.com/user-attachments/assets/368e7cd3-8e47-44f2-8639-2a3a528085c5)
![Screenshot 2025-05-18 094513](https://github.com/user-attachments/assets/58334032-2156-424a-bc7f-4a4ed47cf722)

4. View the scan results, including the screenshot, service identification, and brute-force results.

## Notes
- This application is intended for educational purposes only. Do not use it for unauthorized testing or attacks.
- The application runs in debug mode, which is not suitable for production deployment.

