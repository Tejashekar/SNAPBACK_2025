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
- **Vulnerabilities Checked**:XSS (Cross-Site Scripting) Detection, SQL Injection Detection, Security Headers Check, Sensitive Files Detection:
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


4. View the scan results, including the screenshot, service identification, and brute-force results.
![WhatsApp Image 2025-05-30 at 13 10 56_5890840f](https://github.com/user-attachments/assets/18567582-f111-4ba4-81db-07b767a93316)
![WhatsApp Image 2025-05-30 at 13 10 55_e51242df](https://github.com/user-attachments/assets/3176864c-0182-462b-8d9b-5f37c8e51e72)
![WhatsApp Image 2025-05-30 at 13 10 55_f2efc1f3](https://github.com/user-attachments/assets/ecf1be2d-4334-414b-9295-0de69decb94b)
![WhatsApp Image 2025-05-30 at 13 10 55_0513c8e1](https://github.com/user-attachments/assets/8197bfd7-dd3e-4441-9754-90fe5babc1fd)


## Notes
- This application is intended for educational purposes only. Do not use it for unauthorized testing or attacks.
- The application runs in debug mode, which is not suitable for production deployment.

