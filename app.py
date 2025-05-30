from flask import Flask, render_template, request, jsonify
import requests
from playwright.sync_api import sync_playwright
import os
import time
import logging
import re
from urllib.parse import urljoin, urlparse

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory storage for scan results
scan_results = []

# Default credentials for brute-forcing (for demo purposes)
credentials = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "user", "password": "user"}
]

# Common XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>"
]

# Common SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users; --",
    "admin' --"
]

# Common security headers to check
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security"
]

# Ensure static folder exists for screenshots
if not os.path.exists("static/screenshots"):
    os.makedirs("static/screenshots")

def take_screenshot(url, output_path):
    """Take a screenshot of the given URL using Playwright."""
    try:
        logger.debug(f"Starting screenshot process for {url}")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            logger.debug(f"Navigating to {url}")
            page.goto(url, timeout=30000)
            logger.debug("Taking screenshot")
            page.screenshot(path=output_path)
            browser.close()
            logger.debug("Screenshot completed successfully")
            return True
    except Exception as e:
        logger.error(f"Screenshot error for {url}: {str(e)}", exc_info=True)
        return False

def fingerprint_service(url):
    """Basic fingerprinting to identify web service."""
    try:
        logger.debug(f"Starting fingerprinting for {url}")
        response = requests.get(url, timeout=5)
        logger.debug(f"Response status code: {response.status_code}")
        if response.status_code == 200:
            # Check for common headers or content
            server = response.headers.get("Server", "Unknown")
            logger.debug(f"Server header: {server}")
            if "Apache" in server:
                return "Apache Web Server"
            elif "nginx" in server:
                return "Nginx Web Server"
            elif "login" in response.text.lower():
                return "Login Page"
            return "Unknown Service"
    except requests.RequestException as e:
        logger.error(f"Fingerprinting error: {str(e)}", exc_info=True)
        return "Unreachable"

def brute_force(url, username, password):
    """Simulate brute-forcing (simplified for demo)."""
    try:
        logger.debug(f"Attempting brute force for {url} with {username}:{password}")
        response = requests.get(url, auth=(username, password), timeout=5)
        logger.debug(f"Brute force response status: {response.status_code}")
        if response.status_code == 200:
            return "Success"
        return "Failed"
    except requests.RequestException as e:
        logger.error(f"Brute force error: {str(e)}", exc_info=True)
        return "Error"

def check_xss_vulnerability(url):
    """Check for XSS vulnerabilities."""
    vulnerabilities = []
    try:
        # Test GET parameters
        parsed_url = urlparse(url)
        params = dict(re.findall(r'([^=&]+)=([^&]*)', parsed_url.query))
        
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "XSS",
                        "parameter": param,
                        "payload": payload,
                        "severity": "High"
                    })
    except Exception as e:
        logger.error(f"XSS check error: {str(e)}")
    
    return vulnerabilities

def check_sql_injection(url):
    """Check for SQL injection vulnerabilities."""
    vulnerabilities = []
    try:
        # Test GET parameters
        parsed_url = urlparse(url)
        params = dict(re.findall(r'([^=&]+)=([^&]*)', parsed_url.query))
        
        for param in params:
            for payload in SQL_PAYLOADS:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                response = requests.get(test_url, timeout=5)
                # Check for common SQL error messages
                sql_errors = [
                    "SQL syntax",
                    "mysql_fetch_array",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite/JDBCDriver"
                ]
                if any(error.lower() in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "severity": "Critical"
                    })
    except Exception as e:
        logger.error(f"SQL injection check error: {str(e)}")
    
    return vulnerabilities

def check_security_headers(url):
    """Check for security headers."""
    missing_headers = []
    try:
        response = requests.get(url, timeout=5)
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                missing_headers.append({
                    "header": header,
                    "severity": "Medium",
                    "description": f"Missing {header} header"
                })
    except Exception as e:
        logger.error(f"Security headers check error: {str(e)}")
    
    return missing_headers

def check_sensitive_files(url):
    """Check for common sensitive files."""
    sensitive_files = [
        "/robots.txt",
        "/.env",
        "/.git/config",
        "/wp-config.php",
        "/config.php",
        "/phpinfo.php"
    ]
    
    found_files = []
    for file in sensitive_files:
        try:
            test_url = urljoin(url, file)
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                found_files.append({
                    "file": file,
                    "severity": "High",
                    "description": f"Sensitive file {file} is accessible"
                })
        except Exception as e:
            logger.error(f"Sensitive files check error: {str(e)}")
    
    return found_files

@app.route("/")
def index():
    """Render the main page."""
    logger.debug("Rendering index page")
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Handle scan requests."""
    try:
        url = request.form.get("url")
        logger.debug(f"Received scan request for URL: {url}")
        
        if not url:
            logger.error("No URL provided in request")
            return jsonify({"status": "error", "message": "URL is required"}), 400
            
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            logger.debug(f"Added http:// prefix to URL: {url}")

        # Take screenshot
        screenshot_path = f"static/screenshots/{int(time.time())}.png"
        logger.debug(f"Attempting to take screenshot: {screenshot_path}")
        screenshot_success = take_screenshot(url, screenshot_path)
        logger.debug(f"Screenshot success: {screenshot_success}")

        # Fingerprint service
        logger.debug("Attempting to fingerprint service")
        service = fingerprint_service(url)
        logger.debug(f"Service identified as: {service}")

        # Vulnerability scanning
        logger.debug("Starting vulnerability scan")
        vulnerabilities = []
        
        # XSS check
        xss_vulns = check_xss_vulnerability(url)
        vulnerabilities.extend(xss_vulns)
        
        # SQL injection check
        sql_vulns = check_sql_injection(url)
        vulnerabilities.extend(sql_vulns)
        
        # Security headers check
        missing_headers = check_security_headers(url)
        vulnerabilities.extend(missing_headers)
        
        # Sensitive files check
        sensitive_files = check_sensitive_files(url)
        vulnerabilities.extend(sensitive_files)

        # Brute-force attempt
        logger.debug("Starting brute-force attempts")
        brute_results = []
        for cred in credentials:
            result = brute_force(url, cred["username"], cred["password"])
            brute_results.append({
                "username": cred["username"],
                "password": cred["password"],
                "result": result
            })
            logger.debug(f"Brute force attempt result for {cred['username']}: {result}")

        # Store result
        result = {
            "url": url,
            "service": service,
            "screenshot": screenshot_path if screenshot_success else None,
            "brute_force": brute_results,
            "vulnerabilities": vulnerabilities,
            "status": "success"
        }
        scan_results.append(result)
        logger.debug("Scan completed successfully")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/results")
def results():
    """Render results page."""
    logger.debug("Rendering results page")
    return render_template("results.html", results=scan_results)

if __name__ == "__main__":
    logger.info("Starting Flask application")
    app.run(debug=True, port=5000)
