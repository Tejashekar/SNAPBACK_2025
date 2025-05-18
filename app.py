from flask import Flask, render_template, request, jsonify
import requests
from playwright.sync_api import sync_playwright
import os
import time

app = Flask(__name__)

# In-memory storage for scan results
scan_results = []

# Default credentials for brute-forcing (for demo purposes)
credentials = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "user", "password": "user"}
]

# Ensure static folder exists for screenshots
if not os.path.exists("static/screenshots"):
    os.makedirs("static/screenshots")

def take_screenshot(url, output_path):
    """Take a screenshot of the given URL using Playwright."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=30000)
            page.screenshot(path=output_path)
            browser.close()
            return True
    except Exception as e:
        print(f"Screenshot error for {url}: {e}")
        return False

def fingerprint_service(url):
    """Basic fingerprinting to identify web service."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            # Check for common headers or content
            server = response.headers.get("Server", "Unknown")
            if "Apache" in server:
                return "Apache Web Server"
            elif "nginx" in server:
                return "Nginx Web Server"
            elif "login" in response.text.lower():
                return "Login Page"
            return "Unknown Service"
    except requests.RequestException:
        return "Unreachable"

def brute_force(url, username, password):
    """Simulate brute-forcing (simplified for demo)."""
    # For demo, assume login page and check if credentials are in response
    try:
        response = requests.get(url, auth=(username, password), timeout=5)
        if response.status_code == 200:
            return "Success"
        return "Failed"
    except requests.RequestException:
        return "Error"

@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Handle scan requests."""
    try:
        url = request.form.get("url")
        if not url:
            return jsonify({"status": "error", "message": "URL is required"}), 400
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Take screenshot
        screenshot_path = f"static/screenshots/{int(time.time())}.png"
        screenshot_success = take_screenshot(url, screenshot_path)

        # Fingerprint service
        service = fingerprint_service(url)

        # Brute-force attempt
        brute_results = []
        for cred in credentials:
            result = brute_force(url, cred["username"], cred["password"])
            brute_results.append({
                "username": cred["username"],
                "password": cred["password"],
                "result": result
            })

        # Store result
        result = {
            "url": url,
            "service": service,
            "screenshot": screenshot_path if screenshot_success else None,
            "brute_force": brute_results,
            "status": "success"
        }
        scan_results.append(result)

        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/results")
def results():
    """Render results page."""
    return render_template("results.html", results=scan_results)

if __name__ == "__main__":
    app.run(debug=True, port=5000)