from flask import Flask, request, render_template, jsonify
import requests

app = Flask(__name__)

def perform_sql_injection_check(target_url):
    injection_payload = "'"
    try:
        response = requests.get(target_url + injection_payload)
        if "SQL syntax" in response.text or "sql" in response.text.lower():
            return "SQL injection vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during SQL Injection test: {e}"
    return "No SQL injection vulnerability detected."

def perform_xss_check(target_url):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(target_url, params={"input": xss_payload})
        if xss_payload in response.text:
            return "XSS vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during XSS test: {e}"
    return "No XSS vulnerability detected."

def perform_csrf_check(target_url):
    csrf_token = ""
    try:
        response = requests.get(target_url)
        if "csrf_token" in response.text:
            csrf_token = response.text.split("csrf_token = ")[1].split(";")[0]
        if csrf_token:
            payload = {"csrf_token": csrf_token}
            response = requests.post(target_url, data=payload)
            if "Invalid CSRF token" not in response.text:
                return "CSRF vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during CSRF test: {e}"
    return "No CSRF vulnerability detected."

def perform_ssrf_check(target_url):
    ssrf_payload = "http://localhost"
    try:
        response = requests.get(target_url, params={"input": ssrf_payload})
        if "Error connecting" not in response.text:
            return "SSRF vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during SSRF test: {e}"
    return "No SSRF vulnerability detected."

def perform_lfi_check(target_url):
    lfi_payload = "../../../etc/passwd"
    try:
        response = requests.get(target_url, params={"file": lfi_payload})
        if "root:" in response.text:
            return "LFI vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during LFI test: {e}"
    return "No LFI vulnerability detected."

def perform_rce_check(target_url):
    rce_payload = ";ls"
    try:
        response = requests.get(target_url, params={"input": rce_payload})
        if "bin" in response.text:
            return "RCE vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during RCE test: {e}"
    return "No RCE vulnerability detected."

def perform_command_injection_check(target_url):
    cmd_payload = ";echo Vulnerable"
    try:
        response = requests.get(target_url, params={"cmd": cmd_payload})
        if "Vulnerable" in response.text:
            return "Command Injection vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during Command Injection test: {e}"
    return "No Command Injection vulnerability detected."

def perform_open_redirect_check(target_url):
    redirect_payload = "/example.com"
    try:
        response = requests.get(target_url, params={"next": redirect_payload})
        if "example.com" in response.url:
            return "Open Redirect vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during Open Redirect test: {e}"
    return "No Open Redirect vulnerability detected."

def perform_file_upload_check(target_url):
    try:
        files = {'file': ('test.txt', 'This is a test file')}
        response = requests.post(target_url, files=files)
        if response.status_code == 200 and "test.txt" in response.text:
            return "File Upload vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during File Upload test: {e}"
    return "No File Upload vulnerability detected."

def perform_directory_traversal_check(target_url):
    traversal_payload = "../../../../etc/passwd"
    try:
        response = requests.get(target_url, params={"file": traversal_payload})
        if "root:" in response.text:
            return "Directory Traversal vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during Directory Traversal test: {e}"
    return "No Directory Traversal vulnerability detected."

def perform_xxe_check(target_url):
    xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""
    headers = {"Content-Type": "application/xml"}
    try:
        response = requests.post(target_url, data=xxe_payload, headers=headers)
        if "root:" in response.text:
            return "XXE vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during XXE test: {e}"
    return "No XXE vulnerability detected."

def perform_crlf_injection_check(target_url):
    crlf_payload = "%0D%0AHeader-Test: Hello"
    try:
        response = requests.get(target_url + crlf_payload)
        if "Header-Test" in response.headers:
            return "CRLF Injection vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during CRLF Injection test: {e}"
    return "No CRLF Injection vulnerability detected."

def perform_http_response_splitting_check(target_url):
    splitting_payload = "%0d%0aContent-Length:0"
    try:
        response = requests.get(target_url + splitting_payload)
        if response.status_code == 200:
            return "HTTP Response Splitting vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during HTTP Response Splitting test: {e}"
    return "No HTTP Response Splitting vulnerability detected."

def perform_clickjacking_check(target_url):
    try:
        response = requests.get(target_url)
        if "X-Frame-Options" not in response.headers:
            return "Clickjacking vulnerability detected!"
    except requests.RequestException as e:
        return f"Error during Clickjacking test: {e}"
    return "No Clickjacking vulnerability detected."

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url']
    results = {
        "SQL Injection": perform_sql_injection_check(target_url),
        "XSS": perform_xss_check(target_url),
        "CSRF": perform_csrf_check(target_url),
        "SSRF": perform_ssrf_check(target_url),
        "LFI": perform_lfi_check(target_url),
        "RCE": perform_rce_check(target_url),
        "Command Injection": perform_command_injection_check(target_url),
        "Open Redirect": perform_open_redirect_check(target_url),
        "File Upload": perform_file_upload_check(target_url),
        "Directory Traversal": perform_directory_traversal_check(target_url),
        "XXE": perform_xxe_check(target_url),
        "CRLF Injection": perform_crlf_injection_check(target_url),
        "HTTP Response Splitting": perform_http_response_splitting_check(target_url),
        "Clickjacking": perform_clickjacking_check(target_url)
    }
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
