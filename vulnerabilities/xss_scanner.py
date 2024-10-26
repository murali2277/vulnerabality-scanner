import requests

def scan_xss(url):
    xss_payloads = [
        "<script>alert(1)</script>",      # Basic script injection
        '"><script>alert(1)</script>',    # Injection through parameters
        '<img src=x onerror=alert(1)>',   # Image-based XSS
        '<svg onload=alert(1)>',          # SVG injection
        '"><svg onload=alert(1)>',        # Combination of param & SVG
    ]
    
    results = []
    
    for payload in xss_payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url)
            if payload in response.text:
                results.append(f"XSS Vulnerability Found: {test_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error scanning {url}: {str(e)}")
    
    if not results:
        return "No XSS vulnerabilities found."
    
    return results
