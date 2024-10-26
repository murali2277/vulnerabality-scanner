import requests

def scan_open_redirect(url):
    payloads = [
        '/?redirect=http://malicious.com',
        '/?url=http://malicious.com',
        '/redirect?url=http://malicious.com'
    ]
    
    for payload in payloads:
        try:
            full_url = url + payload
            response = requests.get(full_url, allow_redirects=False)
            
            if response.status_code == 302 and 'malicious.com' in response.headers.get('Location', ''):
                return f"Open redirect vulnerability found: {full_url}"
        except Exception as e:
            return f"Error scanning for open redirects on {url}: {str(e)}"
    
    return "No open redirect vulnerability found."
