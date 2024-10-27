import requests
from bs4 import BeautifulSoup

def scan_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'name': 'csrf_token'}):
            return f"CSRF Vulnerability Found in Form: {form.get('action')}"
    
    return "No CSRF vulnerability found."
