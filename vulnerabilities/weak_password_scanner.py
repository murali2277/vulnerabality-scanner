import requests

# List of commonly used weak passwords
weak_passwords = [
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "111111",
    "abc123", "password1", "1234", "admin", "letmein", "welcome", "passw0rd"
]

# Function to attempt logging in with weak passwords
def scan_weak_password(url):
    login_endpoint = url + "/login"  # Assume a login endpoint exists
    username = "admin"  # Testing for admin or common username
    
    for password in weak_passwords:
        try:
            # Simulating a POST request to the login form
            response = requests.post(login_endpoint, data={'username': username, 'password': password})
            
            # Assuming a successful login redirects or gives a 200 OK status
            if response.status_code == 200 and "welcome" in response.text.lower():
                return f"Weak password found for user '{username}': {password}"
        
        except Exception as e:
            return f"Error scanning for weak passwords on {url}: {str(e)}"
    
    return "No weak passwords found."

