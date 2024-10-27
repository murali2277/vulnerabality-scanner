import requests

def test_session_management(url):
    try:
        # Test session fixation
        response = requests.get(url, cookies={"PHPSESSID": "123456"})
        if "Set-Cookie" in response.headers and "PHPSESSID=123456" in response.headers["Set-Cookie"]:
            return f"Weak Session Management Found: Session fixation vulnerability at {url}"
        return "No session fixation vulnerability found."
    except requests.RequestException as e:
        return f"Error testing session management: {str(e)}"
