import requests

# Common sensitive files for scanning
COMMON_FILES = [
    "/etc/passwd",                       # Unix user file
    "/proc/self/environ",                # Environment variables
    "/var/log/apache2/access.log",       # Apache access log
    "/windows/system32/drivers/etc/hosts",  # Windows hosts file
    "/windows/win.ini",                  # Windows system file
    "/index.php",                        # Test for file inclusion with common files
    "/config.php",                       # Configuration file for PHP applications
    "/.htaccess",                        # Apache access control file
    "/robots.txt",                       # Publicly available file for bots
    "/sitemap.xml",                      # Sitemap file
    "/default.aspx",                     # Default ASP.NET file
    "/config.json",                      # Configuration file (JSON)
    "/web.config"                        # ASP.NET configuration file
]

# Function to scan different types of files for vulnerabilities
def scan_files(url):
    """
    Attempts to access different files commonly targeted for vulnerabilities like
    file inclusion, directory traversal, or leakage of sensitive information.
    
    Parameters:
        url (str): The base URL to scan.
        
    Returns:
        list: A list of scan results.
    """
    results = []
    
    for file_path in COMMON_FILES:
        try:
            scan_url = url + file_path
            response = requests.get(scan_url)
            
            if response.status_code == 200:
                # If the response contains system-specific or sensitive content
                if "root:" in response.text:
                    results.append(f"Potential LFI vulnerability found: {scan_url} (Exposed /etc/passwd)")
                elif "[extensions]" in response.text:
                    results.append(f"Potential LFI vulnerability found: {scan_url} (Exposed Windows win.ini)")
                elif "localhost" in response.text or "127.0.0.1" in response.text:
                    results.append(f"Potential file disclosure found: {scan_url} (Exposed sensitive information)")
                else:
                    # In case file was found but did not contain explicit sensitive information
                    results.append(f"File found but no sensitive content: {scan_url}")
            elif response.status_code == 403:
                results.append(f"Access forbidden to file: {scan_url} (HTTP 403)")
            elif response.status_code == 404:
                results.append(f"File not found: {scan_url} (HTTP 404)")
        except Exception as e:
            results.append(f"Error scanning {scan_url}: {str(e)}")
    
    return results
