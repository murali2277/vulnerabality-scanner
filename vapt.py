import threading
from vulnerabilities import (
    file_inclusion_exploit, sql_injection_scanner, xss_scanner, command_injection_scanner,
    directory_traversal_scanner, open_redirect_scanner,
    weak_password_scanner
)
from vulnerabilities import (
    sql_injection_exploit, xss_exploit, command_injection_exploit,
    directory_traversal_exploit, file_inclusion_exploit
)
from file_scanner import scan_files  # Import the file scanning function

def scan_and_exploit(url):
    results = []

    # ... (previous scan logic for SQLi, XSS, etc.)

    # File Scanning for Sensitive Files
    file_scan_results = scan_files(url)
    for result in file_scan_results:
        results.append({
            'url': url,
            'vulnerability': 'File Disclosure',
            'result': result,
            'severity': 'Medium',
            'recommendation': 'Ensure proper access controls and file permissions are in place.'
        })

    # ... (more scan logic for exploits)
    
    return results
from file_scanner import scan_files

def run_vulnerability_scans_and_pen_tests(urls):
    results = []
    
    def scan_and_exploit(url):
        # Existing vulnerability scanning logic here...

        # File Upload Vulnerability Scanning
        file_upload_result = scan_files(url)
        results.append({
            'url': url,
            'vulnerability': 'File Upload Vulnerability',
            'result': file_upload_result,
            'exploit': 'N/A',
            'severity': 'High',
            'recommendation': 'Implement strict file upload validation and restrictions.'
        })

    # Threading logic remains the same...


# Multithreading helper for faster scanning
def run_vulnerability_scans_and_pen_tests(urls):
    results = []  # To store the scan and exploit results
    
    def scan_and_exploit(url):
        try:
            # SQL Injection
            sql_injection_result = sql_injection_scanner.scan_sql_injection(url)
            sql_exploit_result = sql_injection_exploit.exploit_sql_injection(url)
            results.append({
                'url': url,
                'vulnerability': 'SQL Injection',
                'result': sql_injection_result,
                'exploit': sql_exploit_result,
                'severity': 'High',
                'recommendation': 'Use prepared statements and parameterized queries.'
            })
            
            # XSS (Cross-Site Scripting)
            xss_result = xss_scanner.scan_xss(url)
            xss_exploit_result = xss_exploit.exploit_xss(url)
            results.append({
                'url': url,
                'vulnerability': 'Cross-Site Scripting (XSS)',
                'result': xss_result,
                'exploit': xss_exploit_result,
                'severity': 'Medium',
                'recommendation': 'Sanitize user inputs and apply content security policies.'
            })
            
            # Command Injection
            cmd_injection_result = command_injection_scanner.scan_command_injection(url)
            cmd_exploit_result = command_injection_exploit.exploit_command_injection(url)
            results.append({
                'url': url,
                'vulnerability': 'Command Injection',
                'result': cmd_injection_result,
                'exploit': cmd_exploit_result,
                'severity': 'Critical',
                'recommendation': 'Validate inputs, avoid executing system commands directly.'
            })
            
            # Directory Traversal
            dir_traversal_result = directory_traversal_scanner.scan_directory_traversal(url)
            dir_traversal_exploit_result = directory_traversal_exploit.exploit_directory_traversal(url)
            results.append({
                'url': url,
                'vulnerability': 'Directory Traversal',
                'result': dir_traversal_result,
                'exploit': dir_traversal_exploit_result,
                'severity': 'High',
                'recommendation': 'Restrict file paths and sanitize user input.'
            })
            
            # File Inclusion
            file_inclusion_result = file_inclusion_exploit.scan_file_inclusion(url)
            file_inclusion_exploit_result = file_inclusion_exploit.exploit_file_inclusion(url)
            results.append({
                'url': url,
                'vulnerability': 'File Inclusion',
                'result': file_inclusion_result,
                'exploit': file_inclusion_exploit_result,
                'severity': 'Critical',
                'recommendation': 'Avoid dynamic file inclusion, validate file paths.'
            })
            
            # Open Redirect
            open_redirect_result = open_redirect_scanner.scan_open_redirect(url)
            results.append({
                'url': url,
                'vulnerability': 'Open Redirect',
                'result': open_redirect_result,
                'severity': 'Low',
                'recommendation': 'Whitelist redirection URLs.'
            })
            
            # Weak Password Detection
            weak_password_result = weak_password_scanner.scan_weak_password(url)
            results.append({
                'url': url,
                'vulnerability': 'Weak Password',
                'result': weak_password_result,
                'severity': 'High',
                'recommendation': 'Enforce strong passwords and multi-factor authentication.'
            })
        
        except Exception as e:
            results.append({
                'url': url,
                'vulnerability': 'Error',
                'result': str(e),
                'severity': 'N/A',
                'recommendation': 'Check the URL or the scanning module.'
            })

    # Run each scan in a separate thread for faster execution
    threads = []
    for url in urls:
        thread = threading.Thread(target=scan_and_exploit, args=(url,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return results

""" 
import threading
from vulnerabilities import (
    sql_injection_scanner, xss_scanner, command_injection_scanner,
    directory_traversal_scanner, file_inclusion_scanner, open_redirect_scanner,
    weak_password_scanner
)

from vulnerabilities import (
    sql_injection_exploit, xss_exploit, command_injection_exploit,
    directory_traversal_exploit
)

def run_vulnerability_scans_and_pen_tests(urls):
    results = []
    
    def scan_and_exploit(url):
        # SQL Injection
        sql_injection_result = sql_injection_scanner.scan_sql_injection(url)
        sql_exploit_result = sql_injection_exploit.exploit_sql_injection(url)
        results.append({
            'url': url,
            'vulnerability': 'SQL Injection',
            'result': sql_injection_result,
            'exploit': sql_exploit_result,
            'severity': 'High',
            'recommendation': 'Use prepared statements and parameterized queries.'
        })
        
        # XSS
        xss_result = xss_scanner.scan_xss(url)
        xss_exploit_result = xss_exploit.exploit_xss(url)
        results.append({
            'url': url,
            'vulnerability': 'Cross-Site Scripting (XSS)',
            'result': xss_result,
            'exploit': xss_exploit_result,
            'severity': 'Medium',
            'recommendation': 'Sanitize user inputs and use appropriate content security policies.'
        })
        
        # Command Injection
        cmd_injection_result = command_injection_scanner.scan_command_injection(url)
        cmd_exploit_result = command_injection_exploit.exploit_command_injection(url)
        results.append({
            'url': url,
            'vulnerability': 'Command Injection',
            'result': cmd_injection_result,
            'exploit': cmd_exploit_result,
            'severity': 'Critical',
            'recommendation': 'Use proper input validation and avoid executing system commands directly.'
        })
        
        # Directory Traversal
        dir_traversal_result = directory_traversal_scanner.scan_directory_traversal(url)
        dir_traversal_exploit = directory_traversal_exploit.exploit_directory_traversal(url)
        results.append({
            'url': url,
            'vulnerability': 'Directory Traversal',
            'result': dir_traversal_result,
            'exploit': dir_traversal_exploit,
            'severity': 'High',
            'recommendation': 'Sanitize file paths and restrict file access to necessary directories.'
        })
        
        # File Inclusion
        file_inclusion_result = file_inclusion_scanner.scan_file_inclusion(url)
        file_inclusion_exploit = file_inclusion_exploit.exploit_file_inclusion(url)
        results.append({
            'url': url,
            'vulnerability': 'File Inclusion',
            'result': file_inclusion_result,
            'exploit': file_inclusion_exploit,
            'severity': 'Critical',
            'recommendation': 'Avoid dynamic file inclusion and validate file paths.'
        })
        
        # Open Redirect
        open_redirect_result = open_redirect_scanner.scan_open_redirect(url)
        results.append({
            'url': url,
            'vulnerability': 'Open Redirect',
            'result': open_redirect_result,
            'severity': 'Low',
            'recommendation': 'Validate and whitelist redirect destinations.'
        })
        
        #Weak Password Detection
        weak_password_result = weak_password_scanner.scan_weak_password(url)
        results.append({
            'url': url,
            'vulnerability': 'Weak Password',
            'result': weak_password_result,
            'severity': 'High',
            'recommendation': 'Enforce strong password policies and implement multi-factor authentication.'
        })

    threads = []
    for url in urls:
        thread = threading.Thread(target=scan_and_exploit, args=(url,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results
 """