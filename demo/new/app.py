import os
from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import urllib.parse
import logging
import re
import ssl
import socket
import jwt
import json
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

app = Flask(__name__)
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def _safe_request(self, url: str, method: str = 'GET', 
                     data: Optional[Dict] = None, 
                     headers: Optional[Dict] = None,
                     files: Optional[Dict]=None,
                     allow_redirects: Optional[Dict]=True,
                     timeout: int = 10) -> Optional[requests.Response]:
        try:
            response = self.session.request(
                method, 
                url, 
                data=data,
                files=files, 
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=False  # For testing only - enable SSL verification in production
            )
            return response
        except requests.exceptions.Timeout:
            print(f"Request timed out for URL: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return None

    def check_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        test_payloads = [
            "1' OR '1'='1",
            "admin' --",
            "1; DROP TABLE users",
            "1' UNION SELECT NULL--",
        ]
        findings = []
        
        for payload in test_payloads:
            test_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
            response = self._safe_request(test_url)
            
            if response:
                sql_errors = [
                    'sql syntax',
                    'mysql error',
                    'sqlite error',
                    'postgresql error',
                    'ORA-',
                    'SQL Server error'
                ]
                
                if any(error in response.text.lower() for error in sql_errors):
                    findings.append({
                        'payload': payload,
                        'url': test_url,
                        'status': 'danger',
                        'detail': 'Potential SQL injection vulnerability detected'
                    })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'SQL Injection',
            'status': status,
            'findings': findings
        }

    def check_xss(self) -> Dict:
        """Test for XSS vulnerabilities"""
        test_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ]
        findings = []
        
        for payload in test_payloads:
            test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
            response = self._safe_request(test_url)
            
            if response and payload in response.text:
                findings.append({
                    'payload': payload,
                    'url': test_url,
                    'status': 'danger',
                    'detail': 'Potential XSS vulnerability detected'
                })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'Cross-Site Scripting (XSS)',
            'status': status,
            'findings': findings
        }

    def check_csrf(self) -> Dict:
        """Check for CSRF protections"""
        findings = []
        response = self._safe_request(self.target_url)
        
        if response:
            # Check for CSRF tokens in forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                csrf_token = form.find('input', attrs={'name': re.compile(r'csrf|token', re.I)})
                if not csrf_token:
                    findings.append({
                        'form_action': form.get('action', ''),
                        'status': 'warning',
                        'detail': 'Form without CSRF token detected'
                    })
            
            # Check for SameSite cookie attribute
            if 'Set-Cookie' in response.headers:
                if 'SameSite' not in response.headers['Set-Cookie']:
                    findings.append({
                        'cookie': response.headers['Set-Cookie'],
                        'status': 'warning',
                        'detail': 'Cookie without SameSite attribute detected'
                    })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'CSRF Protection',
            'status': status,
            'findings': findings
        }

    def check_directory_traversal(self) -> Dict:
        """Test for directory traversal vulnerabilities"""
        test_paths = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
            '..\\..\\..',
        ]
        findings = []
        
        for path in test_paths:
            test_url = f"{self.target_url}?file={urllib.parse.quote(path)}"
            response = self._safe_request(test_url)
            
            if response and any(x in response.text for x in ['root:', 'bin:', '/usr/bin']):
                findings.append({
                    'path': path,
                    'url': test_url,
                    'status': 'danger',
                    'detail': 'Potential directory traversal vulnerability detected'
                })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'Directory Traversal',
            'status': status,
            'findings': findings
        }

    def check_file_upload(self) -> Dict:
        """Test file upload security"""
        test_files = {
            'malicious.php': ('malicious.php', '<?php echo "test"; ?>', 'application/x-php'),
            'malicious.php.jpg': ('malicious.php.jpg', '<?php echo "test"; ?>', 'image/jpeg'),
            'large_file.txt': ('large_file.txt', 'A' * 1024 * 1024, 'text/plain'),
        }
        findings = []
        
        for filename, file_data in test_files.items():
            files = {'file': file_data}
            response = self._safe_request(
                f"{self.target_url}/upload",
                method='POST',
                data={},
                files=files
            )
            
            if response and response.status_code == 200:
                findings.append({
                    'filename': filename,
                    'status': 'warning',
                    'detail': f'Potentially unsafe file upload accepted: {filename}'
                })
        
        status = 'warning' if findings else 'safe'
        return {
            'name': 'File Upload',
            'status': status,
            'findings': findings
        }
    def check_ssl_tls(self) -> Dict:
        """Check SSL/TLS configuration"""
        findings = []
        hostname = urllib.parse.urlparse(self.target_url).hostname
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        findings.append({
                            'status': 'danger',
                            'detail': 'SSL certificate has expired'
                        })
                    
                    # Check protocol version
                    version = ssock.version()
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append({
                            'status': 'danger',
                            'detail': f'Insecure protocol version in use: {version}'
                        })
        except Exception as e:
            findings.append({
                'status': 'danger',
                'detail': f'SSL/TLS connection failed: {str(e)}'
            })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'SSL/TLS Security',
            'status': status,
            'findings': findings
        }
    
    def check_security_headers(self) -> Dict:
        """Check security headers"""
        findings = []
        response = self._safe_request(self.target_url)
        
        if response:
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Referrer-Policy': 'Missing Referrer-Policy header',
                'Permissions-Policy': 'Missing Permissions-Policy header',
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    findings.append({
                        'header': header,
                        'status': 'warning',
                        'detail': message
                    })
            
            # Check for information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and any(tech in server_header for tech in ['Apache', 'nginx', 'PHP', 'MySQL']):
                findings.append({
                    'header': 'Server',
                    'status': 'warning',
                    'detail': f'Server header reveals technology: {server_header}'
                })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'Security Headers',
            'status': status,
            'findings': findings
        }

    def check_jwt_security(self) -> Dict:
        """Check JWT token security"""
        findings = []
        
        # Common JWT secrets
        test_secrets = ['secret', 'key', 'private_key', '1234567890']
        test_payload = {'user': 'admin'}
        
        for secret in test_secrets:
            try:
                token = jwt.encode(test_payload, secret, algorithm='HS256')
                response = self._safe_request(
                    self.target_url,
                    headers={'Authorization': f'Bearer {token}'}
                )
                
                if response and response.status_code != 401:
                    findings.append({
                        'secret': secret,
                        'status': 'danger',
                        'detail': f'Weak JWT secret accepted: {secret}'
                    })
            except Exception:
                pass
        
        # Test for "none" algorithm
        try:
            header = {'typ': 'JWT', 'alg': 'none'}
            token_parts = [
                base64.b64encode(json.dumps(header).encode()).decode().rstrip('='),
                base64.b64encode(json.dumps(test_payload).encode()).decode().rstrip('='),
                ''
            ]
            token = '.'.join(token_parts)
            
            response = self._safe_request(
                self.target_url,
                headers={'Authorization': f'Bearer {token}'}
            )
            
            if response and response.status_code != 401:
                findings.append({
                    'status': 'danger',
                    'detail': 'JWT "none" algorithm accepted'
                })
        except Exception:
            pass
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'JWT Security',
            'status': status,
            'findings': findings
        }

    def check_open_redirects(self) -> Dict:
        """Check for open redirect vulnerabilities"""
        findings = []
        test_urls = [
            'https://evil.com',
            '//evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '\\\\evil.com',
            '%2F%2Fevil.com',
        ]
        
        for test_url in test_urls:
            redirect_params = [
                f'?redirect={urllib.parse.quote(test_url)}',
                f'?url={urllib.parse.quote(test_url)}',
                f'?next={urllib.parse.quote(test_url)}',
                f'?return={urllib.parse.quote(test_url)}',
            ]
            
            for param in redirect_params:
                response = self._safe_request(
                    f"{self.target_url}{param}",
                    allow_redirects=False
                )
                
                if response and response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if test_url in location or urllib.parse.unquote(test_url) in location:
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'status': 'danger',
                            'detail': f'Open redirect detected with parameter: {param}'
                        })
        
        status = 'danger' if findings else 'safe'
        return {
            'name': 'Open Redirects',
            'status': status,
            'findings': findings
        }

    def check_rate_limiting(self) -> Dict:
        """Check for rate limiting"""
        findings = []
        num_requests = 50
        interval_seconds = 10
        
        start_time = datetime.now()
        responses = []
        
        for _ in range(num_requests):
            response = self._safe_request(self.target_url)
            if response:
                responses.append(response.status_code)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        # Check if all requests were successful
        if all(status == 200 for status in responses):
            findings.append({
                'requests': num_requests,
                'duration': duration,
                'status': 'warning',
                'detail': f'No rate limiting detected ({num_requests} requests in {duration:.2f}s)'
            })
        
        status = 'warning' if findings else 'safe'
        return {
            'name': 'Rate Limiting',
            'status': status,
            'findings': findings
        }

    def run_all_checks(self) -> Dict:
        """Run all security checks"""
        results = {
            'scan_time': datetime.now().isoformat(),
            'target_url': self.target_url,
            'checks': {}
        }
        
        checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_csrf,
            self.check_directory_traversal,
            self.check_file_upload,
            self.check_ssl_tls,
            self.check_security_headers,
            self.check_jwt_security,
            self.check_open_redirects,
            self.check_rate_limiting,
        ]
        
        for check in checks:
            try:
                check_result = check()
                results['checks'][check.__name__] = check_result
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {str(e)}")
                results['checks'][check.__name__] = {
                    'name': check.__name__,
                    'status': 'error',
                    'error': str(e)
                }
        
        return results
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/scanhtml')
def scanhtml():
    return render_template('scan.html')
@app.route('/history')
def history():
    return render_template('history.html')
@app.route('/setting')
def setting():
    return render_template('setting.html')
@app.route('/help')
def help():
    return render_template('help.html')
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_url = data.get('url')
    selected_checks = data.get('checks', [])
    
    if not target_url:
        return jsonify({'error': 'No target URL provided'}), 400
    
    scanner = SecurityScanner(target_url)
    results = scanner.run_all_checks()
    
    return jsonify([results])


if __name__ == '__main__':
    app.run(debug=True)

