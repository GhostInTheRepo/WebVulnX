"""
WebVulnX - Real Security Scanner
Performs actual vulnerability scanning with real detection
"""

import requests
import re
import time
import socket
import ssl
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import urllib3
import traceback
import hashlib

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Shodan API Configuration
SHODAN_API_KEY = "So5OBkIagDQGLJTvzkO0G3L9ykotMsOp"
SHODAN_API_URL = "https://api.shodan.io"


# Vulnerability Database with CVSS Scores
VULN_DATABASE = {
    'sql_injection': {
        'name': 'SQL Injection',
        'cvss_score': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'critical',
        'cwe': 'CWE-89',
        'description': 'SQL Injection allows attackers to execute arbitrary SQL commands, potentially leading to data theft, modification, or deletion.',
        'recommendation': [
            'Use parameterized queries or prepared statements',
            'Implement input validation and sanitization',
            'Apply least privilege principle for database accounts',
            'Use ORM frameworks that automatically escape queries',
            'Implement Web Application Firewall (WAF) rules'
        ],
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cwe.mitre.org/data/definitions/89.html'
        ]
    },
    'xss_reflected': {
        'name': 'Reflected Cross-Site Scripting (XSS)',
        'cvss_score': 6.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'severity': 'medium',
        'cwe': 'CWE-79',
        'description': 'Reflected XSS allows attackers to inject malicious scripts that execute in victim browsers, enabling session hijacking or phishing.',
        'recommendation': [
            'Encode all user input before rendering in HTML',
            'Implement Content Security Policy (CSP) headers',
            'Use HTTPOnly and Secure flags on cookies',
            'Validate and sanitize all input on server-side',
            'Use frameworks with automatic output encoding'
        ],
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cwe.mitre.org/data/definitions/79.html'
        ]
    },
    'csrf': {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'cvss_score': 6.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
        'severity': 'medium',
        'cwe': 'CWE-352',
        'description': 'CSRF forces authenticated users to perform unintended actions, potentially leading to unauthorized state changes.',
        'recommendation': [
            'Implement anti-CSRF tokens in all forms',
            'Use SameSite cookie attribute',
            'Verify Origin and Referer headers',
            'Require re-authentication for sensitive actions',
            'Use custom request headers for AJAX calls'
        ],
        'references': [
            'https://owasp.org/www-community/attacks/csrf',
            'https://cwe.mitre.org/data/definitions/352.html'
        ]
    },
    'lfi': {
        'name': 'Local File Inclusion (LFI)',
        'cvss_score': 8.6,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
        'severity': 'high',
        'cwe': 'CWE-98',
        'description': 'LFI allows attackers to read sensitive files from the server, potentially exposing credentials and configuration.',
        'recommendation': [
            'Never use user input directly in file paths',
            'Use allowlist for permitted files',
            'Implement proper input validation',
            'Set proper file system permissions',
            'Disable dangerous PHP functions'
        ],
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    },
    'missing_security_header': {
        'name': 'Missing Security Headers',
        'cvss_score': 4.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
        'severity': 'low',
        'cwe': 'CWE-693',
        'description': 'Missing security headers leave the application vulnerable to client-side attacks like clickjacking and XSS.',
        'recommendation': [
            'Add X-Frame-Options: DENY or SAMEORIGIN',
            'Add X-Content-Type-Options: nosniff',
            'Configure Content-Security-Policy header',
            'Enable Strict-Transport-Security (HSTS)',
            'Add X-XSS-Protection: 1; mode=block'
        ],
        'references': [
            'https://owasp.org/www-project-secure-headers/'
        ]
    },
    'sensitive_exposure': {
        'name': 'Sensitive Data Exposure',
        'cvss_score': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'severity': 'high',
        'cwe': 'CWE-200',
        'description': 'Sensitive files or data are publicly accessible, potentially exposing credentials or source code.',
        'recommendation': [
            'Remove or restrict access to sensitive files',
            'Configure proper web server access rules',
            'Never commit secrets to repositories',
            'Implement proper access controls',
            'Regular security audits'
        ],
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    },
    'cors_misconfiguration': {
        'name': 'CORS Misconfiguration',
        'cvss_score': 5.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'severity': 'medium',
        'cwe': 'CWE-942',
        'description': 'Insecure CORS policy allows unauthorized cross-origin requests, potentially leaking sensitive data.',
        'recommendation': [
            'Configure strict origin allowlist',
            'Avoid using wildcard (*) for allowed origins',
            'Validate Origin header server-side',
            'Do not reflect arbitrary origins with credentials',
            'Use proper preflight request handling'
        ],
        'references': [
            'https://portswigger.net/web-security/cors'
        ]
    },
    'server_info': {
        'name': 'Server Information Disclosure',
        'cvss_score': 3.7,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'severity': 'info',
        'cwe': 'CWE-200',
        'description': 'Server reveals version information that could help attackers identify known vulnerabilities.',
        'recommendation': [
            'Remove server version from HTTP headers',
            'Configure custom error pages',
            'Disable detailed error messages',
            'Remove X-Powered-By header'
        ],
        'references': [
            'https://cwe.mitre.org/data/definitions/200.html'
        ]
    },
    'open_redirect': {
        'name': 'Open Redirect',
        'cvss_score': 4.7,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N',
        'severity': 'low',
        'cwe': 'CWE-601',
        'description': 'Open redirect allows attackers to redirect users to malicious sites, enabling phishing attacks.',
        'recommendation': [
            'Validate redirect URLs against allowlist',
            'Use relative URLs for redirects',
            'Warn users before external redirects',
            'Never use user input directly in redirects'
        ],
        'references': [
            'https://cwe.mitre.org/data/definitions/601.html'
        ]
    }
}


class RealVulnerabilityScanner:
    """Real vulnerability scanner with actual security testing"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVulnX-Scanner/2.0 (Security Assessment)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        self.session.verify = False
        self.session.timeout = 15
        
    def scan(self, target: str) -> dict:
        """Perform comprehensive real security scan"""
        start_time = time.time()
        
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        results = {
            'target': target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scanner': 'WebVulnX v2.0',
            'vulnerabilities': [],
            'info': [],
            'scan_time': 0,
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'scan_status': 'completed',
            'ip_address': ''
        }
        
        try:
            # Resolve IP
            parsed = urlparse(target)
            hostname = parsed.netloc.split(':')[0]
            results['ip_address'] = socket.gethostbyname(hostname)
        except:
            pass
        
        try:
            # Test connectivity first
            print(f"[*] Scanning target: {target}")
            base_response = self.session.get(target, timeout=15, allow_redirects=True)
            print(f"[+] Target reachable: {base_response.status_code}")
            
            # Store base info
            results['info'] = self._gather_info(target, base_response)
            
            # Run all security checks
            vulnerabilities = []
            
            # 1. Security Headers Check (real)
            print("[*] Checking security headers...")
            header_vulns = self._check_security_headers(target, base_response)
            vulnerabilities.extend(header_vulns)
            
            # 2. CSRF Check (real)
            print("[*] Checking for CSRF...")
            csrf_vulns = self._check_csrf(target, base_response)
            vulnerabilities.extend(csrf_vulns)
            
            # 3. CORS Check (real)
            print("[*] Checking CORS configuration...")
            cors_vulns = self._check_cors(target)
            vulnerabilities.extend(cors_vulns)
            
            # 4. Sensitive Files Check (real)
            print("[*] Checking for sensitive files...")
            sensitive_vulns = self._check_sensitive_files(target)
            vulnerabilities.extend(sensitive_vulns)
            
            # 5. XSS Check (real)
            print("[*] Checking for XSS vulnerabilities...")
            xss_vulns = self._check_xss(target, base_response)
            vulnerabilities.extend(xss_vulns)
            
            # 6. SQL Injection Check (real)
            print("[*] Checking for SQL Injection...")
            sqli_vulns = self._check_sqli(target, base_response)
            vulnerabilities.extend(sqli_vulns)
            
            # 7. LFI Check (real)
            print("[*] Checking for LFI...")
            lfi_vulns = self._check_lfi(target)
            vulnerabilities.extend(lfi_vulns)
            
            # 8. Open Redirect Check (real)
            print("[*] Checking for Open Redirect...")
            redirect_vulns = self._check_open_redirect(target)
            vulnerabilities.extend(redirect_vulns)
            
            # 9. SSL/TLS Check (real)
            print("[*] Checking SSL/TLS...")
            ssl_vulns = self._check_ssl(target)
            vulnerabilities.extend(ssl_vulns)
            
            # 10. Check Shodan for known vulnerabilities
            print("[*] Checking Shodan for known vulns...")
            shodan_vulns = self._check_shodan_vulns(target)
            vulnerabilities.extend(shodan_vulns)
            
            results['vulnerabilities'] = vulnerabilities
            
            # Calculate summary
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                results['summary']['total'] += 1
                if severity in results['summary']:
                    results['summary'][severity] += 1
            
            print(f"[+] Scan complete: {results['summary']['total']} findings")
            
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Connection error: {e}")
            results['scan_status'] = 'connection_failed'
            results['vulnerabilities'].append({
                'name': 'Target Unreachable',
                'severity': 'info',
                'cvss_score': 0,
                'description': f'Could not connect to target: {str(e)[:100]}',
                'recommendation': ['Verify the target URL is correct', 'Check if the server is running'],
                'type': 'connectivity'
            })
        except Exception as e:
            print(f"[-] Scan error: {e}")
            traceback.print_exc()
            results['scan_status'] = 'error'
        
        results['scan_time'] = round(time.time() - start_time, 2)
        
        # Sort by CVSS score
        results['vulnerabilities'].sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return results
    
    def _gather_info(self, target: str, response) -> list:
        """Gather real target information"""
        info = []
        try:
            info.append({'key': 'Status Code', 'value': str(response.status_code)})
            info.append({'key': 'Server', 'value': response.headers.get('Server', 'Not disclosed')})
            info.append({'key': 'Powered By', 'value': response.headers.get('X-Powered-By', 'Not disclosed')})
            info.append({'key': 'Content Type', 'value': response.headers.get('Content-Type', 'Unknown')})
            info.append({'key': 'Response Size', 'value': f'{len(response.content)} bytes'})
            
            # Get IP
            parsed = urlparse(target)
            try:
                ip = socket.gethostbyname(parsed.netloc.split(':')[0])
                info.append({'key': 'IP Address', 'value': ip})
            except:
                pass
                
        except Exception as e:
            info.append({'key': 'Error', 'value': str(e)})
        
        return info
    
    def _check_security_headers(self, target: str, response) -> list:
        """Check for missing security headers (REAL)"""
        vulns = []
        
        headers_to_check = {
            'X-Frame-Options': 'Clickjacking protection not enabled',
            'X-Content-Type-Options': 'MIME-type sniffing not prevented',
            'Strict-Transport-Security': 'HSTS not enabled - vulnerable to protocol downgrade',
            'Content-Security-Policy': 'No CSP - reduced XSS protection',
            'X-XSS-Protection': 'Browser XSS filter not enabled',
            'Referrer-Policy': 'Referrer information may leak'
        }
        
        response_headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        for header, message in headers_to_check.items():
            if header.lower() not in response_headers_lower:
                vuln = VULN_DATABASE['missing_security_header'].copy()
                vulns.append({
                    'name': f'Missing {header} Header',
                    'severity': vuln['severity'],
                    'cvss_score': vuln['cvss_score'],
                    'cvss_vector': vuln['cvss_vector'],
                    'cwe': vuln['cwe'],
                    'description': message,
                    'matched_at': target,
                    'evidence': f'Header "{header}" not found in response',
                    'recommendation': vuln['recommendation'],
                    'references': vuln['references'],
                    'type': 'missing_header'
                })
        
        return vulns
    
    def _check_csrf(self, target: str, response) -> list:
        """Check for CSRF vulnerabilities (REAL)"""
        vulns = []
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                return vulns
            
            csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token', 
                            'csrfmiddlewaretoken', 'xsrf', '__requestverificationtoken']
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Only check POST forms (CSRF is mainly for state-changing requests)
                if form_method != 'post':
                    continue
                
                # Check for CSRF token
                has_csrf = False
                inputs = form.find_all('input', type='hidden')
                
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if any(pattern in name for pattern in csrf_patterns):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    vuln = VULN_DATABASE['csrf'].copy()
                    vulns.append({
                        'name': vuln['name'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln['cvss_score'],
                        'cvss_vector': vuln['cvss_vector'],
                        'cwe': vuln['cwe'],
                        'description': vuln['description'],
                        'matched_at': target,
                        'evidence': f'POST form at "{form_action}" lacks CSRF token',
                        'recommendation': vuln['recommendation'],
                        'references': vuln['references'],
                        'type': 'csrf'
                    })
                    break  # Report only once
                    
        except Exception as e:
            print(f"    CSRF check error: {e}")
        
        return vulns
    
    def _check_cors(self, target: str) -> list:
        """Check for CORS misconfigurations (REAL)"""
        vulns = []
        
        try:
            # Test with malicious origin
            headers = {'Origin': 'https://evil-attacker.com'}
            response = self.session.get(target, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                vuln = VULN_DATABASE['cors_misconfiguration'].copy()
                vulns.append({
                    'name': 'CORS Wildcard Origin',
                    'severity': vuln['severity'],
                    'cvss_score': vuln['cvss_score'],
                    'cvss_vector': vuln['cvss_vector'],
                    'cwe': vuln['cwe'],
                    'description': 'CORS allows requests from any origin (wildcard)',
                    'matched_at': target,
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'recommendation': vuln['recommendation'],
                    'references': vuln['references'],
                    'type': 'cors'
                })
            elif 'evil-attacker.com' in acao:
                cvss = 7.5 if acac.lower() == 'true' else 5.3
                vuln = VULN_DATABASE['cors_misconfiguration'].copy()
                vulns.append({
                    'name': 'CORS Origin Reflection',
                    'severity': 'high' if acac.lower() == 'true' else 'medium',
                    'cvss_score': cvss,
                    'cvss_vector': vuln['cvss_vector'],
                    'cwe': vuln['cwe'],
                    'description': f'Server reflects arbitrary origins (credentials: {acac})',
                    'matched_at': target,
                    'evidence': f'Origin "evil-attacker.com" reflected in ACAO header',
                    'recommendation': vuln['recommendation'],
                    'references': vuln['references'],
                    'type': 'cors'
                })
                
        except Exception as e:
            print(f"    CORS check error: {e}")
        
        return vulns
    
    def _check_sensitive_files(self, target: str) -> list:
        """Check for exposed sensitive files (REAL)"""
        vulns = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        sensitive_paths = [
            ('/.git/config', 'Git repository configuration exposed', True),
            ('/.git/HEAD', 'Git repository HEAD exposed', True),
            ('/.env', 'Environment file exposed - may contain secrets', True),
            ('/robots.txt', 'Robots.txt found - check for hidden paths', False),
            ('/.htaccess', 'Apache configuration exposed', True),
            ('/web.config', 'IIS configuration exposed', True),
            ('/phpinfo.php', 'PHP info page exposed', True),
            ('/wp-config.php.bak', 'WordPress config backup exposed', True),
            ('/config.php.bak', 'Configuration backup exposed', True),
            ('/.svn/entries', 'SVN repository exposed', True),
            ('/backup.sql', 'Database backup exposed', True),
            ('/.DS_Store', 'macOS directory file exposed', False),
            ('/server-status', 'Apache server status exposed', True),
            ('/.well-known/security.txt', 'Security policy file', False),
            ('/crossdomain.xml', 'Flash cross-domain policy', False),
            ('/sitemap.xml', 'Sitemap file', False)
        ]
        
        for path, message, is_critical in sensitive_paths:
            try:
                url = urljoin(base_url, path)
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Verify it's not a soft 404
                    if not self._is_soft_404(resp):
                        vuln = VULN_DATABASE['sensitive_exposure'].copy()
                        
                        vulns.append({
                            'name': message,
                            'severity': 'high' if is_critical else 'low',
                            'cvss_score': vuln['cvss_score'] if is_critical else 3.0,
                            'cvss_vector': vuln['cvss_vector'],
                            'cwe': vuln['cwe'],
                            'description': vuln['description'],
                            'matched_at': url,
                            'evidence': f'File accessible with status {resp.status_code}, size: {len(resp.content)} bytes',
                            'recommendation': vuln['recommendation'],
                            'references': vuln['references'],
                            'type': 'sensitive_file'
                        })
            except:
                pass
        
        return vulns
    
    def _is_soft_404(self, response) -> bool:
        """Detect soft 404 pages"""
        content = response.text.lower()
        soft_404_indicators = [
            'page not found', 'not found', '404', 'does not exist',
            'file not found', 'error 404', 'invalid page', 'cannot be found'
        ]
        # Check first 1000 chars for efficiency
        return any(indicator in content[:1000] for indicator in soft_404_indicators)
    
    def _check_xss(self, target: str, response) -> list:
        """Check for XSS vulnerabilities (REAL testing)"""
        vulns = []
        
        # Find all input points
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find URL parameters
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        # XSS payloads for testing
        xss_payloads = [
            {'payload': '<script>alert("XSS")</script>', 'pattern': '<script>alert'},
            {'payload': '"><img src=x onerror=alert(1)>', 'pattern': 'onerror=alert'},
            {'payload': "'-alert(1)-'", 'pattern': "'-alert"},
            {'payload': '<svg onload=alert(1)>', 'pattern': 'onload=alert'}
        ]
        
        # Find input fields and forms
        inputs = soup.find_all('input', type='text') + soup.find_all('input', type='search')
        search_params = ['q', 'search', 'query', 's', 'keyword', 'term', 'input', 'name']
        
        # Test URL parameters
        for param in search_params:
            for xss in xss_payloads[:2]:  # Test first 2 payloads
                try:
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url = f"{base_url}?{param}={requests.utils.quote(xss['payload'])}"
                    
                    resp = self.session.get(test_url, timeout=8)
                    
                    if xss['pattern'] in resp.text.lower():
                        vuln = VULN_DATABASE['xss_reflected'].copy()
                        vulns.append({
                            'name': vuln['name'],
                            'severity': vuln['severity'],
                            'cvss_score': vuln['cvss_score'],
                            'cvss_vector': vuln['cvss_vector'],
                            'cwe': vuln['cwe'],
                            'description': vuln['description'],
                            'matched_at': test_url[:100],
                            'parameter': param,
                            'evidence': f'XSS payload reflected in response',
                            'recommendation': vuln['recommendation'],
                            'references': vuln['references'],
                            'type': 'xss_reflected'
                        })
                        return vulns  # Found one, report it
                except:
                    pass
        
        return vulns
    
    def _check_sqli(self, target: str, response) -> list:
        """Check for SQL injection (REAL testing)"""
        vulns = []
        
        parsed = urlparse(target)
        
        sqli_payloads = [
            {"payload": "'", "errors": ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error']},
            {"payload": "' OR 1=1 -- ", "errors": ['sql', 'mysql', 'error', 'warning', 'you have an error']},
            {"payload": "1' OR '1'='1", "errors": ['sql', 'mysql', 'error']},
            {"payload": "1; SELECT * FROM--", "errors": ['sql', 'select', 'from']}
            
        ]
        
        test_params = ['id', 'user_id', 'uid', 'product_id', 'item', 'page', 'cat', 'category', 'article']
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in test_params:
            for sqli in sqli_payloads[:1]:  # One payload per param
                try:
                    test_url = f"{base_url}?{param}={requests.utils.quote(sqli['payload'])}"
                    resp = self.session.get(test_url, timeout=10)
                    resp_lower = resp.text.lower()
                    
                    for error in sqli['errors']:
                        if error in resp_lower:
                            vuln = VULN_DATABASE['sql_injection'].copy()
                            vulns.append({
                                'name': vuln['name'],
                                'severity': vuln['severity'],
                                'cvss_score': vuln['cvss_score'],
                                'cvss_vector': vuln['cvss_vector'],
                                'cwe': vuln['cwe'],
                                'description': vuln['description'],
                                'matched_at': test_url[:100],
                                'parameter': param,
                                'evidence': f'SQL error pattern "{error}" found in response',
                                'recommendation': vuln['recommendation'],
                                'references': vuln['references'],
                                'type': 'sql_injection'
                            })
                            return vulns  # Critical - stop searching
                except:
                    pass
        
        return vulns
    
    def _check_lfi(self, target: str) -> list:
        """Check for Local File Inclusion (REAL testing)"""
        vulns = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        lfi_payloads = [
            {'payload': '../../../../etc/passwd', 'pattern': 'root:'},
            {'payload': '....//....//....//etc/passwd', 'pattern': 'root:'},
            {'payload': '/etc/passwd', 'pattern': 'root:'},
            {'payload': '..\\..\\..\\..\\windows\\system.ini', 'pattern': '[drivers]'}
        ]
        
        lfi_params = ['file', 'page', 'include', 'path', 'doc', 'template', 'view']
        
        for param in lfi_params:
            for lfi in lfi_payloads[:2]:
                try:
                    test_url = f"{base_url}?{param}={requests.utils.quote(lfi['payload'])}"
                    resp = self.session.get(test_url, timeout=8)
                    
                    if lfi['pattern'] in resp.text.lower():
                        vuln = VULN_DATABASE['lfi'].copy()
                        vulns.append({
                            'name': vuln['name'],
                            'severity': vuln['severity'],
                            'cvss_score': vuln['cvss_score'],
                            'cvss_vector': vuln['cvss_vector'],
                            'cwe': vuln['cwe'],
                            'description': vuln['description'],
                            'matched_at': test_url[:100],
                            'parameter': param,
                            'evidence': f'LFI payload triggered file content disclosure',
                            'recommendation': vuln['recommendation'],
                            'references': vuln['references'],
                            'type': 'lfi'
                        })
                        return vulns
                except:
                    pass
        
        return vulns
    
    def _check_open_redirect(self, target: str) -> list:
        """Check for Open Redirect vulnerabilities (REAL)"""
        vulns = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'link', 'target', 'rurl', 'dest']
        evil_url = 'https://evil-site.com'
        
        for param in redirect_params:
            try:
                test_url = f"{base_url}?{param}={requests.utils.quote(evil_url)}"
                resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                
                location = resp.headers.get('Location', '')
                if 'evil-site.com' in location:
                    vuln = VULN_DATABASE['open_redirect'].copy()
                    vulns.append({
                        'name': vuln['name'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln['cvss_score'],
                        'cvss_vector': vuln['cvss_vector'],
                        'cwe': vuln['cwe'],
                        'description': vuln['description'],
                        'matched_at': test_url[:100],
                        'parameter': param,
                        'evidence': f'Redirect to external URL accepted: {location[:50]}',
                        'recommendation': vuln['recommendation'],
                        'references': vuln['references'],
                        'type': 'open_redirect'
                    })
                    return vulns
            except:
                pass
        
        return vulns
    
    def _check_ssl(self, target: str) -> list:
        """Check SSL/TLS configuration (REAL)"""
        vulns = []
        parsed = urlparse(target)
        
        if parsed.scheme != 'https':
            vulns.append({
                'name': 'No HTTPS Encryption',
                'severity': 'high',
                'cvss_score': 7.4,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'cwe': 'CWE-319',
                'description': 'Site uses unencrypted HTTP - traffic can be intercepted',
                'matched_at': target,
                'evidence': 'Protocol is HTTP instead of HTTPS',
                'recommendation': [
                    'Enable HTTPS with valid SSL certificate',
                    'Redirect all HTTP to HTTPS',
                    'Enable HSTS header'
                ],
                'references': ['https://owasp.org/www-project-web-security-testing-guide/'],
                'type': 'no_https'
            })
        else:
            # Check certificate
            try:
                hostname = parsed.netloc.split(':')[0]
                port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # Certificate is valid if we got here
            except ssl.CertificateError as e:
                vulns.append({
                    'name': 'Invalid SSL Certificate',
                    'severity': 'high',
                    'cvss_score': 7.4,
                    'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
                    'cwe': 'CWE-295',
                    'description': 'SSL certificate validation failed',
                    'matched_at': target,
                    'evidence': str(e)[:100],
                    'recommendation': [
                        'Install valid SSL certificate from trusted CA',
                        'Ensure certificate is not expired',
                        'Verify certificate chain is complete'
                    ],
                    'references': ['https://owasp.org/www-project-web-security-testing-guide/'],
                    'type': 'invalid_ssl'
                })
            except Exception:
                pass
        
        return vulns
    
    def _check_shodan_vulns(self, target: str) -> list:
        """Check Shodan for known vulnerabilities"""
        vulns = []
        
        try:
            parsed = urlparse(target)
            hostname = parsed.netloc.split(':')[0]
            ip = socket.gethostbyname(hostname)
            
            url = f"{SHODAN_API_URL}/shodan/host/{ip}?key={SHODAN_API_KEY}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for CVEs
                if 'vulns' in data:
                    for cve in list(data['vulns'])[:5]:  # Max 5 CVEs
                        vulns.append({
                            'name': f'Known Vulnerability: {cve}',
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                            'cwe': 'CWE-1035',
                            'description': f'Shodan detected known vulnerability {cve} on this host',
                            'matched_at': target,
                            'evidence': f'CVE identified via Shodan: {cve}',
                            'recommendation': [
                                'Apply security patches immediately',
                                'Check vendor advisories for updates',
                                'Implement workarounds if patches unavailable'
                            ],
                            'references': [f'https://nvd.nist.gov/vuln/detail/{cve}'],
                            'type': 'known_cve',
                            'cve': cve
                        })
                        
        except Exception as e:
            print(f"    Shodan check error: {e}")
        
        return vulns


def scan(target: str) -> dict:
    """Module-level scan function"""
    scanner = RealVulnerabilityScanner()
    return scanner.scan(target)
