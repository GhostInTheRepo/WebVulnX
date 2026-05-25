"""
Technology Detection Scanner
Identifies technologies, frameworks, and services used by a website
"""

import requests
import re
import json
from urllib.parse import urlparse
from typing import List, Dict, Any
import subprocess


class TechDetector:
    """Technology stack detection scanner"""
    
    # Technology signatures database
    SIGNATURES = {
        # Web Servers
        'Apache': {
            'headers': {'Server': r'Apache'},
            'category': 'Web Server',
            'icon': '🌐'
        },
        'Nginx': {
            'headers': {'Server': r'nginx'},
            'category': 'Web Server',
            'icon': '🌐'
        },
        'Microsoft-IIS': {
            'headers': {'Server': r'Microsoft-IIS'},
            'category': 'Web Server',
            'icon': '🌐'
        },
        'LiteSpeed': {
            'headers': {'Server': r'LiteSpeed'},
            'category': 'Web Server',
            'icon': '🌐'
        },
        'Cloudflare': {
            'headers': {'Server': r'cloudflare', 'CF-RAY': r'.+'},
            'category': 'CDN',
            'icon': '☁️'
        },
        
        # Programming Languages
        'PHP': {
            'headers': {'X-Powered-By': r'PHP'},
            'cookies': {'PHPSESSID': True},
            'body': [r'\.php[\?\"]', r'<\?php'],
            'category': 'Language',
            'icon': '🐘'
        },
        'ASP.NET': {
            'headers': {'X-Powered-By': r'ASP\.NET', 'X-AspNet-Version': r'.+'},
            'cookies': {'ASP.NET_SessionId': True, 'ASPSESSIONID': True},
            'category': 'Language',
            'icon': '🔷'
        },
        'Python': {
            'headers': {'Server': r'(Python|Gunicorn|uWSGI|Waitress)'},
            'category': 'Language',
            'icon': '🐍'
        },
        'Node.js': {
            'headers': {'X-Powered-By': r'Express'},
            'category': 'Language',
            'icon': '💚'
        },
        'Java': {
            'headers': {'X-Powered-By': r'(Servlet|JSP|Java)'},
            'cookies': {'JSESSIONID': True},
            'category': 'Language',
            'icon': '☕'
        },
        'Ruby': {
            'headers': {'X-Powered-By': r'(Phusion Passenger|Ruby)', 'Server': r'(Passenger|Puma|Unicorn)'},
            'cookies': {'_session_id': True},
            'category': 'Language',
            'icon': '💎'
        },
        
        # CMS
        'WordPress': {
            'body': [r'wp-content', r'wp-includes', r'/wp-json/', r'WordPress'],
            'meta': {'generator': r'WordPress'},
            'category': 'CMS',
            'icon': '📝'
        },
        'Drupal': {
            'headers': {'X-Drupal-Cache': r'.+', 'X-Generator': r'Drupal'},
            'body': [r'Drupal\.settings', r'/sites/default/files/'],
            'meta': {'generator': r'Drupal'},
            'category': 'CMS',
            'icon': '💧'
        },
        'Joomla': {
            'body': [r'/media/jui/', r'/components/com_', r'Joomla'],
            'meta': {'generator': r'Joomla'},
            'category': 'CMS',
            'icon': '🟠'
        },
        'Shopify': {
            'body': [r'cdn\.shopify\.com', r'Shopify\.theme'],
            'headers': {'X-ShopId': r'.+'},
            'category': 'E-commerce',
            'icon': '🛒'
        },
        'Magento': {
            'body': [r'/static/version', r'Mage\.Cookies', r'/skin/frontend/'],
            'cookies': {'frontend': True, 'adminhtml': True},
            'category': 'E-commerce',
            'icon': '🛍️'
        },
        'WooCommerce': {
            'body': [r'woocommerce', r'wc-ajax'],
            'category': 'E-commerce',
            'icon': '🛒'
        },
        
        # JavaScript Frameworks
        'React': {
            'body': [r'react\.', r'_reactRootContainer', r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'data-reactroot'],
            'category': 'JS Framework',
            'icon': '⚛️'
        },
        'Vue.js': {
            'body': [r'vue\.js', r'vue\.min\.js', r'v-cloak', r'__VUE__', r'Vue\.config'],
            'category': 'JS Framework',
            'icon': '💚'
        },
        'Angular': {
            'body': [r'ng-version', r'ng-app', r'angular\.js', r'angular\.min\.js', r'\[\(ngModel\)\]'],
            'category': 'JS Framework',
            'icon': '🅰️'
        },
        'jQuery': {
            'body': [r'jquery[\-\.][\d\.]+\.js', r'jquery\.min\.js', r'\$\(document\)\.ready'],
            'category': 'JS Library',
            'icon': '📜'
        },
        'Bootstrap': {
            'body': [r'bootstrap\.css', r'bootstrap\.min\.css', r'bootstrap\.js', r'class="[^"]*\bcontainer\b'],
            'category': 'CSS Framework',
            'icon': '🅱️'
        },
        'Tailwind CSS': {
            'body': [r'tailwindcss', r'tailwind\.css', r'class="[^"]*\b(flex|grid|text-\w+|bg-\w+|p-\d|m-\d)'],
            'category': 'CSS Framework',
            'icon': '🎨'
        },
        'Next.js': {
            'body': [r'_next/static', r'__NEXT_DATA__', r'/_next/'],
            'category': 'JS Framework',
            'icon': '▲'
        },
        'Nuxt.js': {
            'body': [r'_nuxt/', r'__NUXT__', r'nuxt'],
            'category': 'JS Framework',
            'icon': '💚'
        },
        
        # Analytics & Marketing
        'Google Analytics': {
            'body': [r'google-analytics\.com', r'googletagmanager\.com', r'gtag\(', r'ga\('],
            'category': 'Analytics',
            'icon': '📊'
        },
        'Google Tag Manager': {
            'body': [r'googletagmanager\.com/gtm\.js'],
            'category': 'Analytics',
            'icon': '🏷️'
        },
        'Facebook Pixel': {
            'body': [r'connect\.facebook\.net', r'fbq\('],
            'category': 'Analytics',
            'icon': '👤'
        },
        'Hotjar': {
            'body': [r'static\.hotjar\.com', r'hotjar\.com'],
            'category': 'Analytics',
            'icon': '🔥'
        },
        
        # Security
        'reCAPTCHA': {
            'body': [r'google\.com/recaptcha', r'grecaptcha'],
            'category': 'Security',
            'icon': '🤖'
        },
        'Cloudflare Security': {
            'headers': {'CF-RAY': r'.+'},
            'body': [r'cloudflare'],
            'category': 'Security',
            'icon': '🛡️'
        },
        'Sucuri': {
            'headers': {'X-Sucuri-ID': r'.+'},
            'category': 'Security',
            'icon': '🛡️'
        },
        
        # Hosting
        'Amazon AWS': {
            'headers': {'Server': r'AmazonS3', 'X-Amz-Request-Id': r'.+'},
            'body': [r'\.amazonaws\.com', r'\.aws\.'],
            'category': 'Hosting',
            'icon': '☁️'
        },
        'Google Cloud': {
            'headers': {'Via': r'google'},
            'body': [r'\.googleapis\.com', r'storage\.cloud\.google'],
            'category': 'Hosting',
            'icon': '☁️'
        },
        'Azure': {
            'headers': {'X-Powered-By': r'Azure'},
            'body': [r'\.azure\.', r'\.windows\.net'],
            'category': 'Hosting',
            'icon': '☁️'
        },
        'Vercel': {
            'headers': {'X-Vercel-Id': r'.+', 'Server': r'Vercel'},
            'category': 'Hosting',
            'icon': '▲'
        },
        'Netlify': {
            'headers': {'X-NF-Request-ID': r'.+', 'Server': r'Netlify'},
            'category': 'Hosting',
            'icon': '🌐'
        },
        'Heroku': {
            'headers': {'Via': r'heroku'},
            'body': [r'\.herokuapp\.com'],
            'category': 'Hosting',
            'icon': '🟣'
        },
        'Ubuntu Server': {
            'headers': {
                # Apache on Ubuntu often exposes these formats
                'Server': r'(Apache|nginx)(/[\d\.]+)? \(Ubuntu\)',
                # Some Ubuntu apt-based defaults include this security header
                'X-Generator': r'Ubuntu'
            },
            'body': [
                # Often seen in default nginx/apache landing pages
                r'Ubuntu Server',
                r'Ubuntu [0-9]+\.[0-9]+ LTS', 
                # Sometimes Ubuntu-hosted apps leak paths like /usr/share/
                r'/usr/share/',
            ],
            'category': 'Operating System',
            'icon': '🐧'
        }
    }
    
    def __init__(self):
        self.whatweb_available = self._check_whatweb()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _check_whatweb(self) -> bool:
        """Check if WhatWeb is installed"""
        try:
            result = subprocess.run(['whatweb', '--version'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Main detection method
        
        Args:
            target: URL to analyze
        
        Returns:
            Dictionary with detected technologies
        """
        results = {
            'target': target,
            'scanner': 'whatweb' if self.whatweb_available else 'builtin',
            'technologies': [],
            'headers': {},
            'meta': {},
            'cookies': [],
            'scan_time': 0
        }
        
        import time
        start_time = time.time()
        
        # Get response
        try:
            response = self.session.get(target, timeout=15, verify=False, allow_redirects=True)
            
            # Store headers
            results['headers'] = dict(response.headers)
            
            # Store cookies
            results['cookies'] = [cookie.name for cookie in response.cookies]
            
            # Extract meta tags
            results['meta'] = self._extract_meta(response.text)
            
            # Detect technologies
            if self.whatweb_available:
                whatweb_results = self._run_whatweb(target)
                results['technologies'].extend(whatweb_results)
            
            # Run WhatCMS API detection
            whatcms_results = self._run_whatcms_detection(target)
            results['technologies'].extend(whatcms_results)
            
            # Always run builtin detection for comprehensive results
            builtin_results = self._run_builtin_detection(response)
            
            # Merge results avoiding duplicates
            existing_names = {t['name'] for t in results['technologies']}
            for tech in builtin_results:
                if tech['name'] not in existing_names:
                    results['technologies'].append(tech)
            
            # Additional checks
            results['ssl'] = self._check_ssl(target)
            results['ip_address'] = self._get_ip(target)
            
        except Exception as e:
            results['error'] = str(e)
        
        results['scan_time'] = round(time.time() - start_time, 2)
        results['tech_count'] = len(results['technologies'])
        
        # Group by category
        results['by_category'] = self._group_by_category(results['technologies'])
        
        return results
    
    def _run_whatweb(self, target: str) -> List[Dict]:
        """Run WhatWeb scan"""
        technologies = []
        
        try:
            cmd = ['whatweb', '-q', '--log-json=-', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            for plugin_name, plugin_data in data.get('plugins', {}).items():
                                if plugin_name not in ['HTTPServer', 'IP', 'Country']:
                                    technologies.append({
                                        'name': plugin_name,
                                        'version': plugin_data.get('version', [''])[0] if plugin_data.get('version') else '',
                                        'category': self._get_category(plugin_name),
                                        'icon': self._get_icon(plugin_name),
                                        'confidence': 100
                                    })
                        except:
                            pass
        except:
            pass
        
        return technologies
    
    def _run_whatcms_detection(self, target: str) -> List[Dict]:
        """Run WhatCMS API detection"""
        technologies = []
        api_key = '###################'  """Place your own API Key of WhatCMS"""
        
        try:
            # Extract domain from target for the API
            parsed = urlparse(target)
            domain = parsed.netloc
            if not domain:
                 domain = parsed.path # Handle cases like example.com without http
            
            response = requests.get(
                f"https://whatcms.org/API/Tech?key={api_key}&url={domain}", 
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result', {}).get('code') == 200:
                    for tech in data.get('results', []):
                        technologies.append({
                            'name': tech.get('name'),
                            'version': tech.get('version', ''),
                            'category': 'CMS' if 'CMS' in tech.get('categories', []) else 'Other',
                            'icon': '🔍',
                            'confidence': 100
                        })
        except:
            pass
            
        return technologies
    
    def _run_builtin_detection(self, response) -> List[Dict]:
        """Run built-in technology detection"""
        technologies = []
        detected = set()
        
        headers = {k: v for k, v in response.headers.items()}
        cookies = {cookie.name: cookie.value for cookie in response.cookies}
        body = response.text
        
        for tech_name, signature in self.SIGNATURES.items():
            confidence = 0
            matches = []
            
            # Check headers
            if 'headers' in signature:
                for header_name, pattern in signature['headers'].items():
                    header_value = headers.get(header_name, '')
                    if re.search(pattern, header_value, re.IGNORECASE):
                        confidence += 40
                        matches.append(f'Header: {header_name}')
            
            # Check cookies
            if 'cookies' in signature:
                for cookie_name in signature['cookies']:
                    if cookie_name in cookies:
                        confidence += 30
                        matches.append(f'Cookie: {cookie_name}')
            
            # Check body
            if 'body' in signature:
                for pattern in signature['body']:
                    if re.search(pattern, body, re.IGNORECASE):
                        confidence += 20
                        matches.append('Body pattern')
                        break
            
            # Check meta tags
            if 'meta' in signature:
                meta_tags = self._extract_meta(body)
                for meta_name, pattern in signature['meta'].items():
                    meta_value = meta_tags.get(meta_name, '')
                    if re.search(pattern, meta_value, re.IGNORECASE):
                        confidence += 35
                        matches.append(f'Meta: {meta_name}')
            
            # Add if confident enough
            if confidence >= 20 and tech_name not in detected:
                detected.add(tech_name)
                technologies.append({
                    'name': tech_name,
                    'version': self._extract_version(tech_name, body, headers),
                    'category': signature.get('category', 'Other'),
                    'icon': signature.get('icon', '🔧'),
                    'confidence': min(confidence, 100),
                    'evidence': matches
                })
        
        # Sort by confidence
        technologies.sort(key=lambda x: x['confidence'], reverse=True)
        
        return technologies
    
    def _extract_meta(self, html: str) -> Dict[str, str]:
        """Extract meta tags from HTML"""
        meta = {}
        
        # Generator meta tag
        generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if generator_match:
            meta['generator'] = generator_match.group(1)
        
        # Framework meta tag
        framework_match = re.search(r'<meta[^>]+name=["\']framework["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if framework_match:
            meta['framework'] = framework_match.group(1)
        
        return meta
    
    def _extract_version(self, tech_name: str, body: str, headers: Dict) -> str:
        """Try to extract version number"""
        version_patterns = {
            'WordPress': r'WordPress\s*([\d\.]+)',
            'jQuery': r'jquery[/-]([\d\.]+)',
            'Bootstrap': r'bootstrap[/-]([\d\.]+)',
            'React': r'react@([\d\.]+)',
            'Vue.js': r'vue@([\d\.]+)',
            'Angular': r'ng-version=["\']([\d\.]+)["\']',
            'PHP': r'PHP/([\d\.]+)'
        }
        
        if tech_name in version_patterns:
            # Check body
            match = re.search(version_patterns[tech_name], body, re.IGNORECASE)
            if match:
                return match.group(1)
            
            # Check headers
            for header_value in headers.values():
                match = re.search(version_patterns[tech_name], str(header_value), re.IGNORECASE)
                if match:
                    return match.group(1)
        
        # Check X-Powered-By for PHP version
        if tech_name == 'PHP':
            powered_by = headers.get('X-Powered-By', '')
            match = re.search(r'PHP/([\d\.]+)', powered_by)
            if match:
                return match.group(1)
        
        return ''
    
    def _get_category(self, tech_name: str) -> str:
        """Get category for a technology"""
        if tech_name in self.SIGNATURES:
            return self.SIGNATURES[tech_name].get('category', 'Other')
        return 'Other'
    
    def _get_icon(self, tech_name: str) -> str:
        """Get icon for a technology"""
        if tech_name in self.SIGNATURES:
            return self.SIGNATURES[tech_name].get('icon', '🔧')
        return '🔧'
    
    def _check_ssl(self, target: str) -> Dict[str, Any]:
        """Check SSL certificate information"""
        ssl_info = {
            'enabled': target.startswith('https'),
            'valid': False,
            'issuer': '',
            'expires': ''
        }
        
        if ssl_info['enabled']:
            try:
                import ssl
                import socket
                from datetime import datetime
                
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        ssl_info['valid'] = True
                        ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        ssl_info['expires'] = cert.get('notAfter', '')
            except:
                pass
        
        return ssl_info
    
    def _get_ip(self, target: str) -> str:
        """Get IP address of target"""
        try:
            import socket
            parsed = urlparse(target)
            hostname = parsed.hostname
            return socket.gethostbyname(hostname)
        except:
            return ''
    
    def _group_by_category(self, technologies: List[Dict]) -> Dict[str, List[Dict]]:
        """Group technologies by category"""
        groups = {}
        for tech in technologies:
            category = tech.get('category', 'Other')
            if category not in groups:
                groups[category] = []
            groups[category].append(tech)
        return groups


def scan(target: str) -> Dict[str, Any]:
    """Module-level scan function"""
    detector = TechDetector()
    return detector.scan(target)
