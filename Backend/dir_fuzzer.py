"""
Directory Fuzzer / Path Discovery
Discovers hidden directories and files on web servers
"""

import requests
import concurrent.futures
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any
import subprocess
import json


import socket

class DirectoryFuzzer:
    """Directory and file discovery scanner"""
    
    # Common wordlist for directory fuzzing
    COMMON_PATHS = [
        # Admin paths
        'admin', 'administrator', 'admin.php', 'feedback.php', 'admin.html', 'adminpanel',
        'admin_area', 'admin-console', 'admin-login', 'admin/login',
        'cpanel', 'controlpanel', 'dashboard', 'manager', 'webadmin',
        'admin/auth-2.inc', 'admin/auth-5.inc', 'admin/auth-6.inc', 'admin/auth-8.inc',
        'admin/auth-bkp.inc', 'admin/auth-old.inc', 'admin/auth-prod.inc', 'admin/auth-tmp.inc',
        'admin/auth_1.inc', 'admin/auth_dev.inc', 'admin/auth_old.inc', 'admin/auth_prod.inc', 'admin/auth_tmp.inc',
        'admin/auth_test.inc',
        
        # Login paths  
        'login', 'login.php', 'logout.php', 'login.html', 'admin.php', 'signin', 'sign-in',
        'auth', 'authenticate', 'user/login', 'users/sign_in', 'login/', 'login/.bak', 
        'login/.bkp', 'login/.old', 'login/.zip', 'login/.tar.gz', 'login/.tar', 'login/.tar.bz2',

        
        # API paths
        'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
        'swagger', 'swagger-ui', 'api-docs', 'docs', 'documentation',
        
        # Backup files
        'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test',
        'backup.sql', 'backup.zip', 'backup.tar.gz', 'database.sql',
        'db.sql', 'dump.sql', 'data.sql',
        
        # Config files
        'config', 'configuration', 'settings', 'setup', 'install',
        'config.php', 'config.yml', 'config.json', 'settings.php',
        '.env', '.env.backup', '.env.local', '.env.production',
        'web.config', 'app.config', 'setup_mysql.sh',
        
        # Source code
        '.git', '.git/config', '.git/HEAD', '.svn', '.svn/entries',
        '.hg', '.bzr', 'CVS', '.gitignore', '.htaccess', '.htpasswd', '.htaccess.bak', '.htaccess.bkp', '.htaccess.old', '.htaccess.zip', '.htaccess.tar.gz', '.htaccess.tar', '.htaccess.tar.bz2',
        '.hta', '.hta.bak', '.hta.bkp', '.hta.old', '.hta.zip', '.hta.tar.gz', '.hta.tar', '.hta.tar.bz2',
        '.htpasswd.bak', '.htpasswd.bkp', '.htpasswd.old', '.htpasswd.zip', '.htpasswd.tar.gz', '.htpasswd.tar', '.htpasswd.tar.bz2',
        
        # Common directories
        'assets', 'static', 'public', 'media', 'uploads', 'contact-us', 'files',
        'images', 'images.old', 'img', 'css', 'css.old', 'js', 'scripts', 'fonts', 'about', 'about-us', 
        'includes', 'inc', 'lib', 'libs', 'vendor', 'node_modules',
        
        # CMS specific
        'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
        'joomla', 'drupal', 'magento', 'prestashop', 'opencart',
        
        # Server info
        'server-status', 'server-info', 'phpinfo.php', 'info.php',
        'test.php', 'debug', 'console', 'status', 'health',
        'metrics', 'monitoring', '.well-known',
        
        # User data
        'users', 'members', 'accounts', 'profile', 'profiles',
        'register', 'signup', 'password', 'forgot-password',
        
        # Common files
        'robots.txt', 'users.txt', 'sitemap.xml', 'sitemap_index.xml', 'humans.txt',
        'security.txt', '.well-known/security.txt', 'crossdomain.xml',
        'favicon.ico', 'apple-touch-icon.png',
        
        # Logs
        'logs', 'log', 'debug.log', 'error.log', 'access.log',
        'error_log', 'debug_log',
        
        # Development
        'dev', 'development', 'staging', 'stage', 'uat', 'qa',
        'demo', 'beta', 'alpha', 'preview',
        
        # Shell paths
        'shell', 'cmd', 'command', 'exec', 'c99', 'r57',
        'webshell', 'backdoor', 'shell.php', 'c99.php'
    ]
    
    # File extensions to check
    EXTENSIONS = ['', '.php', '.html', '.yml', '.json', '.sql', '.htm', '.asp', '.aspx', '.jsp', '.txt', '.log', '.config',
    '.local', '.production', '.bak', '.bkp', '.xml', '.ico', '.png',  '.old', '.zip', '.tar.gz', '.tar', '.tar.bz2', '.gz',]
    
    def __init__(self):
        self.ffuf_available = self._check_ffuf()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _check_ffuf(self) -> bool:
        """Check if ffuf is installed"""
        try:
            result = subprocess.run(['ffuf', '-V'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def scan(self, target: str, wordlist: str = 'common', extensions: List[str] = None) -> Dict[str, Any]:
        """
        Main fuzzing method
        
        Args:
            target: Base URL to fuzz
            wordlist: 'common', 'extended', or path to custom wordlist
            extensions: List of extensions to append
        
        Returns:
            Dictionary with discovered paths
        """
        # Ensure target ends without slash
        target = target.rstrip('/')
        
        results = {
            'target': target,
            'scanner': 'ffuf' if self.ffuf_available else 'builtin',
            'discovered': [],
            'scan_time': 0,
            'requests_made': 0,
            'ip_address': ''
        }
        
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            results['ip_address'] = socket.gethostbyname(hostname)
        except:
            pass
        
        start_time = time.time()
        
        # Get base response for comparison
        try:
            base_response = self.session.get(target, timeout=10, verify=False)
            base_length = len(base_response.content)
        except:
            base_length = 0
        
        # Build path list
        paths = self.COMMON_PATHS.copy()
        if extensions:
            extended_paths = []
            for path in paths:
                for ext in extensions:
                    extended_paths.append(f"{path}{ext}")
            paths.extend(extended_paths)
        
        # Run scan
        if self.ffuf_available and wordlist != 'common':
            results['discovered'] = self._run_ffuf_scan(target, wordlist)
        else:
            results['discovered'] = self._run_builtin_scan(target, paths, base_length)
        
        results['scan_time'] = round(time.time() - start_time, 2)
        results['requests_made'] = len(paths)
        results['found_count'] = len(results['discovered'])
        
        # Categorize findings
        results['categories'] = self._categorize_findings(results['discovered'])
        
        return results
    
    def _run_ffuf_scan(self, target: str, wordlist: str) -> List[Dict]:
        """Run ffuf scan"""
        discovered = []
        
        try:
            cmd = [
                'ffuf',
                '-u', f"{target}/FUZZ",
                '-w', wordlist,
                '-mc', '200,201,204,301,302,307,401,403,405,500',
                '-o', '-',
                '-of', 'json',
                '-s'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                data = json.loads(result.stdout)
                for item in data.get('results', []):
                    discovered.append({
                        'path': item.get('input', {}).get('FUZZ', ''),
                        'url': item.get('url', ''),
                        'status': item.get('status', 0),
                        'length': item.get('length', 0),
                        'words': item.get('words', 0),
                        'lines': item.get('lines', 0),
                        'type': self._classify_path(item.get('input', {}).get('FUZZ', ''))
                    })
        except Exception as e:
            pass
        
        return discovered
    
    def _run_builtin_scan(self, target: str, paths: List[str], base_length: int) -> List[Dict]:
        """Run built-in directory scan"""
        discovered = []
        
        def check_path(path: str):
            url = f"{target}/{path}"
            try:
                response = self.session.get(
                    url, 
                    timeout=5, 
                    verify=False,
                    allow_redirects=False
                )
                
                # Interesting status codes
                if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]:
                    content_length = len(response.content)
                    
                    # Skip if same as base (likely custom 404)
                    if response.status_code == 200 and abs(content_length - base_length) < 50:
                        return None
                    
                    return {
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'length': content_length,
                        'type': self._classify_path(path),
                        'redirect': response.headers.get('Location', '') if response.status_code in [301, 302, 307] else ''
                    }
            except:
                pass
            return None
        
        # Use thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_path, path): path for path in paths}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        # Sort by status code and path
        discovered.sort(key=lambda x: (x['status'], x['path']))
        
        return discovered
    
    def _classify_path(self, path: str) -> str:
        """Classify the type of discovered path"""
        path_lower = path.lower()
        
        if any(x in path_lower for x in ['admin', 'cpanel', 'manager', 'dashboard']):
            return 'admin'
        elif any(x in path_lower for x in ['login', 'signin', 'auth']):
            return 'auth'
        elif any(x in path_lower for x in ['api', 'rest', 'graphql', 'swagger']):
            return 'api'
        elif any(x in path_lower for x in ['.git', '.svn', '.env', 'config']):
            return 'sensitive'
        elif any(x in path_lower for x in ['backup', '.bak', '.old', '.zip', '.sql']):
            return 'backup'
        elif any(x in path_lower for x in ['phpinfo', 'server-status', 'debug']):
            return 'info'
        elif any(x in path_lower for x in ['upload', 'file', 'media']):
            return 'upload'
        else:
            return 'other'
    
    def _categorize_findings(self, discovered: List[Dict]) -> Dict[str, int]:
        """Categorize all findings"""
        categories = {}
        for item in discovered:
            item_type = item.get('type', 'other')
            categories[item_type] = categories.get(item_type, 0) + 1
        return categories


def scan(target: str, wordlist: str = 'common') -> Dict[str, Any]:
    """Module-level scan function"""
    fuzzer = DirectoryFuzzer()
    return fuzzer.scan(target, wordlist)
