"""
WebVulnX - Real Port Scanner with Shodan Integration
Performs real port scanning using Shodan API and socket scanning
"""

import subprocess
import socket
import json
import requests
import concurrent.futures
import time
from typing import List, Dict, Any
from urllib.parse import urlparse


# Shodan API Configuration
SHODAN_API_KEY = "So5OBkIagDQGLJTvzkO0G3L9ykotMsOp"
SHODAN_API_URL = "https://api.shodan.io"


class RealPortScanner:
    """Real port scanner using Shodan API and socket scanning"""
    
    # Common ports and their services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'MSRPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    # Risky services
    HIGH_RISK_SERVICES = ['telnet', 'ftp', 'smb', 'rdp', 'vnc', 'mysql', 'mongodb', 'redis', 'mssql']
    
    def __init__(self):
        self.shodan_api_key = SHODAN_API_KEY
        self.session = requests.Session()
        self.session.timeout = 15
    
    def scan(self, target: str, scan_type: str = 'common') -> Dict[str, Any]:
        """
        Main scan method - uses Shodan for real data
        
        Args:
            target: IP address, hostname, or URL to scan
            scan_type: 'quick', 'common', or 'full'
        
        Returns:
            Dictionary with real scan results
        """
        # Extract hostname from URL
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.hostname
        
        print(f"[*] Port scanning target: {target}")
        
        results = {
            'target': target,
            'ip': None,
            'ip_address': None,
            'scanner': 'shodan+socket',
            'scan_type': scan_type,
            'ports': [],
            'os_detection': None,
            'organization': None,
            'isp': None,
            'country': None,
            'city': None,
            'hostnames': [],
            'vulnerabilities': [],
            'scan_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            results['ip'] = ip
            results['ip_address'] = ip
            print(f"[+] Resolved IP: {ip}")
            
            # Try Shodan API first for comprehensive data
            print("[*] Querying Shodan API...")
            shodan_data = self._query_shodan(ip)
            
            if shodan_data:
                results = self._parse_shodan_data(shodan_data, results)
                print(f"[+] Shodan found {len(results['ports'])} open ports")
            
            # Supplement with socket scanning for real-time verification
            print("[*] Performing live socket scan...")
            socket_ports = self._run_socket_scan(ip, scan_type)
            
            # Merge results (Shodan + Socket)
            results['ports'] = self._merge_port_data(results['ports'], socket_ports)
            
        except socket.gaierror as e:
            print(f"[-] DNS resolution failed: {e}")
            results['error'] = f"Could not resolve hostname: {target}"
        except Exception as e:
            print(f"[-] Scan error: {e}")
            results['error'] = str(e)
        
        results['scan_time'] = round(time.time() - start_time, 2)
        results['open_ports'] = len([p for p in results['ports'] if p['state'] == 'open'])
        
        # Sort ports by number
        results['ports'].sort(key=lambda x: x['port'])
        
        print(f"[+] Scan complete: {results['open_ports']} open ports found")
        
        return results
    
    def _query_shodan(self, ip: str) -> Dict[str, Any]:
        """Query Shodan API for host information"""
        try:
            url = f"{SHODAN_API_URL}/shodan/host/{ip}?key={self.shodan_api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print("[-] Host not found in Shodan database")
                return None
            else:
                print(f"[-] Shodan API error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] Shodan query failed: {e}")
            return None
    
    def _parse_shodan_data(self, data: Dict, results: Dict) -> Dict:
        """Parse Shodan API response into our format"""
        # Host information
        results['ip'] = data.get('ip_str', results['ip'])
        results['ip_address'] = results['ip']
        results['organization'] = data.get('org', 'Unknown')
        results['isp'] = data.get('isp', 'Unknown')
        results['country'] = data.get('country_name', 'Unknown')
        results['city'] = data.get('city', 'Unknown')
        results['hostnames'] = data.get('hostnames', [])
        results['os_detection'] = data.get('os', 'Unknown')
        
        # Vulnerabilities from Shodan
        if 'vulns' in data:
            for vuln_id in data.get('vulns', []):
                results['vulnerabilities'].append({
                    'id': vuln_id,
                    'source': 'shodan'
                })
        
        # Parse port/service data
        for service in data.get('data', []):
            port_info = {
                'port': service.get('port', 0),
                'protocol': service.get('transport', 'tcp'),
                'state': 'open',
                'service': self._detect_service(service),
                'version': self._extract_version(service),
                'banner': service.get('data', '')[:200] if service.get('data') else '',
                'product': service.get('product', ''),
                'cpe': service.get('cpe', []),
                'risk': self._assess_port_risk(service.get('port', 0), service.get('product', '')),
                'source': 'shodan'
            }
            
            # SSL info if available
            if 'ssl' in service:
                ssl_info = service['ssl']
                port_info['ssl'] = {
                    'cert_issuer': ssl_info.get('cert', {}).get('issuer', {}).get('CN', 'Unknown'),
                    'cert_subject': ssl_info.get('cert', {}).get('subject', {}).get('CN', 'Unknown'),
                    'cipher': ssl_info.get('cipher', {}).get('name', 'Unknown'),
                    'version': ssl_info.get('version', 'Unknown')
                }
            
            results['ports'].append(port_info)
        
        return results
    
    def _detect_service(self, service: Dict) -> str:
        """Detect service name from Shodan data"""
        if service.get('product'):
            return service['product']
        
        port = service.get('port', 0)
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]
        
        # Try to detect from data/banner
        data = service.get('data', '').lower()
        if 'ssh' in data:
            return 'SSH'
        elif 'http' in data:
            return 'HTTP'
        elif 'smtp' in data:
            return 'SMTP'
        elif 'ftp' in data:
            return 'FTP'
        
        return 'unknown'
    
    def _extract_version(self, service: Dict) -> str:
        """Extract version information from Shodan service data"""
        version = service.get('version', '')
        if version:
            return version
        
        # Try to extract from product
        product = service.get('product', '')
        if product:
            return product
        
        # Try to extract from banner
        banner = service.get('data', '')[:100]
        if banner:
            return banner.split('\n')[0][:50]
        
        return ''
    
    def _run_socket_scan(self, target: str, scan_type: str) -> List[Dict]:
        """Real-time socket-based port scanning"""
        ports = []
        
        # Determine which ports to scan
        if scan_type == 'quick':
            port_list = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080]
        elif scan_type == 'common':
            port_list = list(self.COMMON_PORTS.keys())
        else:  # full
            port_list = list(self.COMMON_PORTS.keys()) + [
                3000, 4443, 5000, 5432, 5900, 6379, 
                8000, 8008, 8081, 8443, 8888, 9000, 9090, 9200
            ]
        
        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self._check_port, target, port): port 
                for port in port_list
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = self.COMMON_PORTS.get(port, 'unknown')
                        ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': service,
                            'version': banner or '',
                            'banner': banner or '',
                            'risk': self._assess_port_risk(port, service),
                            'source': 'socket'
                        })
                except:
                    pass
        
        return ports
    
    def _check_port(self, host: str, port: int, timeout: float = 2.0) -> tuple:
        """Check if a single port is open and grab banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                banner = None
                try:
                    # Try to grab banner
                    sock.settimeout(3)
                    if port in [80, 8080, 443, 8443]:
                        sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    else:
                        sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                except:
                    pass
                sock.close()
                return True, banner
            
            sock.close()
            return False, None
        except:
            return False, None
    
    def _merge_port_data(self, shodan_ports: List[Dict], socket_ports: List[Dict]) -> List[Dict]:
        """Merge Shodan and socket scan results"""
        port_map = {}
        
        # Add Shodan ports first (more detailed)
        for port in shodan_ports:
            port_map[port['port']] = port
        
        # Add/update with socket scan results
        for port in socket_ports:
            if port['port'] not in port_map:
                port_map[port['port']] = port
            else:
                # Keep Shodan data but mark as verified
                port_map[port['port']]['verified'] = True
        
        return list(port_map.values())
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """Assess the security risk of an open port"""
        high_risk_ports = {21, 23, 135, 139, 445, 1433, 3389, 5900, 27017, 6379}
        medium_risk_ports = {22, 25, 110, 143, 3306, 5432, 8080}
        
        service_lower = str(service).lower()
        
        # Check high risk services
        if any(s in service_lower for s in self.HIGH_RISK_SERVICES):
            return 'high'
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        elif service_lower in ['unknown', '']:
            return 'medium'
        else:
            return 'low'


def scan(target: str, scan_type: str = 'common') -> Dict[str, Any]:
    """Module-level scan function"""
    scanner = RealPortScanner()
    return scanner.scan(target, scan_type)
