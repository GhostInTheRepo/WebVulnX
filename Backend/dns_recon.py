"""
DNS Reconnaissance Scanner
Performs DNS enumeration using DNS-over-HTTPS (DoH) and external APIs
"""

import requests
import json
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any

class DNSScanner:
    """DNS Reconnaissance Scanner Component"""
    
    # API Key provided by user
    API_KEY = "f996a7f214d73f8ee1d6683f1a06df4aa2804c2222233c7811e06d35852450aa"
    
    # Record types to query
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform DNS reconnaissance
        
        Args:
            target: Domain or URL to scan
            
        Returns:
            Dictionary containing DNS records and network info
        """
        import time
        start_time = time.time()
        
        # Clean target to get domain
        domain = self._get_domain(target)
        
        results = {
            'target': domain,
            'records': {},
            'geolocation': {},
            'scan_time': 0,
            'scan_date': '',
            'api_used': False
        }
        
        try:
            # 1. Fetch records using Google DoH
            # A Records - Enumerate Subdomains
            a_records = []
            
            # Root domain
            root_recs = self._query_doh(domain, 'A')
            if root_recs:
                a_records.extend(root_recs)
                
            # Subdomains enumeration
            subdomains = ['www', 'api', 'ai', 'mail', 'dev', 'test', 'stage', 'cpanel', 'webmail', 'ftp', 'ns1', 'ns2']
            for sub in subdomains:
                try:
                    full_domain = f"{sub}.{domain}"
                    recs = self._query_doh(full_domain, 'A')
                    if recs:
                        a_records.extend(recs)
                except:
                    continue
            
            if a_records:
                results['records']['A'] = a_records

            # Other Record Types
            for record_type in ['AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                records = self._query_doh(domain, record_type)
                if records:
                    results['records'][record_type] = records
            
            # 2. Try to use the API Key if applicable (Placeholder for expansion)
            # Currently relying on DoH for standard records as it's robust and free
            
            # 3. Get Geolocation for A records
            if 'A' in results['records']:
                for record in results['records']['A']:
                    ip = record.get('data')
                    if ip:
                        geo = self._get_ip_info(ip)
                        if geo:
                            results['geolocation'][ip] = geo

        except Exception as e:
            results['error'] = str(e)
            
        from datetime import datetime
        results['scan_date'] = datetime.now().isoformat()
        results['scan_time'] = round(time.time() - start_time, 2)
        results['total_records'] = sum(len(r) for r in results['records'].values())
        
        return results

    def _get_domain(self, target: str) -> str:
        """Extract domain from URL"""
        target = target.strip()
        if not target:
            return ""
            
        # Add scheme if missing to help parsing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            
        try:
            parsed = urlparse(target)
            return parsed.netloc or parsed.path
        except:
            return target

    def _query_doh(self, domain: str, record_type: str) -> List[Dict]:
        """Query Google DNS-over-HTTPS"""
        url = "https://dns.google/resolve"
        params = {
            'name': domain,
            'type': record_type
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'Answer' in data:
                    return [{
                        'name': item['name'],
                        'type': record_type,
                        'ttl': item['TTL'],
                        'data': item['data']
                    } for item in data['Answer']]
        except Exception as e:
            print(f"DoH Query Error ({record_type}): {e}")
            pass
            
        return []

    def _get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get IP Geolocation info"""
        try:
            # Using ip-api.com (free, no key required for basic usage)
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}

# Module level scan function
def scan(target: str) -> Dict[str, Any]:
    scanner = DNSScanner()
    return scanner.scan(target)
