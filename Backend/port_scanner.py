"""
WebVulnX - Nmap Port Scanner Integration
Performs port scanning using local Nmap installation via subprocess
"""

import subprocess
import re
import socket
import time
import sys
from typing import List, Dict, Any
from urllib.parse import urlparse

class RealPortScanner:
    """Port scanner using local Nmap"""
    
    def __init__(self):
        pass
    
    def scan(self, target: str, scan_type: str = 'quick') -> Dict[str, Any]:
        """
        Main scan method - executes Nmap commands
        
        Args:
            target: IP address, hostname, or URL to scan
            scan_type: 'quick' or 'full'
        
        Returns:
            Dictionary with scan results
        """
        # Extract hostname from URL if needed
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.hostname or target
            
        print(f"[*] Starting Nmap scan for target: {target}")
        
        results = {
            'target': target,
            'ip': None,
            'ip_address': None,
            'scanner': 'nmap',
            'scan_type': scan_type,
            'ports': [],
            'os_detection': 'Unknown',
            'organization': 'Unknown',
            'isp': 'Unknown',
            'country': 'Unknown',
            'city': 'Unknown',
            'hostnames': [],
            'vulnerabilities': [],
            'scan_time': 0,
            'command': '',
            'raw_output': ''
        }
        
        start_time = time.time()
        
        try:
            # Resolve IP first to ensure connectivity and for reporting
            try:
                ip = socket.gethostbyname(target)
                results['ip'] = ip
                results['ip_address'] = ip
                print(f"[+] Resolved IP: {ip}")
            except socket.gaierror:
                print(f"[-] Could not resolve hostname: {target}")
                # We let Nmap try to resolve it as well, or fail
            
            # precise command construction based on requirements
            if scan_type == 'quick':
                # Quick Scan: nmap -Pn <target>
                cmd = ['nmap', '-Pn', target]
            elif scan_type == 'full':
                # Full Scan: nmap -Pn -p- -sCV <target>
                cmd = ['nmap', '-Pn', '-p-', target]
            else:
                # Default fallback
                cmd = ['nmap', '-Pn', target]
                
            results['command'] = ' '.join(cmd)
            print(f"[*] Executing: {results['command']}")
            
            # Execute Nmap
            # Using shell=True only if necessary, but list is safer and standard. 
            # However, ensure 'nmap' is in PATH.
            if sys.platform == 'win32':
                # On Windows, sometimes subprocess needs shell=True for PATH resolution 
                # if not fully configured, but let's try direct first.
                process = subprocess.run(cmd, capture_output=True, text=True, check=False)
            else:
                process = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if process.returncode != 0 and not process.stdout:
                # If command failed completely
                error_msg = process.stderr.strip() or "Nmap execution failed"
                print(f"[-] Nmap error: {error_msg}")
                results['error'] = error_msg
                if "not recognized" in error_msg or "No such file" in error_msg:
                     results['error'] = "Nmap is not installed or not in PATH."
                return results

            # Parse Output
            output = process.stdout
            results['raw_output'] = output
            
            parsed_results = self._parse_nmap_output(output)
            results.update(parsed_results)
            
            if not results['ip'] and parsed_results.get('ip'):
                 results['ip'] = parsed_results.get('ip')
                 results['ip_address'] = results['ip']

        except FileNotFoundError:
             results['error'] = "Nmap is not installed or not in system PATH."
        except Exception as e:
            print(f"[-] Scan error: {e}")
            results['error'] = str(e)
        
        results['scan_time'] = round(time.time() - start_time, 2)
        results['open_ports'] = len(results['ports'])
        
        # Sort ports
        results['ports'].sort(key=lambda x: x['port'])
        
        print(f"[+] Scan complete: {results['open_ports']} ports found")
        
        return results

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap text output"""
        parsed = {
            'ports': [],
            'os_detection': 'Unknown',
            'ip': None
        }
        
        lines = output.splitlines()
        current_port = None
        
        port_regex = re.compile(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$')
        ip_regex = re.compile(r'Nmap scan report for .*?\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?')
        os_regex = re.compile(r'^(?:Running|OS details|Device type):\s*(.+)')
        service_info_regex = re.compile(r'Service Info:\s*(.+)')
        
        for line in lines:
            line = line.strip()
            
            # Match IP
            ip_match = ip_regex.search(line)
            if ip_match:
                parsed['ip'] = ip_match.group(1)
                continue
                
            # Match OS
            os_match = os_regex.search(line)
            if os_match:
                parsed['os_detection'] = os_match.group(1)
                continue

            # Match Port Line: 80/tcp open http Apache httpd 2.4.41
            # Note: nmap output columns can vary slightly, but usually: PORT STATE SERVICE VERSION
            # Regex handles basic structure
            port_match = port_regex.match(line)
            if port_match:
                port_num = int(port_match.group(1))
                proto = port_match.group(2)
                state = port_match.group(3)
                rest = port_match.group(4).strip()
                
                # Split service and version
                # Usually "http Apache httpd..." -> Service: http, Version: Apache httpd...
                # But sometimes just "http" or "domain"
                if ' ' in rest:
                    service, version = rest.split(' ', 1)
                else:
                    service = rest
                    version = ''
                
                # Risk assessment (basic)
                risk = self._assess_risk(port_num, service)
                
                port_info = {
                    'port': port_num,
                    'protocol': proto,
                    'state': state,
                    'service': service,
                    'version': version,
                    'banner': version, # Use version as banner for now
                    'risk': risk,
                    'source': 'nmap'
                }
                parsed['ports'].append(port_info)
        
        return parsed

    def _assess_risk(self, port: int, service: str) -> str:
        """Basic risk assessment"""
        high_risk_ports = {21, 23, 445, 1433, 3389}
        medium_risk_ports = {22, 25, 8080}
        
        if port in high_risk_ports:
            return 'high'
        if port in medium_risk_ports:
            return 'medium'
        if 'telnet' in service.lower() or 'ftp' in service.lower():
            return 'high'
            
        return 'low'

def scan(target: str, scan_type: str = 'quick') -> Dict[str, Any]:
    """Module-level scan function"""
    scanner = RealPortScanner()
    return scanner.scan(target, scan_type)
