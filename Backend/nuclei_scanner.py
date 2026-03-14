import subprocess
import os
import json
import re
from urllib.parse import urlparse

def get_vulnerability_details(template_name):
    """Map template name to type, description, and recommendation."""
    template_lower = template_name.lower()
    
    if "xss" in template_lower:
        vuln_type = "XSS"
        description = "Reflected XSS detected"
        recommendation = "Input validation & output encoding\nUse Secure Framework Features\nContent Security Policy (CSP)\nSecure Cookies"
    elif "sql" in template_lower:
        vuln_type = "SQL Injection"
        description = "SQL Injection vulnerability detected"
        recommendation = "Use Parameterized Queries\nInput Validation\nLeast Privilege Database Access\nError Handling\nWeb Application Firewall (WAF)"
    elif "csrf" in template_lower:
        vuln_type = "CSRF"
        description = "CSRF vulnerability detected"
        recommendation = "Implement CSRF Tokens\nVerify HTTP Methods\nProtect Session Cookies\nRe-authentication for Critical Actions"
    else:
        vuln_type = "Other"
        description = f"Vulnerability detected via {template_name}"
        recommendation = "Review the specific finding and apply appropriate security controls."
        
    return vuln_type, description, recommendation

def scan(target):
    """
    Run Nuclei scan against the target and parse the results.
    """
    results = []
    
    # Ensure target is properly formatted
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    # Basic validation to prevent obvious command injection
    parsed_url = urlparse(target)
    if not parsed_url.netloc:
        return {'error': 'Invalid target URL'}

    # Use the absolute path or relative path from the project root
    # Since app is run from the project root, ./Nuclei should work
    # We will use the json output mode of nuclei to parse it robustly
    cmd = [
        "nuclei",
        "-u", target,
        "-t", "./Nuclei/",
        "-silent", # Only show findings
        "-jsonl"   # Output JSONL to stdout in Nuclei v3.6.0+
    ]

    try:
        # Avoid shell=True for security
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=300  # 5 minutes timeout
        )
        
        # Read the stdout json lines
        if process.stdout:
            for line in process.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    template_id = data.get('template-id', 'unknown')
                    url = data.get('matched-at', target)
                    method = data.get('type', 'GET').upper() # Usually GET if not specified in http type
                    severity = data.get('info', {}).get('severity', 'info').title()
                    
                    vuln_type, desc, rec = get_vulnerability_details(template_id)
                    
                    results.append({
                        "template": template_id,
                        "url": url,
                        "method": method,
                        "severity": severity,
                        "type": vuln_type,
                        "description": desc,
                        "recommendation": rec
                    })
                except json.JSONDecodeError:
                    pass
        
        return {
            'findings': results,
            'count': len(results)
        }

    except subprocess.TimeoutExpired:
        return {'error': 'Nuclei scan timed out after 5 minutes'}
    except FileNotFoundError:
        return {'error': 'Nuclei executable not found. Please ensure it is installed and in the system PATH.'}
    except Exception as e:
        return {'error': f'An unexpected error occurred: {str(e)}'}
