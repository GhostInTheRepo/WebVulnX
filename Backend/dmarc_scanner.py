import subprocess
import re
from urllib.parse import urlparse

def validate_domain(domain):
    """
    Validate and extract just the domain name.
    """
    domain = domain.strip().lower()
    
    # Strip protocols if user pasted a URL
    if domain.startswith(('http://', 'https://')):
        try:
            domain = urlparse(domain).netloc
        except Exception:
            pass
            
    # Remove any trailing paths or ports
    domain = domain.split('/')[0].split(':')[0]
    
    # Basic regex for a valid domain structure
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    if not domain_regex.match(domain):
        return None
        
    return domain


def determine_protection_level(policy):
    """Map DMARC policy to Protection Level."""
    if policy == "reject":
        return "Strong"
    elif policy == "quarantine":
        return "Moderate"
    else:
        # None or missing
        return "Weak"


def parse_dmarc_record(record):
    """
    Parse the exact DMARC line returned by dig to extract policy and reports.
    """
    if not record.startswith("v=DMARC1"):
        return {
            'record_found': False,
            'policy': 'none',
            'protection_level': 'Weak'
        }
        
    # Extract policy
    policy_match = re.search(r'p\s*=\s*(none|quarantine|reject)', record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else "none"
    
    # Extract rua
    rua_match = re.search(r'rua\s*=\s*([^;\s]+)', record, re.IGNORECASE)
    rua = rua_match.group(1) if rua_match else None
    
    return {
        'record_found': True,
        'raw_record': record,
        'policy': policy,
        'reports': rua,
        'protection_level': determine_protection_level(policy)
    }


def scan(target):
    """
    Run a dig command to check for DMARC records on the target domain.
    """
    domain = validate_domain(target)
    
    if not domain:
        return {'error': 'Invalid domain format provided for DMARC scan.'}

    # Construct secure subprocess command
    # dig _dmarc.<entered_domain> TXT +short
    cmd = [
        "dig",
        f"_dmarc.{domain}",
        "TXT",
        "+short"
    ]

    try:
        # Prevent shell=True for security against injection
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15  # 15 seconds max for DNS lookup
        )
        
        # If dig returns nothing or error
        if not process.stdout or process.returncode != 0:
             return {
                'domain': domain,
                'record_found': False,
                'policy': 'none',
                'protection_level': 'Weak'
            }
            
        # Parse the output
        records = process.stdout.strip().split('\n')
        
        # Look for the DMARC record among potential multiple TXT records returned
        dmarc_data = None
        for rec in records:
            # Dig typically quotes TXT records
            cleaned = rec.strip('"\'')
            if cleaned.startswith("v=DMARC1"):
                dmarc_data = parse_dmarc_record(cleaned)
                break
                
        if not dmarc_data:
            return {
                'domain': domain,
                'record_found': False,
                'policy': 'none',
                'protection_level': 'Weak'
            }
            
        dmarc_data['domain'] = domain
        return dmarc_data

    except subprocess.TimeoutExpired:
        return {'error': 'DMARC scan timed out.'}
    except FileNotFoundError:
        return {'error': 'The "dig" command is not installed or not found in system PATH.'}
    except Exception as e:
        return {'error': f'An unexpected error occurred during DMARC scan: {str(e)}'}
