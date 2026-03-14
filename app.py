"""
WebVulnX - Security Scanner Application
Flask Backend API
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
from datetime import datetime
from io import BytesIO

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Backend import scanner, port_scanner, dir_fuzzer, tech_detector, dns_recon, nuclei_scanner, dmarc_scanner
from utils import pdf_generator

app = Flask(__name__, template_folder='Frontend', static_folder='Style')
CORS(app)

# Store scan results in memory (for demo purposes)
scan_results_store = {}


@app.route('/')
def index():
    """Serve the main application page"""
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


@app.route('/api/vuln-scan', methods=['POST'])
def vulnerability_scan():
    """
    Run vulnerability scan using Nuclei or fallback methods
    
    Expected JSON body:
    {
        "target": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Run scan
        results = scanner.scan(target)
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results_store[f'vuln_{scan_id}'] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/nuclei-scan', methods=['POST'])
def nuclei_scan():
    """
    Run Nuclei scan
    
    Expected JSON body:
    {
        "target": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Run scan using the newly created module
        results = nuclei_scanner.scan(target)
        
        # Store results
        if 'error' not in results:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            scan_results_store[f'nuclei_{scan_id}'] = results
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'results': results
            })
        else:
            return jsonify({
                'success': False,
                'error': results['error']
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/port-scan', methods=['POST'])
def port_scan():
    """
    Run port scan using Nmap or fallback socket scanning
    
    Expected JSON body:
    {
        "target": "example.com",
        "scan_type": "common"  // quick, common, or full
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'common')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Run scan
        results = port_scanner.scan(target, scan_type)
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results_store[f'port_{scan_id}'] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dir-fuzz', methods=['POST'])
def directory_fuzz():
    """
    Run directory fuzzing/discovery
    
    Expected JSON body:
    {
        "target": "https://example.com",
        "wordlist": "common"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        wordlist = data.get('wordlist', 'common')
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Run scan
        results = dir_fuzzer.scan(target, wordlist)
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results_store[f'dir_{scan_id}'] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tech-detect', methods=['POST'])
def technology_detect():
    """
    Run technology detection
    
    Expected JSON body:
    {
        "target": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Run scan
        results = tech_detector.scan(target)
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results_store[f'tech_{scan_id}'] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dns-recon', methods=['POST'])
def dns_reconnaissance():
    """
    Run DNS Reconnaissance
    
    Expected JSON body:
    {
        "target": "example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
            
        # Run scan
        results = dns_recon.scan(target)
        
        # Store results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results_store[f'dns_{scan_id}'] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dmarc-scan', methods=['POST'])
def dmarc_scan_endpoint():
    """
    Run DMARC scanner
    
    Expected JSON body:
    {
        "target": "example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target domain is required'}), 400
            
        # Run scan
        results = dmarc_scanner.scan(target)
        
        # Store results
        if 'error' not in results:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            scan_results_store[f'dmarc_{scan_id}'] = results
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'results': results
            })
        else:
            return jsonify({
                'success': False,
                'error': results['error']
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf():
    """
    Generate PDF report from scan results
    
    Expected JSON body:
    {
        "target": "https://example.com",
        "vuln_scan": {...},
        "port_scan": {...},
        "dir_fuzz": {...},
        "tech_detect": {...},
        "dns_recon": {...}
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Scan results are required'}), 400
        
        print(f"[PDF] Generating report for: {data.get('target', 'Unknown')}")
        
        # Add metadata
        data['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate PDF
        try:
            pdf_content = pdf_generator.generate(data)
            print(f"[PDF] Generated {len(pdf_content)} bytes")
        except Exception as pdf_error:
            print(f"[PDF] Generation error: {pdf_error}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'PDF generation failed: {str(pdf_error)}'}), 500
        
        if not pdf_content or len(pdf_content) == 0:
            return jsonify({'error': 'PDF generation returned empty content'}), 500
        
        # Return PDF file
        buffer = BytesIO(pdf_content)
        buffer.seek(0)
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        response = send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        response.headers['Content-Length'] = len(pdf_content)
        
        return response
        
    except Exception as e:
        print(f"[PDF] Endpoint error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan-all', methods=['POST'])
def scan_all():
    """
    Run all scans on a target
    
    Expected JSON body:
    {
        "target": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        results = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'vuln_scan': None,
            'port_scan': None,
            'dir_fuzz': None,
            'tech_detect': None,
            'dns_recon': None
        }
        
        # Run all scans
        try:
            results['vuln_scan'] = scanner.scan(target)
        except Exception as e:
            results['vuln_scan'] = {'error': str(e)}
        
        try:
            results['port_scan'] = port_scanner.scan(target, 'common')
        except Exception as e:
            results['port_scan'] = {'error': str(e)}
        
        try:
            results['dir_fuzz'] = dir_fuzzer.scan(target)
        except Exception as e:
            results['dir_fuzz'] = {'error': str(e)}
        
        try:
            results['tech_detect'] = tech_detector.scan(target)
        except Exception as e:
            results['tech_detect'] = {'error': str(e)}

        try:
            results['dns_recon'] = dns_recon.scan(target)
        except Exception as e:
            results['dns_recon'] = {'error': str(e)}
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡️  WEBVULNX - Security Scanner                        ║
    ║                                                           ║
    ║   Starting server at http://localhost:5000                ║
    ║                                                           ║
    ║   Available endpoints:                                    ║
    ║   • POST /api/vuln-scan    - Vulnerability scanning       ║
    ║   • POST /api/port-scan    - Port scanning                ║
    ║   • POST /api/dir-fuzz     - Directory fuzzing            ║
    ║   • POST /api/tech-detect  - Technology detection         ║
    ║   • POST /api/dns-recon    - DNS Reconnaissance           ║
    ║   • POST /api/nuclei-scan  - Nuclei scanning              ║
    ║   • POST /api/dmarc-scan   - DMARC scanning               ║    
    ║   • POST /api/generate-pdf - Generate PDF report          ║
    ║   • POST /api/scan-all     - Run all scans                ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
