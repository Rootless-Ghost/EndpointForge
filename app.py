"""
EndpointForge - Cross-Platform Endpoint Security Monitor
A lightweight host-based intrusion detection and endpoint triage tool
with MITRE ATT&CK mapping for Windows and Linux systems.

Author: Rootless-Ghost
Version: 1.0.0
"""

from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime
import json
import os
import platform
import logging
import subprocess
import yaml

# Import endpoint modules
from modules.process_monitor import ProcessMonitor
from modules.network_monitor import NetworkMonitor
from modules.filesystem_monitor import FileSystemMonitor
from modules.registry_monitor import RegistryMonitor
from modules.persistence_monitor import PersistenceMonitor
from modules.report_generator import ReportGenerator
from modules.wazuh_exporter import WazuhExporter

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# Detect OS at startup
CURRENT_OS = platform.system().lower()  # 'windows' or 'linux'


# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

def _load_config() -> dict:
    """Load config.yaml from the app directory, return empty dict if absent."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("Could not load config.yaml: %s", exc)
        return {}


_config = _load_config()

# Initialize modules
process_mon = ProcessMonitor()
network_mon = NetworkMonitor()
filesystem_mon = FileSystemMonitor()
registry_mon = RegistryMonitor()
persistence_mon = PersistenceMonitor()
report_gen = ReportGenerator()
wazuh_exp = WazuhExporter()


# ──────────────────────────────────────────────
# ROUTES - Pages
# ──────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Main dashboard - system overview and scan controls."""
    return render_template('dashboard.html', os_type=CURRENT_OS)


@app.route('/processes')
def processes():
    """Process execution analysis page."""
    return render_template('processes.html', os_type=CURRENT_OS)


@app.route('/network')
def network():
    """Network connections analysis page."""
    return render_template('network.html', os_type=CURRENT_OS)


@app.route('/filesystem')
def filesystem():
    """File system integrity monitoring page."""
    return render_template('filesystem.html', os_type=CURRENT_OS)


@app.route('/registry')
def registry():
    """Registry modifications analysis page (Windows only)."""
    return render_template('registry.html', os_type=CURRENT_OS)


@app.route('/persistence')
def persistence():
    """Persistence mechanism detection page."""
    return render_template('persistence.html', os_type=CURRENT_OS)


@app.route('/reports')
def reports():
    """Report generation and export page."""
    return render_template('reports.html', os_type=CURRENT_OS)


# ──────────────────────────────────────────────
# API ROUTES - Data Collection & Analysis
# ──────────────────────────────────────────────

@app.route('/api/system-info', methods=['GET'])
def api_system_info():
    """Get basic system information."""
    try:
        info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': platform.node(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'scan_time': datetime.now().isoformat()
        }
        return jsonify({'status': 'success', 'data': info})
    except Exception as e:
        logger.exception("Error while gathering system information")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/processes', methods=['POST'])
def api_scan_processes():
    """Scan running processes and analyze for anomalies."""
    try:
        results = process_mon.scan()
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during process scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/network', methods=['POST'])
def api_scan_network():
    """Scan active network connections."""
    try:
        results = network_mon.scan()
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during network scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/filesystem', methods=['POST'])
def api_scan_filesystem():
    """Scan filesystem for integrity changes."""
    try:
        mode = request.json.get('mode', 'baseline')  # 'baseline' or 'check'
        paths = request.json.get('paths', [])
        results = filesystem_mon.scan(mode=mode, custom_paths=paths)
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during filesystem scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/registry', methods=['POST'])
def api_scan_registry():
    """Scan Windows registry for suspicious modifications."""
    try:
        if CURRENT_OS != 'windows':
            return jsonify({
                'status': 'info',
                'message': 'Registry analysis is only available on Windows systems.',
                'data': {'findings': [], 'os_supported': False}
            })
        results = registry_mon.scan()
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during registry scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/persistence', methods=['POST'])
def api_scan_persistence():
    """Scan for persistence mechanisms."""
    try:
        results = persistence_mon.scan()
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during persistence scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/scan/full', methods=['POST'])
def api_full_scan():
    """Run a complete endpoint scan across all modules."""
    try:
        results = {
            'scan_time': datetime.now().isoformat(),
            'os': CURRENT_OS,
            'hostname': platform.node(),
            'processes': process_mon.scan(),
            'network': network_mon.scan(),
            'filesystem': filesystem_mon.scan(mode='check'),
            'persistence': persistence_mon.scan()
        }
        if CURRENT_OS == 'windows':
            results['registry'] = registry_mon.scan()

        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        logger.exception("Error during full scan")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/report/generate', methods=['POST'])
def api_generate_report():
    """Generate a report from scan results."""
    try:
        scan_data = request.json.get('scan_data', {})
        report_format = request.json.get('format', 'markdown')  # 'markdown' or 'json'
        report = report_gen.generate(scan_data, report_format)
        return jsonify({'status': 'success', 'data': report})
    except Exception as e:
        logger.exception("Error during report generation")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


@app.route('/api/report/export', methods=['POST'])
def api_export_report():
    """Export report as downloadable file."""
    try:
        scan_data = request.json.get('scan_data', {})
        report_format = request.json.get('format', 'markdown')
        report = report_gen.generate(scan_data, report_format)

        ext = 'md' if report_format == 'markdown' else 'json'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'EndpointForge_Report_{timestamp}.{ext}'
        filepath = os.path.join('exports', filename)

        with open(filepath, 'w') as f:
            f.write(report['content'])

        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.exception("Error during report export")
        return jsonify({'status': 'error', 'message': 'An internal error has occurred.'}), 500


# ──────────────────────────────────────────────
# WAZUH INTEGRATION
# ──────────────────────────────────────────────

@app.route('/api/wazuh/setup', methods=['POST'])
def api_wazuh_setup():
    """Setup Wazuh exporter (create log directory)."""
    try:
        result = wazuh_exp.setup()
        if result.get('status') == 'success':
            # Expose only non-sensitive setup information
            return jsonify({
                'status': 'success',
                'data': {
                    'log_path': result.get('log_path'),
                    'log_dir': result.get('log_dir')
                }
            })
        # Log full result server-side but return a generic error to the client
        logger.error("Wazuh setup reported error: %s", result)
        return jsonify({
            'status': 'error',
            'message': 'A Wazuh-related internal error has occurred.'
        }), 500
    except Exception as e:
        logger.exception("Error during Wazuh setup")
        return jsonify({'status': 'error',
                        'message': 'A Wazuh-related internal error has occurred.'}), 500


@app.route('/api/wazuh/export', methods=['POST'])
def api_wazuh_export():
    """Export scan findings to Wazuh log file."""
    try:
        scan_data = request.json.get('scan_data', {})
        result = wazuh_exp.export_findings(scan_data)
        return jsonify({'status': 'success', 'data': result})
    except Exception as e:
        logger.exception("Error during Wazuh export of findings")
        return jsonify({'status': 'error',
                        'message': 'A Wazuh-related internal error has occurred.'}), 500


@app.route('/api/wazuh/status', methods=['GET'])
def api_wazuh_status():
    """Get Wazuh exporter status."""
    try:
        status = wazuh_exp.get_status()
        return jsonify({'status': 'success', 'data': status})
    except Exception as e:
        logger.exception("Error retrieving Wazuh status")
        return jsonify({'status': 'error',
                        'message': 'A Wazuh-related internal error has occurred.'}), 500


@app.route('/api/wazuh/clear', methods=['POST'])
def api_wazuh_clear():
    """Clear the Wazuh export log file."""
    try:
        result = wazuh_exp.clear_log()
        return jsonify({'status': result['status'], 'data': result})
    except Exception as e:
        logger.exception("Error clearing Wazuh export log")
        return jsonify({'status': 'error',
                        'message': 'A Wazuh-related internal error has occurred.'}), 500


@app.route('/api/wazuh/demo', methods=['GET'])
def api_wazuh_demo():
    """Preview what Wazuh export entries look like."""
    try:
        demo = wazuh_exp.get_demo_export()
        return jsonify({'status': 'success', 'data': demo})
    except Exception as e:
        logger.exception("Error generating Wazuh demo export")
        return jsonify({'status': 'error',
                        'message': 'A Wazuh-related internal error has occurred.'}), 500


# ──────────────────────────────────────────────
# DEMO MODE - Simulated data for portfolio demos
# ──────────────────────────────────────────────

@app.route('/api/demo/processes', methods=['GET'])
def demo_processes():
    """Return simulated process data for demo/portfolio purposes."""
    demo_data = process_mon.get_demo_data()
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


@app.route('/api/demo/network', methods=['GET'])
def demo_network():
    """Return simulated network data for demo/portfolio purposes."""
    demo_data = network_mon.get_demo_data()
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


@app.route('/api/demo/filesystem', methods=['GET'])
def demo_filesystem():
    """Return simulated FIM data for demo/portfolio purposes."""
    demo_data = filesystem_mon.get_demo_data()
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


@app.route('/api/demo/registry', methods=['GET'])
def demo_registry():
    """Return simulated registry data for demo/portfolio purposes."""
    demo_data = registry_mon.get_demo_data()
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


@app.route('/api/demo/persistence', methods=['GET'])
def demo_persistence():
    """Return simulated persistence data for demo/portfolio purposes."""
    demo_data = persistence_mon.get_demo_data()
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


@app.route('/api/demo/full', methods=['GET'])
def demo_full_scan():
    """Return a complete simulated scan for demo/portfolio purposes."""
    demo_data = {
        'scan_time': datetime.now().isoformat(),
        'os': 'windows',
        'hostname': 'WORKSTATION-01',
        'processes': process_mon.get_demo_data(),
        'network': network_mon.get_demo_data(),
        'filesystem': filesystem_mon.get_demo_data(),
        'registry': registry_mon.get_demo_data(),
        'persistence': persistence_mon.get_demo_data()
    }
    return jsonify({'status': 'success', 'data': demo_data, 'mode': 'demo'})


# ──────────────────────────────────────────────
# ENDPOINT TRIAGE INTEGRATION
# ──────────────────────────────────────────────

@app.route('/api/triage/run', methods=['POST'])
def api_triage_run():
    """Run Invoke-EndpointTriage.ps1 via subprocess and return status."""
    script = _config.get("endpoint_triage_script", "")
    output = _config.get("endpoint_triage_output", "")

    if not script:
        return jsonify({
            'status': 'error',
            'message': 'endpoint_triage_script not configured in config.yaml'
        }), 500

    if not os.path.isfile(script):
        return jsonify({
            'status': 'error',
            'message': f'Script not found: {script}'
        }), 500

    ps_command = (
        f"Get-Content '{script}' -Encoding UTF8 "
        f"| powershell -ExecutionPolicy Bypass -Command -"
    )
    cmd = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', ps_command]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Triage timed out after 5 minutes'}), 500
    except Exception as exc:
        logger.exception("Failed to launch Invoke-EndpointTriage.ps1")
        return jsonify({'status': 'error', 'message': 'Failed to start triage process'}), 500

    if proc.returncode != 0:
        return jsonify({
            'status': 'error',
            'message': f'Script exited with code {proc.returncode}',
            'stderr': proc.stderr[-2000:] if proc.stderr else '',
        }), 500

    return jsonify({
        'status': 'success',
        'message': 'Triage completed successfully',
        'output_path': output,
        'stdout': proc.stdout[-2000:] if proc.stdout else '',
    })


if __name__ == '__main__':
    os.makedirs('exports', exist_ok=True)
    os.makedirs('baselines', exist_ok=True)
    debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    app.run(debug=debug_mode, host='0.0.0.0', port=5005)
