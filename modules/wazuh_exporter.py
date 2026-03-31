"""
Wazuh Exporter Module
Ships EndpointForge findings as structured JSON logs for Wazuh ingestion.

Integration method: EndpointForge writes findings to a JSON log file on
the endpoint. Wazuh agent monitors that log file using localfile config.
Wazuh server decodes the JSON with a custom decoder and fires alerts
based on custom rules mapped to MITRE ATT&CK.

Deployment:
  1. EndpointForge runs on the endpoint (where Wazuh agent is installed)
  2. Findings are written to the configured log path
  3. Wazuh agent picks up new log entries via ossec.conf localfile
  4. Wazuh server decodes with custom decoder → fires rules → dashboard

Log paths:
  Windows: C:\\EndpointForge\\logs\\endpointforge.json
  Linux:   /var/log/endpointforge/endpointforge.json
"""

import os
import json
import platform
import socket
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


# Default log paths by OS
DEFAULT_LOG_PATHS = {
    'windows': r'C:\EndpointForge\logs\endpointforge.json',
    'linux': '/var/log/endpointforge/endpointforge.json'
}


class WazuhExporter:
    """Exports EndpointForge findings as Wazuh-ingestible JSON logs."""

    def __init__(self, log_path=None):
        self.os_type = platform.system().lower()
        self.log_path = log_path or DEFAULT_LOG_PATHS.get(self.os_type, '/tmp/endpointforge.json')
        self.hostname = platform.node()

    def setup(self):
        """
        Create log directory and verify write access.
        Returns dict with status and instructions.
        """
        log_dir = os.path.dirname(self.log_path)
        try:
            os.makedirs(log_dir, exist_ok=True)

            # Test write access
            test_file = os.path.join(log_dir, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)

            return {
                'status': 'success',
                'log_path': self.log_path,
                'log_dir': log_dir,
                'message': f'Log directory ready at {log_dir}',
                'next_steps': self._get_agent_config_instructions()
            }
        except PermissionError:
            return {
                'status': 'error',
                'message': f'Permission denied creating {log_dir}. Run with elevated privileges.',
                'log_path': self.log_path
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'log_path': self.log_path
            }

    def export_findings(self, scan_data):
        """
        Export scan findings to the JSON log file.
        Each finding becomes one JSON line (NDJSON format) for Wazuh to parse.
        Returns count of exported entries.
        """
        # Ensure directory exists
        log_dir = os.path.dirname(self.log_path)
        os.makedirs(log_dir, exist_ok=True)

        exported = 0
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000+0000')

        # Collect all findings across modules
        modules = ['processes', 'network', 'filesystem', 'registry', 'persistence']

        with open(self.log_path, 'a') as f:
            for module in modules:
                module_data = scan_data.get(module, {})
                findings = module_data.get('findings', [])

                for finding in findings:
                    log_entry = self._format_finding(finding, module, timestamp)
                    f.write(json.dumps(log_entry) + '\n')
                    exported += 1

            # Also write a scan summary entry
            summary_entry = self._format_scan_summary(scan_data, timestamp)
            f.write(json.dumps(summary_entry) + '\n')
            exported += 1

        return {
            'status': 'success',
            'exported_count': exported,
            'log_path': self.log_path,
            'timestamp': timestamp
        }

    def export_single_finding(self, finding, module='unknown'):
        """Export a single finding immediately (for real-time alerting)."""
        log_dir = os.path.dirname(self.log_path)
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000+0000')
        log_entry = self._format_finding(finding, module, timestamp)

        with open(self.log_path, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        return {'status': 'success', 'log_path': self.log_path}

    def _format_finding(self, finding, module, timestamp):
        """
        Format a single finding as a Wazuh-compatible JSON log entry.
        Field names are chosen to align with Wazuh's decoder expectations
        and MITRE ATT&CK integration.
        """
        return {
            'timestamp': timestamp,
            'endpointforge': {
                'module': module,
                'type': finding.get('type', 'unknown'),
                'severity': finding.get('severity', 'info'),
                'message': finding.get('message', ''),
                'details': finding.get('details', ''),
                'process': finding.get('process', ''),
                'pid': finding.get('pid', 0),
                'mitre': {
                    'id': finding.get('mitre_id', ''),
                    'technique': finding.get('mitre_name', '')
                },
                'registry_key': finding.get('registry_key', ''),
                'value_name': finding.get('value_name', ''),
            },
            'agent': {
                'name': self.hostname,
                'ip': self._get_local_ip()
            },
            'source': 'endpointforge',
            'version': '1.0.0'
        }

    def _format_scan_summary(self, scan_data, timestamp):
        """Format a scan summary log entry."""
        # Aggregate severity counts
        severity_totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        total_findings = 0
        modules = ['processes', 'network', 'filesystem', 'registry', 'persistence']

        for module in modules:
            module_data = scan_data.get(module, {})
            summary = module_data.get('summary', {})
            for sev in severity_totals:
                severity_totals[sev] += summary.get(sev, 0)
            total_findings += len(module_data.get('findings', []))

        return {
            'timestamp': timestamp,
            'endpointforge': {
                'module': 'scan_summary',
                'type': 'scan_complete',
                'severity': 'critical' if severity_totals['critical'] > 0
                           else 'high' if severity_totals['high'] > 0
                           else 'medium' if severity_totals['medium'] > 0
                           else 'info',
                'message': f'EndpointForge scan complete: {total_findings} findings',
                'details': json.dumps(severity_totals),
                'total_findings': total_findings,
                'severity_counts': severity_totals,
                'mitre': {
                    'id': '',
                    'technique': ''
                }
            },
            'agent': {
                'name': self.hostname,
                'ip': self._get_local_ip()
            },
            'source': 'endpointforge',
            'version': '1.0.0'
        }

    def clear_log(self):
        """Clear the log file (useful before a fresh scan)."""
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, 'w') as f:
                    pass  # Truncate
            return {'status': 'success', 'message': f'Log cleared: {self.log_path}'}
        except Exception as e:
            # Log the detailed exception server-side, but return a generic message to the caller
            logger.exception("Failed to clear Wazuh export log")
            return {
                'status': 'error',
                'message': 'Failed to clear Wazuh export log.'
            }

    def get_status(self):
        """Check exporter status and log file info."""
        log_exists = os.path.exists(self.log_path)
        log_size = os.path.getsize(self.log_path) if log_exists else 0
        line_count = 0
        if log_exists:
            try:
                with open(self.log_path, 'r') as f:
                    line_count = sum(1 for _ in f)
            except Exception:
                pass

        return {
            'log_path': self.log_path,
            'log_exists': log_exists,
            'log_size_bytes': log_size,
            'log_size_readable': self._human_size(log_size),
            'entry_count': line_count,
            'os': self.os_type,
            'hostname': self.hostname
        }

    def _get_local_ip(self):
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _human_size(self, size_bytes):
        """Convert bytes to human-readable size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f'{size_bytes:.1f} {unit}'
            size_bytes /= 1024
        return f'{size_bytes:.1f} TB'

    def _get_agent_config_instructions(self):
        """Return ossec.conf snippet for the Wazuh agent."""
        if self.os_type == 'windows':
            return {
                'agent_config': f'''<!-- Add to C:\\Program Files (x86)\\ossec-agent\\ossec.conf -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>{self.log_path}</location>
    <label key="log_type">endpointforge</label>
  </localfile>
</ossec_config>''',
                'restart_command': 'Restart-Service WazuhSvc'
            }
        else:
            return {
                'agent_config': f'''<!-- Add to /var/ossec/etc/ossec.conf -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>{self.log_path}</location>
    <label key="log_type">endpointforge</label>
  </localfile>
</ossec_config>''',
                'restart_command': 'sudo systemctl restart wazuh-agent'
            }

    def get_demo_export(self):
        """Return what a demo export would look like without writing to disk."""
        from modules.process_monitor import ProcessMonitor
        from modules.network_monitor import NetworkMonitor
        from modules.filesystem_monitor import FileSystemMonitor
        from modules.registry_monitor import RegistryMonitor
        from modules.persistence_monitor import PersistenceMonitor

        scan_data = {
            'hostname': 'WORKSTATION-01',
            'os': 'windows',
            'processes': ProcessMonitor().get_demo_data(),
            'network': NetworkMonitor().get_demo_data(),
            'filesystem': FileSystemMonitor().get_demo_data(),
            'registry': RegistryMonitor().get_demo_data(),
            'persistence': PersistenceMonitor().get_demo_data()
        }

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000+0000')
        entries = []

        for module in ['processes', 'network', 'filesystem', 'registry', 'persistence']:
            module_data = scan_data.get(module, {})
            for finding in module_data.get('findings', []):
                entries.append(self._format_finding(finding, module, timestamp))

        entries.append(self._format_scan_summary(scan_data, timestamp))

        return {
            'entries': entries,
            'count': len(entries),
            'sample_ndjson': '\n'.join(json.dumps(e) for e in entries[:3])
        }
