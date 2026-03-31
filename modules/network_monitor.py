"""
Network Connections Monitor
Maps active connections to owning processes, identifies listening ports,
and flags suspicious external connections.
"""

import platform
from datetime import datetime


# Known suspicious ports (commonly used by malware)
SUSPICIOUS_PORTS = {
    4444: 'Metasploit default handler',
    5555: 'Common reverse shell',
    6666: 'Common backdoor',
    6667: 'IRC (common C2 channel)',
    8443: 'Alternative HTTPS (potential C2)',
    9999: 'Common reverse shell',
    1337: 'Common backdoor',
    31337: 'Back Orifice',
    12345: 'NetBus trojan',
    55553: 'Common C2',
    13337: 'Common C2',
    443: None,  # HTTPS - only flag if unexpected process
    80: None,   # HTTP - only flag if unexpected process
}

# Processes that legitimately make external connections
LEGITIMATE_NETWORK_PROCESSES = {
    'windows': [
        'svchost.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe',
        'outlook.exe', 'teams.exe', 'onedrive.exe', 'code.exe',
        'windowsupdate', 'wuauclt.exe', 'microsoftedgeupdate.exe',
        'searchhost.exe', 'widgets.exe', 'spotify.exe'
    ],
    'linux': [
        'firefox', 'chrome', 'chromium', 'apt', 'apt-get', 'dpkg',
        'snap', 'flatpak', 'curl', 'wget', 'ssh', 'systemd-resolved',
        'NetworkManager', 'snapd', 'code', 'spotify'
    ]
}

# Private/reserved IP ranges
PRIVATE_RANGES = [
    ('10.', '10.'),
    ('172.16.', '172.31.'),
    ('192.168.', '192.168.'),
    ('127.', '127.'),
    ('0.0.0.0', '0.0.0.0'),
    ('::', '::'),
    ('::1', '::1'),
    ('fe80:', 'fe80:'),
]


class NetworkMonitor:
    """Cross-platform network connection monitor."""

    def __init__(self):
        self.os_type = platform.system().lower()

    def scan(self):
        """Run live network connection scan using the endpoint collector."""
        from modules.collector import EndpointCollector
        collector = EndpointCollector()

        connections = collector.collect_network_connections()
        findings = []

        if not connections:
            return {
                'connections': [],
                'findings': [{
                    'type': 'collection_warning',
                    'severity': 'info',
                    'message': 'No connections collected. Install psutil for best results: pip install psutil',
                    'mitre_id': None,
                    'mitre_name': None,
                    'details': 'Falling back to netstat/ss may require elevated privileges.'
                }],
                'connection_count': 0,
                'findings_count': 0,
                'established_count': 0,
                'listening_count': 0,
                'scan_time': datetime.now().isoformat(),
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 1}
            }

        # Analyze connections
        findings.extend(self._check_suspicious_ports(connections))
        findings.extend(self._check_unusual_external(connections))
        findings.extend(self._check_listening_services(connections))

        return {
            'connections': connections,
            'findings': findings,
            'connection_count': len(connections),
            'findings_count': len(findings),
            'established_count': sum(1 for c in connections if c['status'] == 'ESTABLISHED'),
            'listening_count': sum(1 for c in connections if c['status'] == 'LISTEN'),
            'scan_time': datetime.now().isoformat(),
            'summary': self._build_summary(findings)
        }

    def _is_private_ip(self, ip):
        """Check if an IP address is in a private/reserved range."""
        if not ip:
            return True
        for start, _ in PRIVATE_RANGES:
            if ip.startswith(start):
                return True
        return False

    def _check_suspicious_ports(self, connections):
        """Flag connections on known suspicious ports."""
        findings = []
        for conn in connections:
            remote_port = conn.get('remote_port')
            local_port = conn.get('local_port')

            for port in [remote_port, local_port]:
                if port and port in SUSPICIOUS_PORTS and SUSPICIOUS_PORTS[port]:
                    findings.append({
                        'type': 'suspicious_port',
                        'severity': 'high',
                        'process': conn['process'],
                        'pid': conn['pid'],
                        'message': f'Connection on suspicious port {port}: {SUSPICIOUS_PORTS[port]}',
                        'mitre_id': 'T1571',
                        'mitre_name': 'Non-Standard Port',
                        'details': f'Local: {conn["local_address"]} → Remote: {conn["remote_address"]} | Status: {conn["status"]}'
                    })
        return findings

    def _check_unusual_external(self, connections):
        """Flag unexpected processes making external connections."""
        findings = []
        legitimate = LEGITIMATE_NETWORK_PROCESSES.get(self.os_type, [])

        for conn in connections:
            if conn['status'] == 'ESTABLISHED' and conn['remote_ip']:
                if not self._is_private_ip(conn['remote_ip']):
                    proc_lower = conn['process'].lower()
                    if not any(legit in proc_lower for legit in legitimate):
                        findings.append({
                            'type': 'unusual_external_connection',
                            'severity': 'medium',
                            'process': conn['process'],
                            'pid': conn['pid'],
                            'message': f'Unusual process with external connection: {conn["process"]} → {conn["remote_ip"]}',
                            'mitre_id': 'T1071.001',
                            'mitre_name': 'Application Layer Protocol: Web Protocols',
                            'details': f'Local: {conn["local_address"]} → Remote: {conn["remote_address"]}'
                        })
        return findings

    def _check_listening_services(self, connections):
        """Flag unexpected listening services."""
        findings = []
        high_risk_listeners = ['cmd.exe', 'powershell.exe', 'bash', 'sh', 'nc', 'ncat', 'netcat']

        for conn in connections:
            if conn['status'] == 'LISTEN':
                proc_lower = conn['process'].lower()
                if any(risk in proc_lower for risk in high_risk_listeners):
                    findings.append({
                        'type': 'suspicious_listener',
                        'severity': 'critical',
                        'process': conn['process'],
                        'pid': conn['pid'],
                        'message': f'High-risk process listening on port: {conn["process"]} on {conn["local_address"]}',
                        'mitre_id': 'T1059.004' if self.os_type == 'linux' else 'T1059.001',
                        'mitre_name': 'Command and Scripting Interpreter',
                        'details': f'A shell or netcat process is listening for incoming connections. Possible bind shell or reverse shell listener.'
                    })
        return findings

    def _build_summary(self, findings):
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_demo_data(self):
        """Return realistic simulated network data for portfolio demos."""
        demo_connections = [
            {
                'pid': 1024, 'process': 'svchost.exe',
                'local_address': '0.0.0.0:135', 'remote_address': 'N/A',
                'status': 'LISTEN', 'local_port': 135, 'remote_port': None,
                'remote_ip': None, 'protocol': 'TCP'
            },
            {
                'pid': 1088, 'process': 'svchost.exe',
                'local_address': '0.0.0.0:445', 'remote_address': 'N/A',
                'status': 'LISTEN', 'local_port': 445, 'remote_port': None,
                'remote_ip': None, 'protocol': 'TCP'
            },
            {
                'pid': 4521, 'process': 'chrome.exe',
                'local_address': '192.168.1.105:52341', 'remote_address': '142.250.80.46:443',
                'status': 'ESTABLISHED', 'local_port': 52341, 'remote_port': 443,
                'remote_ip': '142.250.80.46', 'protocol': 'TCP'
            },
            {
                'pid': 764, 'process': 'lsass.exe',
                'local_address': '0.0.0.0:49664', 'remote_address': 'N/A',
                'status': 'LISTEN', 'local_port': 49664, 'remote_port': None,
                'remote_ip': None, 'protocol': 'TCP'
            },
            # ---- SUSPICIOUS ENTRIES ----
            {
                'pid': 6672, 'process': 'svchost.exe',
                'local_address': '192.168.1.105:49823', 'remote_address': '185.220.101.45:4444',
                'status': 'ESTABLISHED', 'local_port': 49823, 'remote_port': 4444,
                'remote_ip': '185.220.101.45', 'protocol': 'TCP'
            },
            {
                'pid': 8901, 'process': 'powershell.exe',
                'local_address': '192.168.1.105:50112', 'remote_address': '91.215.85.17:443',
                'status': 'ESTABLISHED', 'local_port': 50112, 'remote_port': 443,
                'remote_ip': '91.215.85.17', 'protocol': 'TCP'
            },
            {
                'pid': 9921, 'process': 'nc.exe',
                'local_address': '0.0.0.0:9999', 'remote_address': 'N/A',
                'status': 'LISTEN', 'local_port': 9999, 'remote_port': None,
                'remote_ip': None, 'protocol': 'TCP'
            },
        ]

        demo_findings = [
            {
                'type': 'suspicious_port',
                'severity': 'high',
                'process': 'svchost.exe',
                'pid': 6672,
                'message': 'Connection on suspicious port 4444: Metasploit default handler',
                'mitre_id': 'T1571',
                'mitre_name': 'Non-Standard Port',
                'details': 'Local: 192.168.1.105:49823 → Remote: 185.220.101.45:4444 | Status: ESTABLISHED'
            },
            {
                'type': 'unusual_external_connection',
                'severity': 'medium',
                'process': 'powershell.exe',
                'pid': 8901,
                'message': 'Unusual process with external connection: powershell.exe → 91.215.85.17',
                'mitre_id': 'T1071.001',
                'mitre_name': 'Application Layer Protocol: Web Protocols',
                'details': 'Local: 192.168.1.105:50112 → Remote: 91.215.85.17:443 | Encrypted C2 channel suspected'
            },
            {
                'type': 'suspicious_listener',
                'severity': 'critical',
                'process': 'nc.exe',
                'pid': 9921,
                'message': 'High-risk process listening: nc.exe on 0.0.0.0:9999',
                'mitre_id': 'T1059.003',
                'mitre_name': 'Command and Scripting Interpreter: Windows Command Shell',
                'details': 'Netcat listening on port 9999. Possible bind shell awaiting incoming connection.'
            },
            {
                'type': 'suspicious_port',
                'severity': 'high',
                'process': 'nc.exe',
                'pid': 9921,
                'message': 'Connection on suspicious port 9999: Common reverse shell',
                'mitre_id': 'T1571',
                'mitre_name': 'Non-Standard Port',
                'details': 'Local: 0.0.0.0:9999 | Netcat listener on common attack port'
            },
        ]

        return {
            'connections': demo_connections,
            'findings': demo_findings,
            'connection_count': len(demo_connections),
            'findings_count': len(demo_findings),
            'established_count': 3,
            'listening_count': 4,
            'scan_time': datetime.now().isoformat(),
            'summary': {'critical': 1, 'high': 2, 'medium': 1, 'low': 0, 'info': 0}
        }
