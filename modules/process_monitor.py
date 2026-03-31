"""
Process Execution Monitor
Enumerates running processes, builds parent-child hierarchy,
and flags anomalies against known-good baselines.
"""

import platform
import json
from datetime import datetime

# Windows core process baselines - expected properties for critical system processes
WINDOWS_CORE_PROCESSES = {
    'system': {
        'expected_pid': 4,
        'expected_parent': 'None (PID 0)',
        'expected_path': 'N/A (kernel)',
        'expected_instances': 1,
        'description': 'Windows kernel process',
        'notes': 'Always PID 4. No parent process. Should never have a file path.'
    },
    'smss.exe': {
        'expected_pid': None,
        'expected_parent': 'System (PID 4)',
        'expected_path': r'C:\Windows\System32\smss.exe',
        'expected_instances': 1,
        'description': 'Session Manager Subsystem',
        'notes': 'First user-mode process. Parent is System. Only one instance after boot.'
    },
    'csrss.exe': {
        'expected_pid': None,
        'expected_parent': 'smss.exe (created then orphaned)',
        'expected_path': r'C:\Windows\System32\csrss.exe',
        'expected_instances': 2,
        'description': 'Client Server Runtime Subsystem',
        'notes': 'Two instances normal (Session 0 + Session 1). Parent appears as non-existent (orphaned from smss.exe).'
    },
    'wininit.exe': {
        'expected_pid': None,
        'expected_parent': 'smss.exe (created then orphaned)',
        'expected_path': r'C:\Windows\System32\wininit.exe',
        'expected_instances': 1,
        'description': 'Windows Initialization Process',
        'notes': 'One instance. Runs in Session 0. Parent appears as non-existent (orphaned).'
    },
    'winlogon.exe': {
        'expected_pid': None,
        'expected_parent': 'smss.exe (created then orphaned)',
        'expected_path': r'C:\Windows\System32\winlogon.exe',
        'expected_instances': 1,
        'description': 'Windows Logon Process',
        'notes': 'One instance per session. Runs in Session 1+. Handles user logon/logoff.'
    },
    'services.exe': {
        'expected_pid': None,
        'expected_parent': 'wininit.exe',
        'expected_path': r'C:\Windows\System32\services.exe',
        'expected_instances': 1,
        'description': 'Service Control Manager',
        'notes': 'One instance only. Parent must be wininit.exe. Manages Windows services.'
    },
    'lsass.exe': {
        'expected_pid': None,
        'expected_parent': 'wininit.exe',
        'expected_path': r'C:\Windows\System32\lsass.exe',
        'expected_instances': 1,
        'description': 'Local Security Authority Subsystem',
        'notes': 'One instance only. Parent must be wininit.exe. Credential storage — prime target for credential dumping.'
    },
    'svchost.exe': {
        'expected_pid': None,
        'expected_parent': 'services.exe',
        'expected_path': r'C:\Windows\System32\svchost.exe',
        'expected_instances': None,  # Multiple instances expected
        'description': 'Service Host Process',
        'notes': 'Multiple instances normal. Parent must be services.exe. Always runs with -k flag. Path must be System32.'
    },
    'explorer.exe': {
        'expected_pid': None,
        'expected_parent': 'userinit.exe (created then exits)',
        'expected_path': r'C:\Windows\explorer.exe',
        'expected_instances': 1,
        'description': 'Windows Explorer Shell',
        'notes': 'One instance per user session. Parent appears as non-existent (userinit.exe exits). Runs in user session.'
    },
}

# Suspicious indicators for process analysis
SUSPICIOUS_PROCESS_NAMES = [
    'mimikatz', 'psexec', 'procdump', 'lazagne', 'rubeus',
    'sharphound', 'bloodhound', 'covenant', 'cobalt',
    'meterpreter', 'nc.exe', 'ncat.exe', 'netcat',
    'powershell_ise', 'certutil', 'bitsadmin', 'mshta',
    'regsvr32', 'rundll32', 'wmic', 'cmstp', 'msiexec'
]

SUSPICIOUS_PATHS = [
    r'\temp\\', r'\tmp\\', r'\appdata\local\temp',
    r'\downloads\\', r'\public\\', r'\programdata\\',
    '/tmp/', '/var/tmp/', '/dev/shm/'
]


class ProcessMonitor:
    """Cross-platform process execution monitor."""

    def __init__(self):
        self.os_type = platform.system().lower()

    def scan(self):
        """Run live process scan using the endpoint collector."""
        from modules.collector import EndpointCollector
        collector = EndpointCollector()

        processes = collector.collect_processes()
        if not processes:
            return {
                'error': 'Could not collect process data. Install psutil: pip install psutil',
                'processes': [],
                'findings': [],
                'process_count': 0,
                'findings_count': 0,
                'summary': {}
            }

        findings = []
        process_tree = {p['pid']: p for p in processes}

        # Analyze against baselines
        if self.os_type == 'windows':
            findings.extend(self._check_windows_core_processes(processes, process_tree))
            findings.extend(self._check_svchost_parents(processes, process_tree))

        findings.extend(self._check_suspicious_processes(processes))
        findings.extend(self._check_suspicious_paths(processes))
        findings.extend(self._check_suspicious_cmdline(processes))

        return {
            'processes': processes,
            'findings': findings,
            'process_count': len(processes),
            'findings_count': len(findings),
            'scan_time': datetime.now().isoformat(),
            'summary': self._build_summary(findings)
        }

    def _check_svchost_parents(self, processes, process_tree):
        """Verify all svchost.exe instances are children of services.exe."""
        findings = []
        services_pids = set()

        # Find services.exe PID(s)
        for proc in processes:
            if proc['name'].lower() == 'services.exe':
                services_pids.add(proc['pid'])

        # Check each svchost
        for proc in processes:
            if proc['name'].lower() == 'svchost.exe':
                if proc['ppid'] not in services_pids:
                    parent = process_tree.get(proc['ppid'], {})
                    parent_name = parent.get('name', 'Unknown')
                    findings.append({
                        'type': 'wrong_parent',
                        'severity': 'critical',
                        'process': 'svchost.exe',
                        'pid': proc['pid'],
                        'message': f'svchost.exe (PID {proc["pid"]}) has unexpected parent: {parent_name} (PID {proc["ppid"]})',
                        'mitre_id': 'T1036.005',
                        'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                        'details': f'Expected parent: services.exe. Actual parent: {parent_name}. Path: {proc["exe"]}'
                    })

                # Check for missing -k flag
                if proc['cmdline'] != 'N/A' and '-k' not in proc['cmdline']:
                    findings.append({
                        'type': 'missing_flag',
                        'severity': 'high',
                        'process': 'svchost.exe',
                        'pid': proc['pid'],
                        'message': f'svchost.exe (PID {proc["pid"]}) running without -k flag',
                        'mitre_id': 'T1036.005',
                        'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                        'details': f'Legitimate svchost.exe always runs with -k <service_group>. CMD: {proc["cmdline"][:200]}'
                    })

        return findings

    def _check_suspicious_cmdline(self, processes):
        """Check for suspicious command-line patterns."""
        findings = []
        suspicious_patterns = [
            ('-enc ', 'Encoded command', 'critical', 'T1059.001'),
            ('-nop ', 'No profile flag', 'high', 'T1059.001'),
            ('-w hidden', 'Hidden window', 'high', 'T1059.001'),
            ('-ep bypass', 'Execution policy bypass', 'high', 'T1059.001'),
            ('downloadstring', 'Download cradle', 'critical', 'T1059.001'),
            ('invoke-expression', 'IEX execution', 'critical', 'T1059.001'),
            ('invoke-webrequest', 'Web request', 'medium', 'T1059.001'),
            ('net user ', 'User enumeration/creation', 'medium', 'T1059.003'),
            ('net localgroup', 'Group modification', 'high', 'T1059.003'),
            ('whoami /all', 'Privilege discovery', 'low', 'T1059.003'),
            ('reg add', 'Registry modification via CLI', 'high', 'T1112'),
            ('schtasks /create', 'Scheduled task creation', 'high', 'T1053.005'),
        ]

        for proc in processes:
            if proc['cmdline'] and proc['cmdline'] != 'N/A':
                cmdline_lower = proc['cmdline'].lower()
                for pattern, desc, severity, mitre_id in suspicious_patterns:
                    if pattern in cmdline_lower:
                        findings.append({
                            'type': 'suspicious_cmdline',
                            'severity': severity,
                            'process': proc['name'],
                            'pid': proc['pid'],
                            'message': f'{desc} detected in {proc["name"]} (PID {proc["pid"]})',
                            'mitre_id': mitre_id,
                            'mitre_name': 'Command and Scripting Interpreter',
                            'details': f'CMD: {proc["cmdline"][:300]} | User: {proc["username"]}'
                        })
                        break  # One finding per process to avoid noise

        return findings

    def _check_windows_core_processes(self, processes, process_tree):
        """Validate Windows core processes against known-good baselines."""
        findings = []
        name_counts = {}

        for proc in processes:
            name_lower = proc['name'].lower()
            name_counts[name_lower] = name_counts.get(name_lower, 0) + 1

        for core_name, baseline in WINDOWS_CORE_PROCESSES.items():
            count = name_counts.get(core_name, 0)

            # Check instance count
            if baseline['expected_instances'] is not None:
                if count == 0:
                    findings.append({
                        'type': 'missing_core_process',
                        'severity': 'critical',
                        'process': core_name,
                        'message': f'Core process {core_name} is NOT running',
                        'mitre_id': 'T1036.005',
                        'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                        'details': baseline['description']
                    })
                elif count > baseline['expected_instances'] and core_name != 'csrss.exe':
                    findings.append({
                        'type': 'excess_instances',
                        'severity': 'high',
                        'process': core_name,
                        'message': f'{core_name} has {count} instances (expected {baseline["expected_instances"]})',
                        'mitre_id': 'T1036.005',
                        'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                        'details': f'Multiple instances may indicate process masquerading. {baseline["notes"]}'
                    })

            # Check executable path
            for proc in processes:
                if proc['name'].lower() == core_name and proc['exe'] != 'N/A':
                    if baseline['expected_path'] != 'N/A (kernel)':
                        if proc['exe'].lower() != baseline['expected_path'].lower():
                            findings.append({
                                'type': 'wrong_path',
                                'severity': 'critical',
                                'process': core_name,
                                'message': f'{core_name} running from unexpected path: {proc["exe"]}',
                                'mitre_id': 'T1036.005',
                                'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                                'details': f'Expected: {baseline["expected_path"]}. {baseline["notes"]}'
                            })

        return findings

    def _check_suspicious_processes(self, processes):
        """Check for known suspicious process names."""
        findings = []
        for proc in processes:
            name_lower = proc['name'].lower().replace('.exe', '')
            for suspicious in SUSPICIOUS_PROCESS_NAMES:
                if suspicious in name_lower:
                    findings.append({
                        'type': 'suspicious_process',
                        'severity': 'high',
                        'process': proc['name'],
                        'pid': proc['pid'],
                        'message': f'Suspicious process detected: {proc["name"]} (PID: {proc["pid"]})',
                        'mitre_id': 'T1204.002',
                        'mitre_name': 'User Execution: Malicious File',
                        'details': f'Path: {proc["exe"]} | User: {proc["username"]} | CMD: {proc["cmdline"]}'
                    })
        return findings

    def _check_suspicious_paths(self, processes):
        """Check for processes running from suspicious locations."""
        findings = []
        for proc in processes:
            if proc['exe'] and proc['exe'] != 'N/A':
                exe_lower = proc['exe'].lower()
                for sus_path in SUSPICIOUS_PATHS:
                    if sus_path in exe_lower:
                        # Skip known legitimate temp processes
                        if proc['name'].lower() in ['setup.exe', 'installer.exe']:
                            continue
                        findings.append({
                            'type': 'suspicious_path',
                            'severity': 'medium',
                            'process': proc['name'],
                            'pid': proc['pid'],
                            'message': f'{proc["name"]} running from suspicious path: {proc["exe"]}',
                            'mitre_id': 'T1036.005',
                            'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                            'details': f'User: {proc["username"]} | CMD: {proc["cmdline"]}'
                        })
        return findings

    def _build_summary(self, findings):
        """Build findings summary by severity."""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_demo_data(self):
        """Return realistic simulated process data for portfolio demos."""
        demo_processes = [
            {
                'pid': 4, 'ppid': 0, 'name': 'System', 'exe': 'N/A',
                'cmdline': 'N/A', 'username': 'NT AUTHORITY\\SYSTEM',
                'status': 'running', 'create_time': '2025-03-23T08:00:00',
                'cpu_percent': 0.1, 'memory_percent': 0.05
            },
            {
                'pid': 512, 'ppid': 4, 'name': 'smss.exe',
                'exe': r'C:\Windows\System32\smss.exe', 'cmdline': r'\SystemRoot\System32\smss.exe',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:01', 'cpu_percent': 0.0, 'memory_percent': 0.02
            },
            {
                'pid': 620, 'ppid': 512, 'name': 'csrss.exe',
                'exe': r'C:\Windows\System32\csrss.exe',
                'cmdline': r'%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:02', 'cpu_percent': 0.2, 'memory_percent': 0.15
            },
            {
                'pid': 696, 'ppid': 512, 'name': 'wininit.exe',
                'exe': r'C:\Windows\System32\wininit.exe', 'cmdline': 'wininit.exe',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:02', 'cpu_percent': 0.0, 'memory_percent': 0.03
            },
            {
                'pid': 752, 'ppid': 696, 'name': 'services.exe',
                'exe': r'C:\Windows\System32\services.exe', 'cmdline': r'C:\Windows\system32\services.exe',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:03', 'cpu_percent': 0.1, 'memory_percent': 0.08
            },
            {
                'pid': 764, 'ppid': 696, 'name': 'lsass.exe',
                'exe': r'C:\Windows\System32\lsass.exe', 'cmdline': r'C:\Windows\system32\lsass.exe',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:03', 'cpu_percent': 0.3, 'memory_percent': 0.25
            },
            {
                'pid': 1024, 'ppid': 752, 'name': 'svchost.exe',
                'exe': r'C:\Windows\System32\svchost.exe',
                'cmdline': r'C:\Windows\system32\svchost.exe -k DcomLaunch -p',
                'username': 'NT AUTHORITY\\SYSTEM', 'status': 'running',
                'create_time': '2025-03-23T08:00:05', 'cpu_percent': 0.5, 'memory_percent': 0.45
            },
            {
                'pid': 1088, 'ppid': 752, 'name': 'svchost.exe',
                'exe': r'C:\Windows\System32\svchost.exe',
                'cmdline': r'C:\Windows\system32\svchost.exe -k RPCSS -p',
                'username': 'NT AUTHORITY\\NETWORK SERVICE', 'status': 'running',
                'create_time': '2025-03-23T08:00:05', 'cpu_percent': 0.2, 'memory_percent': 0.18
            },
            {
                'pid': 3456, 'ppid': 1024, 'name': 'explorer.exe',
                'exe': r'C:\Windows\explorer.exe', 'cmdline': r'C:\Windows\Explorer.EXE',
                'username': 'WORKSTATION-01\\analyst', 'status': 'running',
                'create_time': '2025-03-23T08:01:30', 'cpu_percent': 1.2, 'memory_percent': 2.5
            },
            # ---- SUSPICIOUS ENTRIES FOR DEMO ----
            {
                'pid': 6672, 'ppid': 3456, 'name': 'svchost.exe',
                'exe': r'C:\Users\Public\Downloads\svchost.exe',
                'cmdline': r'C:\Users\Public\Downloads\svchost.exe',
                'username': 'WORKSTATION-01\\analyst', 'status': 'running',
                'create_time': '2025-03-23T09:15:42', 'cpu_percent': 15.3, 'memory_percent': 4.2
            },
            {
                'pid': 7788, 'ppid': 6672, 'name': 'cmd.exe',
                'exe': r'C:\Windows\System32\cmd.exe',
                'cmdline': r'cmd.exe /c whoami /all > C:\Users\Public\info.txt',
                'username': 'WORKSTATION-01\\analyst', 'status': 'running',
                'create_time': '2025-03-23T09:15:45', 'cpu_percent': 0.5, 'memory_percent': 0.1
            },
            {
                'pid': 8901, 'ppid': 6672, 'name': 'powershell.exe',
                'exe': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                'cmdline': 'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtA...',
                'username': 'WORKSTATION-01\\analyst', 'status': 'running',
                'create_time': '2025-03-23T09:16:01', 'cpu_percent': 8.7, 'memory_percent': 3.1
            },
        ]

        demo_findings = [
            {
                'type': 'wrong_path',
                'severity': 'critical',
                'process': 'svchost.exe',
                'pid': 6672,
                'message': r'svchost.exe running from unexpected path: C:\Users\Public\Downloads\svchost.exe',
                'mitre_id': 'T1036.005',
                'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                'details': r'Expected: C:\Windows\System32\svchost.exe. Parent must be services.exe but parent PID 3456 is explorer.exe.'
            },
            {
                'type': 'excess_instances',
                'severity': 'high',
                'process': 'svchost.exe',
                'pid': 6672,
                'message': 'svchost.exe instance with non-services.exe parent (PPID: 3456 / explorer.exe)',
                'mitre_id': 'T1036.005',
                'mitre_name': 'Masquerading: Match Legitimate Name or Location',
                'details': 'Legitimate svchost.exe is always a child of services.exe. This instance was spawned by explorer.exe.'
            },
            {
                'type': 'suspicious_process',
                'severity': 'high',
                'process': 'powershell.exe',
                'pid': 8901,
                'message': 'PowerShell with encoded command and hidden window detected',
                'mitre_id': 'T1059.001',
                'mitre_name': 'Command and Scripting Interpreter: PowerShell',
                'details': 'Flags: -nop (no profile), -w hidden (hidden window), -enc (encoded command). Common in malware execution chains.'
            },
            {
                'type': 'suspicious_path',
                'severity': 'medium',
                'process': 'cmd.exe',
                'pid': 7788,
                'message': r'cmd.exe spawned by suspicious svchost.exe performing reconnaissance',
                'mitre_id': 'T1059.003',
                'mitre_name': 'Command and Scripting Interpreter: Windows Command Shell',
                'details': r'Command: whoami /all > C:\Users\Public\info.txt — reconnaissance output redirected to public folder.'
            },
        ]

        return {
            'processes': demo_processes,
            'findings': demo_findings,
            'process_count': len(demo_processes),
            'findings_count': len(demo_findings),
            'scan_time': datetime.now().isoformat(),
            'summary': {'critical': 1, 'high': 2, 'medium': 1, 'low': 0, 'info': 0}
        }
