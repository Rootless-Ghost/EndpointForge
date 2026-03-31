"""
File System Integrity Monitor (FIM)
Baselines critical directories, detects creation/modification/deletion,
and flags unauthorized changes with hash comparison.
"""

import os
import hashlib
import json
import platform
from datetime import datetime
from pathlib import Path


# Default monitored directories by OS
DEFAULT_PATHS = {
    'windows': [
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
        r'C:\Program Files',
        r'C:\Program Files (x86)',
        r'C:\Users\Public',
        r'C:\ProgramData',
    ],
    'linux': [
        '/etc',
        '/bin',
        '/sbin',
        '/usr/bin',
        '/usr/sbin',
        '/usr/local/bin',
        '/tmp',
        '/var/tmp',
        '/dev/shm',
    ]
}

# High-value files to specifically monitor
CRITICAL_FILES = {
    'windows': [
        r'C:\Windows\System32\drivers\etc\hosts',
        r'C:\Windows\System32\config\SAM',
        r'C:\Windows\System32\config\SYSTEM',
        r'C:\Windows\System32\config\SECURITY',
    ],
    'linux': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/etc/crontab',
        '/etc/hosts',
        '/etc/resolv.conf',
    ]
}

# File extensions commonly associated with malware
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf',
    '.hta', '.scr', '.pif', '.com', '.msi', '.jar',
    '.sh', '.elf', '.bin', '.so'
]


class FileSystemMonitor:
    """Cross-platform file system integrity monitor."""

    def __init__(self):
        self.os_type = platform.system().lower()
        self.baseline_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'baselines')

    def scan(self, mode='baseline', custom_paths=None):
        """
        Run filesystem scan.
        mode: 'baseline' to create new baseline, 'check' to compare against existing
        custom_paths: optional list of additional paths to monitor
        """
        paths = DEFAULT_PATHS.get(self.os_type, [])
        if custom_paths:
            paths.extend(custom_paths)

        if mode == 'baseline':
            return self._create_baseline(paths)
        else:
            return self._check_integrity(paths)

    def _hash_file(self, filepath):
        """Calculate SHA-256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError):
            return None

    def _scan_directory(self, directory, max_depth=2, max_files=500):
        """Scan a directory and return file metadata."""
        files = {}
        file_count = 0

        try:
            for root, dirs, filenames in os.walk(directory):
                depth = root.replace(directory, '').count(os.sep)
                if depth >= max_depth:
                    dirs.clear()
                    continue

                for filename in filenames:
                    if file_count >= max_files:
                        break

                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        files[filepath] = {
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'hash': self._hash_file(filepath),
                            'extension': os.path.splitext(filename)[1].lower()
                        }
                        file_count += 1
                    except (PermissionError, OSError, FileNotFoundError):
                        continue

        except (PermissionError, OSError):
            pass

        return files

    def _create_baseline(self, paths):
        """Create a new baseline snapshot of monitored directories."""
        baseline = {
            'created': datetime.now().isoformat(),
            'os': self.os_type,
            'paths': {},
            'critical_files': {}
        }

        total_files = 0
        for path in paths:
            if os.path.exists(path):
                files = self._scan_directory(path)
                baseline['paths'][path] = files
                total_files += len(files)

        # Baseline critical files
        for crit_file in CRITICAL_FILES.get(self.os_type, []):
            if os.path.exists(crit_file):
                baseline['critical_files'][crit_file] = {
                    'hash': self._hash_file(crit_file),
                    'modified': datetime.fromtimestamp(
                        os.stat(crit_file).st_mtime).isoformat(),
                    'size': os.stat(crit_file).st_size
                }

        # Save baseline
        baseline_file = os.path.join(self.baseline_dir, f'fim_baseline_{self.os_type}.json')
        os.makedirs(self.baseline_dir, exist_ok=True)
        with open(baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        return {
            'mode': 'baseline_created',
            'paths_scanned': len(paths),
            'total_files': total_files,
            'critical_files': len(baseline['critical_files']),
            'baseline_file': baseline_file,
            'scan_time': datetime.now().isoformat(),
            'findings': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 1}
        }

    def _check_integrity(self, paths):
        """Compare current state against baseline and report changes."""
        baseline_file = os.path.join(self.baseline_dir, f'fim_baseline_{self.os_type}.json')

        if not os.path.exists(baseline_file):
            return {
                'mode': 'no_baseline',
                'message': 'No baseline found. Create a baseline first.',
                'findings': [{
                    'type': 'no_baseline',
                    'severity': 'info',
                    'message': 'No FIM baseline exists. Run a baseline scan first to establish known-good state.',
                    'mitre_id': None,
                    'mitre_name': None,
                    'details': 'A baseline captures file hashes and metadata for comparison on subsequent scans.'
                }],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 1}
            }

        with open(baseline_file, 'r') as f:
            baseline = json.load(f)

        findings = []
        changes = {'new': [], 'modified': [], 'deleted': []}

        # Check each baselined path
        for path, baselined_files in baseline.get('paths', {}).items():
            if not os.path.exists(path):
                findings.append({
                    'type': 'directory_missing',
                    'severity': 'critical',
                    'message': f'Monitored directory missing: {path}',
                    'mitre_id': 'T1070.002' if self.os_type == 'linux' else 'T1070.001',
                    'mitre_name': 'Indicator Removal',
                    'details': 'An entire monitored directory has been removed.'
                })
                continue

            current_files = self._scan_directory(path)

            # Check for new files
            for filepath in current_files:
                if filepath not in baselined_files:
                    ext = current_files[filepath]['extension']
                    severity = 'high' if ext in SUSPICIOUS_EXTENSIONS else 'medium'
                    changes['new'].append(filepath)
                    findings.append({
                        'type': 'new_file',
                        'severity': severity,
                        'message': f'New file detected: {filepath}',
                        'mitre_id': 'T1204.002',
                        'mitre_name': 'User Execution: Malicious File',
                        'details': f'Size: {current_files[filepath]["size"]} bytes | Modified: {current_files[filepath]["modified"]} | Extension: {ext}'
                    })

            # Check for modified files
            for filepath, baseline_meta in baselined_files.items():
                if filepath in current_files:
                    current_meta = current_files[filepath]
                    if (baseline_meta.get('hash') and current_meta.get('hash') and
                            baseline_meta['hash'] != current_meta['hash']):
                        changes['modified'].append(filepath)
                        findings.append({
                            'type': 'file_modified',
                            'severity': 'high',
                            'message': f'File hash changed: {filepath}',
                            'mitre_id': 'T1112' if 'registry' in filepath.lower() else 'T1083',
                            'mitre_name': 'File Modification Detected',
                            'details': f'Old hash: {baseline_meta["hash"][:16]}... | New hash: {current_meta["hash"][:16]}...'
                        })
                elif os.path.exists(filepath) is False:
                    changes['deleted'].append(filepath)
                    findings.append({
                        'type': 'file_deleted',
                        'severity': 'medium',
                        'message': f'File removed since baseline: {filepath}',
                        'mitre_id': 'T1070.001',
                        'mitre_name': 'Indicator Removal',
                        'details': f'Original size: {baseline_meta["size"]} bytes | Was last modified: {baseline_meta["modified"]}'
                    })

        # Check critical files
        for crit_file, crit_baseline in baseline.get('critical_files', {}).items():
            if os.path.exists(crit_file):
                current_hash = self._hash_file(crit_file)
                if current_hash and crit_baseline.get('hash') and current_hash != crit_baseline['hash']:
                    findings.append({
                        'type': 'critical_file_modified',
                        'severity': 'critical',
                        'message': f'Critical system file modified: {crit_file}',
                        'mitre_id': 'T1112',
                        'mitre_name': 'Modify System Configuration',
                        'details': f'This is a high-value system file. Unauthorized modification may indicate compromise.'
                    })
            else:
                findings.append({
                    'type': 'critical_file_missing',
                    'severity': 'critical',
                    'message': f'Critical system file missing: {crit_file}',
                    'mitre_id': 'T1070.001',
                    'mitre_name': 'Indicator Removal',
                    'details': 'A critical system file has been removed. This may indicate tampering.'
                })

        return {
            'mode': 'integrity_check',
            'changes': changes,
            'new_files': len(changes['new']),
            'modified_files': len(changes['modified']),
            'deleted_files': len(changes['deleted']),
            'findings': findings,
            'findings_count': len(findings),
            'scan_time': datetime.now().isoformat(),
            'baseline_date': baseline.get('created', 'Unknown'),
            'summary': self._build_summary(findings)
        }

    def _build_summary(self, findings):
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_demo_data(self):
        """Return realistic simulated FIM data for portfolio demos."""
        demo_findings = [
            {
                'type': 'critical_file_modified',
                'severity': 'critical',
                'message': r'Critical system file modified: C:\Windows\System32\drivers\etc\hosts',
                'mitre_id': 'T1112',
                'mitre_name': 'Modify System Configuration',
                'details': 'Hosts file modified — potential DNS redirection. Old hash: a3f2b8c1d9e4... | New hash: 7d1e9f3a2b8c...'
            },
            {
                'type': 'new_file',
                'severity': 'high',
                'message': r'New file detected: C:\Users\Public\Downloads\update.exe',
                'mitre_id': 'T1204.002',
                'mitre_name': 'User Execution: Malicious File',
                'details': 'Size: 245760 bytes | Modified: 2025-03-23T09:14:33 | Extension: .exe | Suspicious location.'
            },
            {
                'type': 'new_file',
                'severity': 'high',
                'message': r'New file detected: C:\Windows\Temp\payload.ps1',
                'mitre_id': 'T1204.002',
                'mitre_name': 'User Execution: Malicious File',
                'details': 'Size: 8432 bytes | Modified: 2025-03-23T09:15:01 | Extension: .ps1 | PowerShell script in Temp directory.'
            },
            {
                'type': 'file_modified',
                'severity': 'high',
                'message': r'File hash changed: C:\Windows\System32\svchost.exe',
                'mitre_id': 'T1036.005',
                'mitre_name': 'Masquerading',
                'details': 'System binary hash has changed. Possible replacement with malicious binary. Old hash: 9a8b7c6d5e4f... | New hash: 1f2e3d4c5b6a...'
            },
            {
                'type': 'file_deleted',
                'severity': 'medium',
                'message': r'File removed since baseline: C:\Windows\System32\LogFiles\recent.evtx',
                'mitre_id': 'T1070.001',
                'mitre_name': 'Indicator Removal: Clear Windows Event Logs',
                'details': 'Event log file removed. May indicate log tampering to cover tracks.'
            },
            {
                'type': 'new_file',
                'severity': 'medium',
                'message': r'New file detected: C:\ProgramData\Microsoft\updater.dll',
                'mitre_id': 'T1204.002',
                'mitre_name': 'User Execution: Malicious File',
                'details': 'Size: 524288 bytes | Modified: 2025-03-23T09:16:15 | Extension: .dll | DLL in ProgramData.'
            },
        ]

        return {
            'mode': 'integrity_check',
            'changes': {
                'new': [
                    r'C:\Users\Public\Downloads\update.exe',
                    r'C:\Windows\Temp\payload.ps1',
                    r'C:\ProgramData\Microsoft\updater.dll'
                ],
                'modified': [
                    r'C:\Windows\System32\drivers\etc\hosts',
                    r'C:\Windows\System32\svchost.exe'
                ],
                'deleted': [
                    r'C:\Windows\System32\LogFiles\recent.evtx'
                ]
            },
            'new_files': 3,
            'modified_files': 2,
            'deleted_files': 1,
            'findings': demo_findings,
            'findings_count': len(demo_findings),
            'scan_time': datetime.now().isoformat(),
            'baseline_date': '2025-03-22T20:00:00',
            'summary': {'critical': 1, 'high': 3, 'medium': 2, 'low': 0, 'info': 0}
        }
