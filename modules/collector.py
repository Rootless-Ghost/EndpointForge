"""
Endpoint Data Collector
Handles all OS-specific live data collection for Windows and Linux.
This is the layer that actually talks to the system — psutil, WMI,
subprocess calls, /proc parsing, etc. All other modules consume
the normalized data this collector returns.
"""

import platform
import subprocess
import os
import json
from datetime import datetime


class EndpointCollector:
    """Cross-platform endpoint data collector."""

    def __init__(self):
        self.os_type = platform.system().lower()
        self._psutil = None
        self._load_psutil()

    def _load_psutil(self):
        """Try to import psutil; set to None if unavailable."""
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            self._psutil = None

    def psutil_available(self):
        return self._psutil is not None

    # ──────────────────────────────────────────────
    # SYSTEM INFO
    # ──────────────────────────────────────────────

    def collect_system_info(self):
        """Collect basic system information."""
        info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'os_release': platform.release(),
            'hostname': platform.node(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'collected_at': datetime.now().isoformat()
        }

        if self._psutil:
            info['boot_time'] = datetime.fromtimestamp(
                self._psutil.boot_time()).isoformat()
            info['cpu_count'] = self._psutil.cpu_count()
            mem = self._psutil.virtual_memory()
            info['total_memory_gb'] = round(mem.total / (1024**3), 2)
            info['memory_percent'] = mem.percent
            info['users'] = [
                {'name': u.name, 'terminal': u.terminal or 'N/A',
                 'host': u.host or 'local',
                 'started': datetime.fromtimestamp(u.started).isoformat()}
                for u in self._psutil.users()
            ]

        # Windows-specific
        if self.os_type == 'windows':
            info['domain'] = os.environ.get('USERDOMAIN', 'N/A')
            info['logon_server'] = os.environ.get('LOGONSERVER', 'N/A')

        return info

    # ──────────────────────────────────────────────
    # PROCESS COLLECTION
    # ──────────────────────────────────────────────

    def collect_processes(self):
        """
        Collect running processes with full detail.
        Returns list of process dicts with normalized fields.
        """
        if not self._psutil:
            return self._collect_processes_fallback()

        processes = []
        for proc in self._psutil.process_iter([
            'pid', 'ppid', 'name', 'exe', 'cmdline',
            'username', 'status', 'create_time',
            'cpu_percent', 'memory_percent'
        ]):
            try:
                pinfo = proc.info
                entry = {
                    'pid': pinfo['pid'],
                    'ppid': pinfo['ppid'],
                    'name': pinfo['name'] or 'Unknown',
                    'exe': pinfo['exe'] or 'N/A',
                    'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else 'N/A',
                    'username': pinfo['username'] or 'N/A',
                    'status': pinfo['status'],
                    'create_time': datetime.fromtimestamp(
                        pinfo['create_time']).isoformat() if pinfo['create_time'] else 'N/A',
                    'cpu_percent': pinfo['cpu_percent'] or 0,
                    'memory_percent': round(pinfo['memory_percent'], 2) if pinfo['memory_percent'] else 0
                }
                processes.append(entry)
            except (self._psutil.NoSuchProcess, self._psutil.AccessDenied,
                    self._psutil.ZombieProcess):
                continue

        return processes

    def _collect_processes_fallback(self):
        """Fallback process collection without psutil using OS commands."""
        processes = []

        if self.os_type == 'windows':
            try:
                # Use WMIC for process enumeration
                result = subprocess.run(
                    ['wmic', 'process', 'get',
                     'ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate',
                     '/format:csv'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    for line in lines[1:]:
                        parts = line.split(',')
                        if len(parts) >= 6:
                            processes.append({
                                'pid': int(parts[4]) if parts[4].isdigit() else 0,
                                'ppid': int(parts[3]) if parts[3].isdigit() else 0,
                                'name': parts[2] or 'Unknown',
                                'exe': parts[1] or 'N/A',
                                'cmdline': parts[0] or 'N/A',
                                'username': 'N/A',
                                'status': 'running',
                                'create_time': parts[5] if len(parts) > 5 else 'N/A',
                                'cpu_percent': 0,
                                'memory_percent': 0
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Try tasklist as secondary fallback
            if not processes:
                try:
                    result = subprocess.run(
                        ['tasklist', '/v', '/fo', 'csv'],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        for line in lines[1:]:
                            parts = line.strip('"').split('","')
                            if len(parts) >= 2:
                                processes.append({
                                    'pid': int(parts[1]) if parts[1].isdigit() else 0,
                                    'ppid': 0,
                                    'name': parts[0],
                                    'exe': 'N/A',
                                    'cmdline': 'N/A',
                                    'username': parts[6] if len(parts) > 6 else 'N/A',
                                    'status': parts[5] if len(parts) > 5 else 'Unknown',
                                    'create_time': 'N/A',
                                    'cpu_percent': 0,
                                    'memory_percent': 0
                                })
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        elif self.os_type == 'linux':
            try:
                result = subprocess.run(
                    ['ps', 'auxww', '--no-headers'],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            processes.append({
                                'pid': int(parts[1]) if parts[1].isdigit() else 0,
                                'ppid': 0,  # ps aux doesn't show ppid
                                'name': os.path.basename(parts[10].split()[0]),
                                'exe': parts[10].split()[0],
                                'cmdline': parts[10],
                                'username': parts[0],
                                'status': parts[7],
                                'create_time': parts[8],
                                'cpu_percent': float(parts[2]) if parts[2].replace('.', '').isdigit() else 0,
                                'memory_percent': float(parts[3]) if parts[3].replace('.', '').isdigit() else 0
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Enrich with ppid from /proc
            for proc in processes:
                try:
                    status_file = f'/proc/{proc["pid"]}/status'
                    if os.path.exists(status_file):
                        with open(status_file, 'r') as f:
                            for sline in f:
                                if sline.startswith('PPid:'):
                                    proc['ppid'] = int(sline.split(':')[1].strip())
                                    break
                except (PermissionError, FileNotFoundError, ValueError):
                    pass

        return processes

    # ──────────────────────────────────────────────
    # NETWORK COLLECTION
    # ──────────────────────────────────────────────

    def collect_network_connections(self):
        """Collect active network connections mapped to processes."""
        if not self._psutil:
            return self._collect_network_fallback()

        connections = []
        for conn in self._psutil.net_connections(kind='inet'):
            try:
                proc_name = 'Unknown'
                proc_pid = conn.pid or 0
                if conn.pid:
                    try:
                        proc = self._psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                        pass

                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A'
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'

                connections.append({
                    'pid': proc_pid,
                    'process': proc_name,
                    'local_address': local_addr,
                    'remote_address': remote_addr,
                    'status': conn.status,
                    'local_port': conn.laddr.port if conn.laddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'remote_ip': conn.raddr.ip if conn.raddr else None,
                    'protocol': 'TCP' if conn.type.name == 'SOCK_STREAM' else 'UDP'
                })
            except Exception:
                continue

        return connections

    def _collect_network_fallback(self):
        """Fallback network collection without psutil."""
        connections = []

        if self.os_type == 'windows':
            try:
                # netstat with process IDs
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 5 and parts[0] in ('TCP', 'UDP'):
                            protocol = parts[0]
                            local = parts[1]
                            remote = parts[2] if len(parts) > 2 else 'N/A'
                            state = parts[3] if protocol == 'TCP' and len(parts) > 3 else 'N/A'
                            pid = int(parts[-1]) if parts[-1].isdigit() else 0

                            local_parts = local.rsplit(':', 1)
                            remote_parts = remote.rsplit(':', 1) if remote != 'N/A' else ['N/A', None]

                            connections.append({
                                'pid': pid,
                                'process': self._get_process_name_by_pid(pid),
                                'local_address': local,
                                'remote_address': remote,
                                'status': state,
                                'local_port': int(local_parts[1]) if len(local_parts) > 1 and local_parts[1].isdigit() else None,
                                'remote_port': int(remote_parts[1]) if len(remote_parts) > 1 and remote_parts[1] and remote_parts[1].isdigit() else None,
                                'remote_ip': remote_parts[0] if remote_parts[0] != '*' else None,
                                'protocol': protocol
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        elif self.os_type == 'linux':
            try:
                # ss with process info
                result = subprocess.run(
                    ['ss', '-tulnp'],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) >= 5:
                            state = parts[1]
                            local = parts[4]
                            peer = parts[5] if len(parts) > 5 else 'N/A'

                            # Extract process info if available
                            proc_info = ''
                            for p in parts:
                                if 'users:' in p:
                                    proc_info = p
                                    break

                            local_parts = local.rsplit(':', 1)
                            peer_parts = peer.rsplit(':', 1)

                            connections.append({
                                'pid': 0,
                                'process': proc_info or 'Unknown',
                                'local_address': local,
                                'remote_address': peer,
                                'status': state,
                                'local_port': int(local_parts[1]) if len(local_parts) > 1 and local_parts[1].isdigit() else None,
                                'remote_port': int(peer_parts[1]) if len(peer_parts) > 1 and peer_parts[1].isdigit() else None,
                                'remote_ip': peer_parts[0] if peer_parts[0] not in ('*', '0.0.0.0') else None,
                                'protocol': parts[0].upper() if parts else 'TCP'
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return connections

    # ──────────────────────────────────────────────
    # WINDOWS-SPECIFIC COLLECTION
    # ──────────────────────────────────────────────

    def collect_windows_scheduled_tasks(self):
        """Collect Windows scheduled tasks with full details."""
        if self.os_type != 'windows':
            return []

        tasks = []
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/v'],
                capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace'
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    # Parse CSV header
                    headers = [h.strip('"') for h in lines[0].split('","')]
                    for line in lines[1:]:
                        values = [v.strip('"') for v in line.split('","')]
                        if len(values) >= 9:
                            tasks.append({
                                'hostname': values[0] if len(values) > 0 else '',
                                'task_name': values[1] if len(values) > 1 else '',
                                'next_run': values[2] if len(values) > 2 else '',
                                'status': values[3] if len(values) > 3 else '',
                                'logon_mode': values[4] if len(values) > 4 else '',
                                'last_run': values[5] if len(values) > 5 else '',
                                'last_result': values[6] if len(values) > 6 else '',
                                'author': values[7] if len(values) > 7 else '',
                                'task_to_run': values[8] if len(values) > 8 else '',
                                'run_as_user': values[14] if len(values) > 14 else '',
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            tasks.append({'error': str(e)})

        return tasks

    def collect_windows_services(self):
        """Collect Windows services with binary paths."""
        if self.os_type != 'windows':
            return []

        services = []

        # Try PowerShell first (more reliable than WMIC)
        try:
            ps_cmd = (
                'Get-WmiObject Win32_Service | '
                'Select-Object Name, DisplayName, State, StartMode, PathName, StartName | '
                'ConvertTo-Json'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for svc in data:
                    services.append({
                        'name': svc.get('Name', ''),
                        'display_name': svc.get('DisplayName', ''),
                        'state': svc.get('State', ''),
                        'start_mode': svc.get('StartMode', ''),
                        'path': svc.get('PathName', ''),
                        'run_as': svc.get('StartName', '')
                    })
                return services
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        # Fallback to sc query
        try:
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                current_service = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            services.append(current_service)
                        current_service = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('DISPLAY_NAME:'):
                        current_service['display_name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('STATE'):
                        parts = line.split()
                        current_service['state'] = parts[-1] if parts else 'Unknown'
                if current_service:
                    services.append(current_service)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return services

    def collect_windows_startup_items(self):
        """Collect items from Windows startup folders."""
        if self.os_type != 'windows':
            return []

        items = []
        startup_paths = []

        # User startup
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            startup_paths.append(
                os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup')
            )

        # All users startup
        programdata = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
        startup_paths.append(
            os.path.join(programdata, r'Microsoft\Windows\Start Menu\Programs\Startup')
        )

        for startup_dir in startup_paths:
            if os.path.exists(startup_dir):
                for item in os.listdir(startup_dir):
                    filepath = os.path.join(startup_dir, item)
                    try:
                        stat = os.stat(filepath)
                        items.append({
                            'name': item,
                            'path': filepath,
                            'folder': startup_dir,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'extension': os.path.splitext(item)[1].lower()
                        })
                    except OSError:
                        continue

        return items

    def collect_windows_registry_values(self, key_path):
        """Read values from a specific Windows registry key."""
        if self.os_type != 'windows':
            return []

        entries = []

        # Try winreg module first
        try:
            import winreg

            hive_map = {
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
            }

            parts = key_path.split('\\', 1)
            hive = hive_map.get(parts[0])
            subkey = parts[1] if len(parts) > 1 else ''

            if hive is None:
                return entries

            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        entries.append({
                            'key': key_path,
                            'name': name,
                            'value': str(value),
                            'type': reg_type,
                            'type_name': self._reg_type_name(reg_type)
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, PermissionError):
                pass

            return entries
        except ImportError:
            pass

        # Fallback to reg query
        try:
            result = subprocess.run(
                ['reg', 'query', key_path.replace('HKLM\\', 'HKLM\\').replace('HKCU\\', 'HKCU\\')],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('HK') and '    ' in line:
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            entries.append({
                                'key': key_path,
                                'name': parts[0],
                                'value': parts[2],
                                'type': 0,
                                'type_name': parts[1]
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return entries

    # ──────────────────────────────────────────────
    # LINUX-SPECIFIC COLLECTION
    # ──────────────────────────────────────────────

    def collect_linux_cron_jobs(self):
        """Collect all cron jobs — system-level and per-user."""
        if self.os_type != 'linux':
            return []

        cron_entries = []

        # System crontab
        if os.path.exists('/etc/crontab'):
            try:
                with open('/etc/crontab', 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            cron_entries.append({
                                'source': '/etc/crontab',
                                'line_number': line_num,
                                'content': line,
                                'type': 'system'
                            })
            except PermissionError:
                cron_entries.append({
                    'source': '/etc/crontab',
                    'error': 'Permission denied',
                    'type': 'system'
                })

        # /etc/cron.d/ directory
        cron_d = '/etc/cron.d/'
        if os.path.exists(cron_d):
            for cron_file in os.listdir(cron_d):
                filepath = os.path.join(cron_d, cron_file)
                try:
                    with open(filepath, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                cron_entries.append({
                                    'source': filepath,
                                    'line_number': line_num,
                                    'content': line,
                                    'type': 'cron.d'
                                })
                except PermissionError:
                    pass

        # Current user crontab
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line_num, line in enumerate(result.stdout.strip().split('\n'), 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        cron_entries.append({
                            'source': 'user crontab',
                            'line_number': line_num,
                            'content': line,
                            'type': 'user'
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Enumerate other users' crontabs if running as root
        crontab_dirs = ['/var/spool/cron/crontabs/', '/var/spool/cron/']
        for cron_dir in crontab_dirs:
            if os.path.exists(cron_dir):
                try:
                    for username in os.listdir(cron_dir):
                        filepath = os.path.join(cron_dir, username)
                        if os.path.isfile(filepath):
                            try:
                                with open(filepath, 'r') as f:
                                    for line_num, line in enumerate(f, 1):
                                        line = line.strip()
                                        if line and not line.startswith('#'):
                                            cron_entries.append({
                                                'source': filepath,
                                                'user': username,
                                                'line_number': line_num,
                                                'content': line,
                                                'type': 'user_spool'
                                            })
                            except PermissionError:
                                pass
                except PermissionError:
                    pass

        return cron_entries

    def collect_linux_systemd_services(self):
        """Collect systemd service unit files and their status."""
        if self.os_type != 'linux':
            return []

        services = []
        try:
            result = subprocess.run(
                ['systemctl', 'list-unit-files', '--type=service',
                 '--no-pager', '--no-legend'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].endswith('.service'):
                        svc_name = parts[0]
                        svc_state = parts[1]

                        # Get ExecStart for enabled/running services
                        exec_start = None
                        if svc_state in ('enabled', 'static'):
                            try:
                                show_result = subprocess.run(
                                    ['systemctl', 'show', svc_name,
                                     '--property=ExecStart,MainPID,ActiveState'],
                                    capture_output=True, text=True, timeout=5
                                )
                                if show_result.returncode == 0:
                                    for prop_line in show_result.stdout.strip().split('\n'):
                                        if prop_line.startswith('ExecStart='):
                                            exec_start = prop_line.split('=', 1)[1]
                            except (subprocess.TimeoutExpired, FileNotFoundError):
                                pass

                        services.append({
                            'name': svc_name,
                            'state': svc_state,
                            'exec_start': exec_start or 'N/A'
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return services

    def collect_linux_shell_configs(self):
        """Collect contents of shell configuration files."""
        if self.os_type != 'linux':
            return []

        configs = []
        shell_files = [
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.bash_profile'),
            os.path.expanduser('~/.profile'),
            os.path.expanduser('~/.zshrc'),
            '/etc/profile',
            '/etc/bash.bashrc',
        ]

        for config_file in shell_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        lines = []
                        for line_num, line in enumerate(f, 1):
                            stripped = line.strip()
                            if stripped and not stripped.startswith('#'):
                                lines.append({
                                    'line_number': line_num,
                                    'content': stripped
                                })
                    configs.append({
                        'file': config_file,
                        'lines': lines,
                        'line_count': len(lines),
                        'readable': True
                    })
                except PermissionError:
                    configs.append({
                        'file': config_file,
                        'lines': [],
                        'line_count': 0,
                        'readable': False
                    })

        return configs

    # ──────────────────────────────────────────────
    # UTILITIES
    # ──────────────────────────────────────────────

    def _get_process_name_by_pid(self, pid):
        """Look up process name by PID."""
        if not pid:
            return 'Unknown'

        if self._psutil:
            try:
                return self._psutil.Process(pid).name()
            except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                return 'Unknown'

        # Fallback
        if self.os_type == 'windows':
            try:
                result = subprocess.run(
                    ['tasklist', '/fi', f'PID eq {pid}', '/fo', 'csv', '/nh'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split(',')
                    if parts:
                        return parts[0].strip('"')
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        elif self.os_type == 'linux':
            try:
                comm_file = f'/proc/{pid}/comm'
                if os.path.exists(comm_file):
                    with open(comm_file, 'r') as f:
                        return f.read().strip()
            except (PermissionError, FileNotFoundError):
                pass

        return 'Unknown'

    def _reg_type_name(self, reg_type):
        """Convert registry type integer to name."""
        type_names = {
            0: 'REG_NONE',
            1: 'REG_SZ',
            2: 'REG_EXPAND_SZ',
            3: 'REG_BINARY',
            4: 'REG_DWORD',
            7: 'REG_MULTI_SZ',
            11: 'REG_QWORD'
        }
        return type_names.get(reg_type, f'TYPE_{reg_type}')
