"""
Registry Modifications Monitor (Windows Only)
Monitors key registry locations for persistence entries,
suspicious modifications, and known-bad patterns.
"""

import platform
from datetime import datetime


# Registry keys commonly abused for persistence
PERSISTENCE_REGISTRY_KEYS = {
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run': {
        'description': 'Programs that run at startup for all users',
        'mitre_id': 'T1547.001',
        'risk': 'high'
    },
    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run': {
        'description': 'Programs that run at startup for current user',
        'mitre_id': 'T1547.001',
        'risk': 'high'
    },
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce': {
        'description': 'Programs that run once at next startup (all users)',
        'mitre_id': 'T1547.001',
        'risk': 'high'
    },
    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce': {
        'description': 'Programs that run once at next startup (current user)',
        'mitre_id': 'T1547.001',
        'risk': 'high'
    },
    r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon': {
        'description': 'Winlogon shell and userinit — controls what runs at logon',
        'mitre_id': 'T1547.001',
        'risk': 'critical'
    },
    r'HKLM\SYSTEM\CurrentControlSet\Services': {
        'description': 'Windows service registration — new services for persistence',
        'mitre_id': 'T1543.003',
        'risk': 'high'
    },
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders': {
        'description': 'Shell folder redirections — can redirect startup folder',
        'mitre_id': 'T1547.009',
        'risk': 'medium'
    },
    r'HKLM\SOFTWARE\Classes\CLSID': {
        'description': 'COM object registration — COM hijacking for persistence',
        'mitre_id': 'T1546.015',
        'risk': 'high'
    },
    r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options': {
        'description': 'IFEO debugger keys — can redirect legitimate executables',
        'mitre_id': 'T1546.012',
        'risk': 'critical'
    },
    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run': {
        'description': 'Policy-based autorun — less commonly monitored',
        'mitre_id': 'T1547.001',
        'risk': 'high'
    },
    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders': {
        'description': 'User shell folder paths — startup folder redirection',
        'mitre_id': 'T1547.009',
        'risk': 'medium'
    },
}

# Suspicious registry value patterns
SUSPICIOUS_VALUE_PATTERNS = [
    {'pattern': 'powershell', 'description': 'PowerShell execution in registry value', 'severity': 'high'},
    {'pattern': 'cmd /c', 'description': 'Command shell execution in registry value', 'severity': 'high'},
    {'pattern': 'wscript', 'description': 'Windows Script Host in registry value', 'severity': 'high'},
    {'pattern': 'cscript', 'description': 'Console Script Host in registry value', 'severity': 'high'},
    {'pattern': 'mshta', 'description': 'MSHTA execution in registry value', 'severity': 'high'},
    {'pattern': 'regsvr32', 'description': 'Regsvr32 execution in registry value', 'severity': 'medium'},
    {'pattern': 'rundll32', 'description': 'Rundll32 execution in registry value', 'severity': 'medium'},
    {'pattern': r'\temp\\', 'description': 'Executable path in Temp directory', 'severity': 'high'},
    {'pattern': r'\appdata\\', 'description': 'Executable path in AppData', 'severity': 'medium'},
    {'pattern': r'\public\\', 'description': 'Executable path in Public folder', 'severity': 'high'},
    {'pattern': '-enc', 'description': 'Encoded PowerShell command', 'severity': 'critical'},
    {'pattern': '-nop', 'description': 'PowerShell no-profile flag', 'severity': 'high'},
    {'pattern': 'downloadstring', 'description': 'PowerShell download cradle', 'severity': 'critical'},
    {'pattern': 'invoke-expression', 'description': 'PowerShell Invoke-Expression (IEX)', 'severity': 'critical'},
    {'pattern': 'base64', 'description': 'Base64 encoded content', 'severity': 'high'},
]


class RegistryMonitor:
    """Windows registry modification monitor."""

    def __init__(self):
        self.os_type = platform.system().lower()

    def scan(self):
        """Scan Windows registry for suspicious entries using the endpoint collector."""
        if self.os_type != 'windows':
            return {
                'os_supported': False,
                'message': 'Registry analysis is only available on Windows.',
                'findings': [],
                'summary': {}
            }

        from modules.collector import EndpointCollector
        collector = EndpointCollector()

        findings = []
        entries = []

        for reg_path, reg_info in PERSISTENCE_REGISTRY_KEYS.items():
            key_entries = collector.collect_windows_registry_values(reg_path)
            for entry in key_entries:
                entries.append(entry)
                # Check against suspicious patterns
                value_str = str(entry.get('value', '')).lower()
                for pattern in SUSPICIOUS_VALUE_PATTERNS:
                    if pattern['pattern'] in value_str:
                        findings.append({
                            'type': 'suspicious_registry_value',
                            'severity': pattern['severity'],
                            'registry_key': reg_path,
                            'value_name': entry.get('name', 'Unknown'),
                            'message': f'{pattern["description"]} in {reg_path}',
                            'mitre_id': reg_info['mitre_id'],
                            'mitre_name': self._get_mitre_name(reg_info['mitre_id']),
                            'details': f'Value: {entry.get("value", "N/A")[:200]}'
                        })

        return {
            'os_supported': True,
            'entries': entries,
            'entries_count': len(entries),
            'findings': findings,
            'findings_count': len(findings),
            'keys_scanned': len(PERSISTENCE_REGISTRY_KEYS),
            'scan_time': datetime.now().isoformat(),
            'summary': self._build_summary(findings)
        }

    def _read_registry_key(self, key_path):
        """Read values from a registry key."""
        entries = []
        try:
            import winreg

            # Parse hive and subkey
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
                            'type': reg_type
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, PermissionError):
                pass

        except ImportError:
            pass

        return entries

    def _get_mitre_name(self, technique_id):
        """Get MITRE technique name from ID."""
        from modules.mitre_mapping import get_technique
        tech = get_technique(technique_id)
        return tech['name'] if tech else technique_id

    def _build_summary(self, findings):
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_demo_data(self):
        """Return realistic simulated registry data for portfolio demos."""
        demo_entries = [
            {
                'key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'SecurityHealth',
                'value': r'%ProgramFiles%\Windows Defender\MSASCuiL.exe',
                'type': 2, 'status': 'legitimate'
            },
            {
                'key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'VMware User Process',
                'value': r'"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr',
                'type': 1, 'status': 'legitimate'
            },
            {
                'key': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'OneDrive',
                'value': r'"C:\Users\analyst\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background',
                'type': 1, 'status': 'legitimate'
            },
            # ---- SUSPICIOUS ENTRIES ----
            {
                'key': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'WindowsUpdate',
                'value': r'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGU...',
                'type': 1, 'status': 'suspicious'
            },
            {
                'key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'SystemUpdater',
                'value': r'C:\Users\Public\Downloads\svchost.exe',
                'type': 1, 'status': 'suspicious'
            },
            {
                'key': r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe',
                'name': 'Debugger',
                'value': r'C:\Windows\System32\cmd.exe',
                'type': 1, 'status': 'suspicious'
            },
            {
                'key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'name': 'Cleanup',
                'value': r'cmd /c del /f /q C:\Windows\Temp\*.log && C:\ProgramData\updater.exe',
                'type': 1, 'status': 'suspicious'
            },
        ]

        demo_findings = [
            {
                'type': 'suspicious_registry_value',
                'severity': 'critical',
                'registry_key': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'value_name': 'WindowsUpdate',
                'message': 'Encoded PowerShell command in HKCU Run key',
                'mitre_id': 'T1547.001',
                'mitre_name': 'Boot or Logon Autostart Execution: Registry Run Keys',
                'details': 'Value contains -nop -w hidden -enc flags. Encoded PowerShell execution at user logon. Classic persistence mechanism.'
            },
            {
                'type': 'suspicious_registry_value',
                'severity': 'high',
                'registry_key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'value_name': 'SystemUpdater',
                'message': r'Executable in Public\Downloads referenced by HKLM Run key',
                'mitre_id': 'T1547.001',
                'mitre_name': 'Boot or Logon Autostart Execution: Registry Run Keys',
                'details': r'Path: C:\Users\Public\Downloads\svchost.exe — masquerading as svchost.exe from a non-standard location.'
            },
            {
                'type': 'suspicious_registry_value',
                'severity': 'critical',
                'registry_key': r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe',
                'value_name': 'Debugger',
                'message': 'IFEO debugger hijack detected on sethc.exe (Sticky Keys)',
                'mitre_id': 'T1546.012',
                'mitre_name': 'Event Triggered Execution: Image File Execution Options Injection',
                'details': r'sethc.exe redirected to cmd.exe. Classic accessibility feature backdoor — pressing Shift 5x at login screen launches cmd.exe as SYSTEM.'
            },
            {
                'type': 'suspicious_registry_value',
                'severity': 'high',
                'registry_key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'value_name': 'Cleanup',
                'message': 'Command shell execution with log deletion in RunOnce key',
                'mitre_id': 'T1547.001',
                'mitre_name': 'Boot or Logon Autostart Execution: Registry Run Keys',
                'details': 'Deletes temp logs then executes updater.exe from ProgramData. Anti-forensics combined with persistence.'
            },
        ]

        return {
            'os_supported': True,
            'entries': demo_entries,
            'entries_count': len(demo_entries),
            'findings': demo_findings,
            'findings_count': len(demo_findings),
            'keys_scanned': len(PERSISTENCE_REGISTRY_KEYS),
            'scan_time': datetime.now().isoformat(),
            'summary': {'critical': 2, 'high': 2, 'medium': 0, 'low': 0, 'info': 0}
        }
