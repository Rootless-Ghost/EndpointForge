"""
MITRE ATT&CK Mapping Module
Central reference for technique IDs used across all EndpointForge modules.
"""

# ──────────────────────────────────────────────
# PERSISTENCE TECHNIQUES
# ──────────────────────────────────────────────
PERSISTENCE = {
    'T1547.001': {
        'name': 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
        'description': 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.',
        'platforms': ['windows'],
        'severity': 'high'
    },
    'T1053.005': {
        'name': 'Scheduled Task/Job: Scheduled Task',
        'description': 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.',
        'platforms': ['windows'],
        'severity': 'high'
    },
    'T1053.003': {
        'name': 'Scheduled Task/Job: Cron',
        'description': 'Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.',
        'platforms': ['linux'],
        'severity': 'high'
    },
    'T1543.003': {
        'name': 'Create or Modify System Process: Windows Service',
        'description': 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.',
        'platforms': ['windows'],
        'severity': 'high'
    },
    'T1543.002': {
        'name': 'Create or Modify System Process: Systemd Service',
        'description': 'Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.',
        'platforms': ['linux'],
        'severity': 'high'
    },
    'T1546.004': {
        'name': 'Event Triggered Execution: Unix Shell Configuration Modification',
        'description': 'Adversaries may establish persistence through executing malicious commands triggered by a user\'s shell.',
        'platforms': ['linux'],
        'severity': 'medium'
    },
    'T1547.009': {
        'name': 'Boot or Logon Autostart Execution: Shortcut Modification',
        'description': 'Adversaries may create or modify shortcuts that can execute a program during system boot or user login.',
        'platforms': ['windows'],
        'severity': 'medium'
    },
    'T1546.015': {
        'name': 'Event Triggered Execution: Component Object Model Hijacking',
        'description': 'Adversaries may establish persistence by executing malicious content triggered by hijacked references to COM objects.',
        'platforms': ['windows'],
        'severity': 'high'
    },
}

# ──────────────────────────────────────────────
# EXECUTION TECHNIQUES
# ──────────────────────────────────────────────
EXECUTION = {
    'T1059.001': {
        'name': 'Command and Scripting Interpreter: PowerShell',
        'description': 'Adversaries may abuse PowerShell commands and scripts for execution.',
        'platforms': ['windows'],
        'severity': 'high'
    },
    'T1059.003': {
        'name': 'Command and Scripting Interpreter: Windows Command Shell',
        'description': 'Adversaries may abuse the Windows command shell (cmd.exe) for execution.',
        'platforms': ['windows'],
        'severity': 'medium'
    },
    'T1059.004': {
        'name': 'Command and Scripting Interpreter: Unix Shell',
        'description': 'Adversaries may abuse Unix shell commands and scripts for execution.',
        'platforms': ['linux'],
        'severity': 'medium'
    },
    'T1204.002': {
        'name': 'User Execution: Malicious File',
        'description': 'An adversary may rely upon a user opening a malicious file in order to gain execution.',
        'platforms': ['windows', 'linux'],
        'severity': 'high'
    },
}

# ──────────────────────────────────────────────
# DEFENSE EVASION TECHNIQUES
# ──────────────────────────────────────────────
DEFENSE_EVASION = {
    'T1036.005': {
        'name': 'Masquerading: Match Legitimate Name or Location',
        'description': 'Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing their malicious ones.',
        'platforms': ['windows', 'linux'],
        'severity': 'critical'
    },
    'T1070.001': {
        'name': 'Indicator Removal: Clear Windows Event Logs',
        'description': 'Adversaries may clear Windows Event Logs to hide the activity of an intrusion.',
        'platforms': ['windows'],
        'severity': 'critical'
    },
    'T1070.002': {
        'name': 'Indicator Removal: Clear Linux or Mac System Logs',
        'description': 'Adversaries may clear system logs to hide evidence of an intrusion.',
        'platforms': ['linux'],
        'severity': 'critical'
    },
    'T1112': {
        'name': 'Modify Registry',
        'description': 'Adversaries may interact with the Windows Registry to hide configuration information within Registry keys.',
        'platforms': ['windows'],
        'severity': 'high'
    },
}

# ──────────────────────────────────────────────
# DISCOVERY TECHNIQUES
# ──────────────────────────────────────────────
DISCOVERY = {
    'T1057': {
        'name': 'Process Discovery',
        'description': 'Adversaries may attempt to get information about running processes on a system.',
        'platforms': ['windows', 'linux'],
        'severity': 'low'
    },
    'T1049': {
        'name': 'System Network Connections Discovery',
        'description': 'Adversaries may attempt to get a listing of network connections to or from the compromised system.',
        'platforms': ['windows', 'linux'],
        'severity': 'low'
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'description': 'Adversaries may enumerate files and directories or may search in specific locations of a host.',
        'platforms': ['windows', 'linux'],
        'severity': 'low'
    },
}

# ──────────────────────────────────────────────
# COMMAND AND CONTROL TECHNIQUES
# ──────────────────────────────────────────────
COMMAND_AND_CONTROL = {
    'T1071.001': {
        'name': 'Application Layer Protocol: Web Protocols',
        'description': 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.',
        'platforms': ['windows', 'linux'],
        'severity': 'high'
    },
    'T1571': {
        'name': 'Non-Standard Port',
        'description': 'Adversaries may communicate using a protocol and port pairing that are typically not associated.',
        'platforms': ['windows', 'linux'],
        'severity': 'medium'
    },
}


def get_technique(technique_id):
    """Look up a MITRE ATT&CK technique by ID across all categories."""
    for category in [PERSISTENCE, EXECUTION, DEFENSE_EVASION, DISCOVERY, COMMAND_AND_CONTROL]:
        if technique_id in category:
            return category[technique_id]
    return None


def get_all_techniques():
    """Return all techniques as a flat dictionary."""
    all_techniques = {}
    for category in [PERSISTENCE, EXECUTION, DEFENSE_EVASION, DISCOVERY, COMMAND_AND_CONTROL]:
        all_techniques.update(category)
    return all_techniques


SEVERITY_LEVELS = {
    'critical': {'score': 4, 'color': '#ff1744', 'label': 'CRITICAL'},
    'high':     {'score': 3, 'color': '#ff6d00', 'label': 'HIGH'},
    'medium':   {'score': 2, 'color': '#ffd600', 'label': 'MEDIUM'},
    'low':      {'score': 1, 'color': '#00c853', 'label': 'LOW'},
    'info':     {'score': 0, 'color': '#448aff', 'label': 'INFO'},
}
