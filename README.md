# EndpointForge

<div align="center">
**Cross-Platform Endpoint Security Monitor**

A lightweight host-based intrusion detection and endpoint triage tool with MITRE ATT&CK mapping for Windows and Linux systems. Built with Python and Flask.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0+-green?style=flat-square&logo=flask)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-cyan?style=flat-square)
 </div>
---

## Overview

EndpointForge monitors endpoints across four core security pillars, detecting suspicious activity and mapping all findings to MITRE ATT&CK techniques:

| Pillar | Windows | Linux | Description |
|--------|---------|-------|-------------|
| **Process Execution** | ✅ | ✅ | Process enumeration, parent-child hierarchy, core process baseline validation |
| **File System Integrity** | ✅ | ✅ | FIM with SHA-256 hashing, critical file monitoring, change detection |
| **Network Connections** | ✅ | ✅ | Active connections mapped to processes, suspicious port detection |
| **Registry Modifications** | ✅ | — | Persistence key monitoring, suspicious value pattern detection |

### Additional Detection

- **Persistence Mechanisms** — Windows autoruns, scheduled tasks, services, startup folders / Linux cron jobs, systemd services, shell configs, init scripts
- **MITRE ATT&CK Mapping** — Every finding tagged with technique IDs
- **Severity Scoring** — Critical, High, Medium, Low, Info
- **Report Generation** — Markdown and JSON export

## Features

### Process Execution Analysis
- Enumerate running processes with PID, PPID, command-line arguments, and user context
- Build parent-child process hierarchy
- **Windows Core Process Baselines** — Validate that System, smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe, svchost.exe, and explorer.exe are running from correct paths with expected parent processes and instance counts
- Flag suspicious process names (known offensive tools) and unusual execution paths

### File System Integrity Monitoring (FIM)
- Baseline critical directories with SHA-256 file hashes
- Detect new, modified, and deleted files on subsequent scans
- Monitor critical system files (hosts, SAM, shadow, sudoers, sshd_config)
- Flag suspicious file extensions (.exe, .ps1, .bat, .sh, .elf in monitored paths)

### Network Connection Analysis
- Map all active connections to their owning process
- Detect connections on known suspicious ports (4444, 5555, 6666, 9999, etc.)
- Flag unexpected processes with external connections
- Identify high-risk listeners (shells, netcat)

### Registry Modification Monitoring (Windows)
- Scan Run/RunOnce keys, Winlogon, Services, IFEO, COM CLSIDs
- Detect encoded PowerShell, download cradles, suspicious paths in registry values
- Flag Image File Execution Options (IFEO) debugger hijacking

### Persistence Detection
- **Windows:** Registry run keys, scheduled tasks, services, startup folders
- **Linux:** Cron jobs (system + user), systemd services, shell configs (.bashrc, .profile, .zshrc), rc.local
- Pattern matching for suspicious indicators across all persistence locations

### Reporting
- Markdown reports with executive summary, findings by module, MITRE mapping table, and recommendations
- JSON export for SIEM ingestion and automation pipelines
- Severity-sorted findings across all modules

## Demo Mode

EndpointForge includes a **demo mode** with realistic simulated endpoint data for portfolio demonstrations. Demo data includes a simulated Windows compromise scenario with:

- Masquerading svchost.exe running from a user-writable directory
- Encoded PowerShell execution with hidden window
- Reverse shell connections on port 4444
- Netcat bind shell listener
- Modified hosts file and system binaries
- IFEO Sticky Keys backdoor
- Malicious scheduled tasks and cron jobs
- Persistence via registry run keys and startup folders

## Installation

```bash
git clone https://github.com/Rootless-Ghost/EndpointForge.git
cd EndpointForge
pip install -r requirements.txt
python app.py
```

Navigate to `http://localhost:5000` in your browser.

### Requirements

- Python 3.10+
- Flask 3.0+
- psutil 5.9+ (for live scanning)

## Usage

### Live Scanning
Run EndpointForge on the target endpoint and use the web interface to trigger scans against the live system.

### Demo Mode
Click **"Load Demo Data"** on any page to view simulated scan results without running on a live system.

### Report Export
After running a scan (live or demo), navigate to **Reports & Export** to generate Markdown or JSON reports.

## Project Structure

```
EndpointForge/
├── app.py                      # Flask application and API routes
├── requirements.txt
├── modules/
│   ├── process_monitor.py      # Process execution analysis
│   ├── network_monitor.py      # Network connection monitoring
│   ├── filesystem_monitor.py   # File integrity monitoring
│   ├── registry_monitor.py     # Registry modification detection
│   ├── persistence_monitor.py  # Persistence mechanism detection
│   ├── report_generator.py     # Markdown/JSON report generation
│   └── mitre_mapping.py        # MITRE ATT&CK technique reference
├── templates/
│   ├── base.html               # Base layout with sidebar navigation
│   ├── dashboard.html          # Main dashboard
│   ├── processes.html          # Process analysis page
│   ├── network.html            # Network analysis page
│   ├── filesystem.html         # FIM page
│   ├── registry.html           # Registry analysis page
│   ├── persistence.html        # Persistence detection page
│   └── reports.html            # Report generation page
├── static/
│   ├── css/style.css           # Dark theme stylesheet
│   └── js/main.js              # Frontend JavaScript
├── baselines/                  # FIM baseline storage
└── exports/                    # Generated reports
```

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| **Persistence** | T1547.001, T1053.005, T1053.003, T1543.003, T1543.002, T1546.004, T1546.015, T1547.009 |
| **Execution** | T1059.001, T1059.003, T1059.004, T1204.002 |
| **Defense Evasion** | T1036.005, T1070.001, T1070.002, T1112 |
| **Discovery** | T1057, T1049, T1083 |
| **Command and Control** | T1071.001, T1571 |

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Analysis:** psutil, hashlib, subprocess
- **Framework:** MITRE ATT&CK
- **Export:** Markdown, JSON

## Roadmap

### v1.1 — Wazuh SIEM Integration
- [ ] JSON log export to Wazuh agent monitored path (`/var/ossec/logs/endpointforge/`)
- [ ] Custom Wazuh decoder for EndpointForge JSON log format
- [ ] Custom Wazuh rules mapped to MITRE ATT&CK from EndpointForge findings
- [ ] Wazuh Active Response mode — auto-trigger scans when a rule fires on the endpoint
- [ ] Dashboard integration — EndpointForge findings visible in Wazuh MITRE ATT&CK panel

### v1.2 — Detection Enhancements
- [ ] Windows Event Log analysis (Security, Sysmon, PowerShell Operational)
- [ ] DNS cache inspection for C2 beacon indicators
- [ ] Named pipe enumeration with known-bad pattern matching
- [ ] DLL hijack path detection (writable DLL search order locations)
- [ ] Loaded driver enumeration with unsigned driver flagging

### v1.3 — Reporting & Correlation
- [ ] Sigma rule matching against collected endpoint data (pairs with SigmaForge)
- [ ] YARA scanning of suspicious executables (pairs with YaraForge)
- [ ] Timeline view — unified chronological display across all modules
- [ ] Differential scanning — compare current state against a saved baseline snapshot
- [ ] PDF report export

### Future
- [ ] Remote scanning via WinRM/SSH (multi-endpoint from a single console)
- [ ] Scheduled automated scans with alerting thresholds
- [ ] Integration with EndpointTriage for continuous monitoring + on-demand forensic collection
- [ ] VirusTotal API hash lookup for flagged processes and files
- [ ] Snort rule generation from suspicious network findings (pairs with SnortForge)

## License

MIT License

## Author

**Rootless-Ghost** — [@Rootless_Ghost](https://twitter.com/Rootless_Ghost)
