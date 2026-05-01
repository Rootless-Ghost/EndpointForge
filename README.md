<div align="center">

# EndpointForge

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

---

## SOC Use Case

**Threat hunting and live triage on an endpoint where you have local or agent access.**

1. **Baseline first** — run the filesystem module in `baseline` mode to SHA-256 hash the paths you care about. The baseline is saved to `baselines/fim_baseline_{os}.json`.
2. **Full scan** — `POST /api/scan/full` runs all five modules in one pass and returns a unified findings dict. On Windows, registry is included automatically; on Linux it is skipped with `os_supported: false`.
3. **Triage findings** — severity levels are `critical / high / medium / low / info`. Each finding carries a MITRE technique ID and name so you can pivot directly to ATT&CK documentation.
4. **Export to Wazuh** — `POST /api/wazuh/export` writes NDJSON to the log file. The Wazuh agent picks it up, the decoder fires, and rules generate alerts in the Wazuh dashboard — no manual log shipping.
5. **Generate a report** — produce a Markdown or JSON report from scan results, download it from `exports/`, and reference it in an IR workflow or attach it to a SIREN incident.

**Registry hunt workflow (Windows only):** `POST /api/scan/registry` checks 11 high-value keys against 15 suspicious value patterns — powershell, cmd /c, mshta, regsvr32, rundll32, -enc, -nop, downloadstring, invoke-expression, base64, \temp\\, \appdata\\, \public\\, wscript, cscript. Findings map to T1547.001 and T1112.

---

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

---

## Architecture

### Application startup (`app.py`)

```
CURRENT_OS = platform.system().lower()   # 'windows' or 'linux', detected once at startup

process_mon     = ProcessMonitor()
network_mon     = NetworkMonitor()
filesystem_mon  = FileSystemMonitor()
registry_mon    = RegistryMonitor()
persistence_mon = PersistenceMonitor()
report_gen      = ReportGenerator()
wazuh_exp       = WazuhExporter()

os.makedirs('exports', exist_ok=True)
os.makedirs('baselines', exist_ok=True)
app.run(debug=debug_mode, host='0.0.0.0', port=5005)
```

`debug_mode` reads `FLASK_DEBUG` from the environment (values `1`, `true`, or `yes` enable it).

### Flask routes

**Page routes** — render templates that POST to the API layer via JavaScript:

| Route | Function | Template |
|-------|----------|----------|
| `GET /` | `dashboard()` | `dashboard.html` |
| `GET /processes` | `processes()` | `processes.html` |
| `GET /network` | `network()` | `network.html` |
| `GET /filesystem` | `filesystem()` | `filesystem.html` |
| `GET /registry` | `registry()` | `registry.html` |
| `GET /persistence` | `persistence()` | `persistence.html` |
| `GET /reports` | `reports()` | `reports.html` |

**Scan and report API routes:**

| Route | Method | Function |
|-------|--------|----------|
| `/api/system-info` | GET | `api_system_info()` |
| `/api/scan/processes` | POST | `api_scan_processes()` |
| `/api/scan/network` | POST | `api_scan_network()` |
| `/api/scan/filesystem` | POST | `api_scan_filesystem()` — accepts `{"mode": "baseline"\|"check", "paths": [...]}` |
| `/api/scan/registry` | POST | `api_scan_registry()` — returns `os_supported: false` on non-Windows |
| `/api/scan/persistence` | POST | `api_scan_persistence()` |
| `/api/scan/full` | POST | `api_full_scan()` — all modules; registry only on Windows |
| `/api/triage/run` | POST | `api_triage_run()` — run `Invoke-EndpointTriage.ps1` via subprocess; script and output paths configured in `config.yaml` |
| `/api/report/generate` | POST | `api_generate_report()` — accepts `{"scan_data": ..., "format": "markdown"\|"json"}` |
| `/api/report/export` | POST | `api_export_report()` — saves to `exports/EndpointForge_Report_{timestamp}.{ext}` |

**Wazuh integration routes:**

| Route | Method | Function |
|-------|--------|----------|
| `/api/wazuh/setup` | POST | `api_wazuh_setup()` — creates log directory, returns ossec.conf snippet |
| `/api/wazuh/export` | POST | `api_wazuh_export()` — writes NDJSON from `scan_data` |
| `/api/wazuh/status` | GET | `api_wazuh_status()` — log path, file size, entry count |
| `/api/wazuh/clear` | POST | `api_wazuh_clear()` — truncates log file |
| `/api/wazuh/demo` | GET | `api_wazuh_demo()` — preview NDJSON format without writing to disk |

**Demo routes** — no live system access, always safe:

| Route | Method | Function |
|-------|--------|----------|
| `/api/demo/processes` | GET | `demo_processes()` |
| `/api/demo/network` | GET | `demo_network()` |
| `/api/demo/filesystem` | GET | `demo_filesystem()` |
| `/api/demo/registry` | GET | `demo_registry()` |
| `/api/demo/persistence` | GET | `demo_persistence()` |
| `/api/demo/full` | GET | `demo_full_scan()` — simulates a complete Windows scan |

### Module internals

**ProcessMonitor** (`modules/process_monitor.py`)

`scan()` → `EndpointCollector().collect_processes()` → four analysis passes:

- `_check_windows_core_processes()` — validates 9 core processes against `WINDOWS_CORE_PROCESSES` baselines
- `_check_svchost_parents()` — flags svchost.exe not parented by services.exe; flags missing `-k` argument → T1036.005
- `_check_suspicious_processes()` — name matching against `SUSPICIOUS_PROCESS_NAMES` → T1204.002
- `_check_suspicious_paths()` — path matching against `SUSPICIOUS_PATHS` → T1036.005
- `_check_suspicious_cmdline()` — 12 cmdline patterns → T1059.001, T1059.003, T1112, T1053.005

Returns: `{processes, findings, process_count, findings_count, scan_time, summary}`

**NetworkMonitor** (`modules/network_monitor.py`)

`scan()` → `EndpointCollector().collect_network_connections()` → three checks:

- `_check_suspicious_ports()` — 11-entry `SUSPICIOUS_PORTS` dict → T1571
- `_check_unusual_external()` — unexpected process with external established connection → T1071.001
- `_check_listening_services()` — high-risk listeners: cmd.exe, powershell.exe, bash, sh, nc, ncat, netcat → T1059.001, T1059.004

Returns: `{connections, findings, connection_count, established_count, listening_count, findings_count, scan_time, summary}`

**FileSystemMonitor** (`modules/filesystem_monitor.py`)

`scan(mode='baseline', custom_paths=None)`

- **baseline mode** — `_create_baseline(paths)`: SHA-256 hashes files up to `max_depth=2`, `max_files=500` per directory; saves to `baselines/fim_baseline_{os}.json`
- **check mode** — `_check_integrity(paths)`: compares current hashes vs baseline; new files → T1204.002, modified → T1083/T1112, deleted → T1070.001; modifications to `CRITICAL_FILES` → T1112/T1070.001

`CRITICAL_FILES` — Windows: hosts, SAM, SYSTEM, SECURITY; Linux: passwd, shadow, sudoers, sshd_config, crontab, hosts, resolv.conf

`SUSPICIOUS_EXTENSIONS`: 16 entries (.exe, .dll, .bat, .ps1, .vbs, .js, .hta, .scr, .pif, .com, .cmd, .msi, .reg, .inf, .lnk, .so)

**RegistryMonitor** (`modules/registry_monitor.py`) — Windows only

`scan()` calls `EndpointCollector.collect_windows_registry_values(reg_path)` for 11 keys: HKLM/HKCU Run, RunOnce, Winlogon, Services, Shell Folders, CLSID, IFEO, Policies Explorer Run, User Shell Folders. 15 `SUSPICIOUS_VALUE_PATTERNS` checked per value: powershell, cmd /c, wscript, cscript, mshta, regsvr32, rundll32, \temp\\, \appdata\\, \public\\, -enc, -nop, downloadstring, invoke-expression, base64.

Returns: `{os_supported, entries, entries_count, findings, findings_count, keys_scanned, scan_time, summary}`

**PersistenceMonitor** (`modules/persistence_monitor.py`) — cross-platform

`scan()` branches on OS:

| Platform | Method | MITRE |
|----------|--------|-------|
| Windows | `_analyze_scheduled_tasks()` | T1053.005 |
| Windows | `_analyze_services()` | T1543.003 |
| Windows | `_analyze_startup_items()` | T1547.001 |
| Linux | `_analyze_cron_jobs()` | T1053.003 |
| Linux | `_analyze_systemd_services()` | T1543.002 |
| Linux | `_analyze_shell_configs()` | T1546.004 |
| Linux | `_scan_linux_init_scripts()` — checks `/etc/rc.local` | T1037.004 |

`_is_suspicious_value()` checks 20 indicator strings across all findings.

**EndpointCollector** (`modules/collector.py`) — psutil primary, subprocess fallback

| Method | Primary | Fallback |
|--------|---------|----------|
| `collect_processes()` | psutil | WMIC / tasklist (Windows); ps auxww + /proc/PID/status (Linux) |
| `collect_network_connections()` | psutil | netstat -ano (Windows); ss -tulnp (Linux) |
| `collect_windows_registry_values(key_path)` | winreg | reg query |
| `collect_linux_cron_jobs()` | /etc/crontab, /etc/cron.d/, crontab -l, /var/spool/cron/crontabs/ | — |
| `collect_linux_systemd_services()` | systemctl list-unit-files | — |
| `collect_linux_shell_configs()` | 6 shell config files | — |

**ReportGenerator** (`modules/report_generator.py`)

`generate(scan_data, report_format='markdown')` → two formats:

- **Markdown** — executive summary (severity table), per-module sections, MITRE ATT&CK technique table, recommendations
- **JSON** — `{report_metadata, summary: {total_findings, severity_counts}, findings (sorted by severity: critical → high → medium → low → info), mitre_techniques, raw_data}`

**WazuhExporter** (`modules/wazuh_exporter.py`)

`WazuhExporter(log_path=None)` — default paths: Windows `C:\EndpointForge\logs\endpointforge.json`, Linux `/var/log/endpointforge/endpointforge.json`

NDJSON entry structure:

```json
{
  "timestamp": "2025-01-01T00:00:00.000+0000",
  "endpointforge": {
    "module": "processes",
    "type": "suspicious_process",
    "severity": "high",
    "message": "...",
    "details": "...",
    "process": "powershell.exe",
    "pid": 1234,
    "mitre": { "id": "T1059.001", "technique": "PowerShell" },
    "registry_key": "",
    "value_name": ""
  },
  "agent": { "name": "HOSTNAME", "ip": "192.168.x.x" },
  "source": "endpointforge",
  "version": "1.0.0"
}
```

`export_findings(scan_data)` iterates `['processes', 'network', 'filesystem', 'registry', 'persistence']` and appends a scan summary entry as the final line. `export_single_finding(finding, module)` exports a single finding immediately for real-time alerting.

---

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

---

## Installation

```bash
git clone https://github.com/Rootless-Ghost/EndpointForge.git
cd EndpointForge
pip install -r requirements.txt
python app.py
```

Navigate to `http://localhost:5005` in your browser.

### Docker (standalone)

```bash
docker build -t endpointforge .
docker run -p 5005:5005 endpointforge
```

Open http://localhost:5005

### Requirements

- Python 3.10+
- Flask 3.0+
- psutil 5.9+ (for live scanning)

---

## Quick Start

```bash
# Start the web UI
python app.py
# → http://0.0.0.0:5005

# Enable debug mode
FLASK_DEBUG=1 python app.py
```

**First-run workflow:**

1. Open `http://localhost:5005`
2. Click **Run Full Scan** — processes, network, filesystem (check mode), and persistence run immediately; registry is added automatically on Windows
3. Review findings by severity on the dashboard or drill into individual module pages
4. Open **Reports** → Generate Markdown or JSON → Export `.md` / `.json` to `exports/`

**FIM baseline setup (API):**

```
POST /api/scan/filesystem
{"mode": "baseline", "paths": []}
```

Then run integrity checks against the saved baseline:

```
POST /api/scan/filesystem
{"mode": "check", "paths": []}
```

**Demo mode (no live system access required):**

```
GET /api/demo/full
```

Returns a complete simulated Windows scan — 12 processes (9 legitimate + 3 suspicious), network connections, filesystem changes, registry entries, and persistence mechanisms.

---

## Usage

### Live Scanning
Run EndpointForge on the target endpoint and use the web interface to trigger scans against the live system.

### Demo Mode
Click **"Load Demo Data"** on any page to view simulated scan results without running on a live system.

### Report Export
After running a scan (live or demo), navigate to **Reports & Export** to generate Markdown or JSON reports.

---

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
│   ├── mitre_mapping.py        # MITRE ATT&CK technique reference
│   └── wazuh_exporter.py       # NDJSON log export for Wazuh agent ingestion
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
├── exports/                    # Generated reports
└── wazuh/
    ├── endpointforge_decoder.xml   # Wazuh manager decoder for EndpointForge JSON
    └── endpointforge_rules.xml     # Custom rules (IDs 100200–100265) with MITRE tags
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| **Persistence** | T1547.001, T1053.005, T1053.003, T1543.003, T1543.002, T1546.004, T1546.015, T1547.009 |
| **Execution** | T1059.001, T1059.003, T1059.004, T1204.002 |
| **Defense Evasion** | T1036.005, T1070.001, T1070.002, T1112 |
| **Discovery** | T1057, T1049, T1083 |
| **Command and Control** | T1071.001, T1571 |

### Technique detail by module

**Persistence (8 techniques)**

| Technique | Name | Module |
|-----------|------|--------|
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | Persistence — `_scan_linux_init_scripts()` (`/etc/rc.local`) |
| T1053.003 | Scheduled Task/Job: Cron | Persistence — `_analyze_cron_jobs()` |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence — `_analyze_scheduled_tasks()`, Process cmdline |
| T1078 | Valid Accounts | Persistence |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence — `_analyze_systemd_services()` |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence — `_analyze_services()` |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence — `_analyze_shell_configs()` |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence — `_analyze_startup_items()` |

**Execution (4 techniques)**

| Technique | Name | Module |
|-----------|------|--------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Process — `_check_suspicious_cmdline()`, Network — `_check_listening_services()` |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Process — `_check_suspicious_cmdline()` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Network — `_check_listening_services()` |
| T1204.002 | User Execution: Malicious File | Process — `_check_suspicious_processes()`, Filesystem — new files |

**Defense Evasion (4 techniques)**

| Technique | Name | Module |
|-----------|------|--------|
| T1036.005 | Masquerading: Match Legitimate Name or Location | Process — `_check_svchost_parents()`, `_check_suspicious_paths()` |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Filesystem — `_check_integrity()` deleted critical files |
| T1083 | File and Directory Discovery | Filesystem — `_check_integrity()` modified files |
| T1112 | Modify Registry | Process — `_check_suspicious_cmdline()`, Filesystem — modified critical files |

**Discovery (3 techniques)**

| Technique | Name | Module |
|-----------|------|--------|
| T1049 | System Network Connections Discovery | Network — `_check_unusual_external()` |
| T1057 | Process Discovery | Process — `scan()` |
| T1083 | File and Directory Discovery | Filesystem — `scan()` |

**Command and Control (2 techniques)**

| Technique | Name | Module |
|-----------|------|--------|
| T1071.001 | Application Layer Protocol: Web Protocols | Network — `_check_unusual_external()` |
| T1571 | Non-Standard Port | Network — `_check_suspicious_ports()` |

---

## Integration with Nebula Forge

### Wazuh export pipeline

EndpointForge is designed to run on an endpoint where the Wazuh agent is installed. Findings flow to the Wazuh server automatically once the agent is configured.

**Step 1 — setup the log directory:**

```
POST /api/wazuh/setup
```

Returns the ossec.conf snippet via `WazuhExporter._get_agent_config_instructions()`:

```xml
<!-- Windows: C:\Program Files (x86)\ossec-agent\ossec.conf -->
<!-- Linux:   /var/ossec/etc/ossec.conf -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>C:\EndpointForge\logs\endpointforge.json</location>
    <label key="log_type">endpointforge</label>
  </localfile>
</ossec_config>
```

**Step 2 — restart the agent:**

```
# Windows
Restart-Service WazuhSvc

# Linux
sudo systemctl restart wazuh-agent
```

**Step 3 — export findings after each scan:**

```
POST /api/wazuh/export
{"scan_data": <full scan result>}
```

Each finding writes one NDJSON line. A scan summary entry is appended as the final line. The Wazuh manager decodes using `wazuh/endpointforge_decoder.xml` and fires rules from `wazuh/endpointforge_rules.xml` (IDs 100200–100265) with MITRE ATT&CK tags.

**Check exporter status:**

```
GET /api/wazuh/status
# Returns: log_path, log_exists, log_size_bytes, entry_count, os, hostname
```

**Preview NDJSON format without writing to disk:**

```
GET /api/wazuh/demo
```

### Closed-loop validation with SigmaForge

EndpointForge and SigmaForge form a closed-loop detection validation pipeline:

```
SigmaForge → Wazuh XML rules → Wazuh server
EndpointForge → NDJSON findings → Wazuh agent → Wazuh server
```

When both are deployed:
1. SigmaForge authors a detection rule and converts it to Wazuh XML
2. The rule is deployed to the Wazuh server
3. EndpointForge runs on the endpoint and exports findings as NDJSON via `WazuhExporter.export_findings()`
4. The Wazuh agent ships the NDJSON to the server
5. If the rule fires against an EndpointForge finding, detection is confirmed
6. If not, the detection gap surfaces back to SigmaForge for rule refinement

This pipeline requires no pySigma dependency — SigmaForge uses a custom conversion engine with a native Wazuh XML backend.

### SIREN handoff

EndpointForge reports export as Markdown (`.md`) or JSON (`.json`) to the `exports/` directory. The JSON format produced by `ReportGenerator._generate_json()` includes `report_metadata`, `summary`, `findings` (sorted by severity), `mitre_techniques`, and `raw_data` — structured for direct ingestion into a SIREN incident report as IOC and affected-system evidence.

### EndpointForge → ir-chain (on-demand triage)

The **Run Full Triage** button on the dashboard calls `POST /api/triage/run`, which launches `Invoke-EndpointTriage.ps1` via subprocess. The script writes a timestamped `HOSTNAME_YYYYMMDD_HHMMSS` output folder to the directory configured as `endpoint_triage_output` in `config.yaml`.

ir-chain watches that same directory. When the new case folder appears, ir-chain automatically picks it up, runs log-analyzer against the `eventlogs/Security.csv`, builds a structured SIREN incident payload from the findings, and POSTs it to SIREN — completing the triage-to-report pipeline from a single button click.

Configure the triage script and output paths in `config.yaml` (gitignored):

```yaml
endpoint_triage_script: "/path/to/EndpointTriage/Invoke-EndpointTriage.ps1"
endpoint_triage_output: "/path/to/EndpointTriage/TriageOutput"
```

---

## Related Tools

| Tool | Description | Link |
|------|-------------|------|
| **SigmaForge** | Sigma rule generator — converts to Wazuh XML rules that detect EndpointForge findings | [GitHub](https://github.com/Rootless-Ghost/SigmaForge) |
| **EndpointTriage** | PowerShell forensic collector for Windows endpoint IR | [GitHub](https://github.com/Rootless-Ghost/EndpointTriage) |

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Analysis:** psutil, hashlib, subprocess
- **Framework:** MITRE ATT&CK
- **Export:** Markdown, JSON

## Roadmap

### v1.1 — Wazuh SIEM Integration
- [x] JSON log export to Wazuh agent monitored path (`/var/ossec/logs/endpointforge/`)
- [x] Custom Wazuh decoder for EndpointForge JSON log format
- [x] Custom Wazuh rules mapped to MITRE ATT&CK from EndpointForge findings
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

This project is licensed under the MIT License — see the [LICENSE](LICENSE) for details. 

<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost)

</div>
