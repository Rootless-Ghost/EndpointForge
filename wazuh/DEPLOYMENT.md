# EndpointForge → Wazuh Integration Guide

## Your Environment
- **Wazuh Server:** 192.168.46.100
- **Agents:** SOC Ubuntu, Kali, Kali Purple, Windows 11 VM
- **EndpointForge** runs on the agent endpoints and writes JSON findings to a log file
- **Wazuh agent** monitors that log file and ships entries to the server
- **Wazuh server** decodes the JSON and fires alerts based on custom rules

---

## Step 1: Deploy Decoder and Rules on Wazuh Server

SSH into your Wazuh server:

```bash
ssh user@192.168.46.100
```

Copy the decoder file:

```bash
sudo cp endpointforge_decoder.xml /var/ossec/etc/decoders/endpointforge_decoder.xml
```

Copy the rules file:

```bash
sudo cp endpointforge_rules.xml /var/ossec/etc/rules/endpointforge_rules.xml
```

Set correct ownership:

```bash
sudo chown wazuh:wazuh /var/ossec/etc/decoders/endpointforge_decoder.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/endpointforge_rules.xml
```

Restart Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

Verify no config errors:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

## Step 2: Configure Wazuh Agent on Endpoints

### Linux Agents (SOC Ubuntu, Kali, Kali Purple)

Create the EndpointForge log directory:

```bash
sudo mkdir -p /var/log/endpointforge
sudo chown $(whoami):$(whoami) /var/log/endpointforge
```

Edit the Wazuh agent config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this block inside the `<ossec_config>` tags:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/endpointforge/endpointforge.json</location>
  <label key="log_type">endpointforge</label>
</localfile>
```

Restart the Wazuh agent:

```bash
sudo systemctl restart wazuh-agent
```

### Windows Agent (Win11 VM)

Create the EndpointForge log directory:

```powershell
mkdir C:\EndpointForge\logs
```

Edit the Wazuh agent config (run Notepad as Administrator):

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Add this block inside the `<ossec_config>` tags:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\EndpointForge\logs\endpointforge.json</location>
  <label key="log_type">endpointforge</label>
</localfile>
```

Restart the Wazuh agent service:

```powershell
Restart-Service WazuhSvc
```

---

## Step 3: Run EndpointForge and Export to Wazuh

### Via Flask Web UI

1. Start EndpointForge: `python app.py`
2. Run a scan (Full Scan or individual module)
3. Navigate to **Reports & Export**
4. Click **Export to Wazuh** — findings are written to the log file
5. Wazuh agent picks them up automatically

### Via Python Script (no Flask needed)

```python
from modules.process_monitor import ProcessMonitor
from modules.network_monitor import NetworkMonitor
from modules.filesystem_monitor import FileSystemMonitor
from modules.registry_monitor import RegistryMonitor
from modules.persistence_monitor import PersistenceMonitor
from modules.wazuh_exporter import WazuhExporter

# Initialize
exporter = WazuhExporter()
exporter.setup()

# Run scans
scan_data = {
    'processes': ProcessMonitor().scan(),
    'network': NetworkMonitor().scan(),
    'filesystem': FileSystemMonitor().scan(mode='check'),
    'persistence': PersistenceMonitor().scan()
}

# On Windows, also scan registry
# scan_data['registry'] = RegistryMonitor().scan()

# Export to Wazuh
result = exporter.export_findings(scan_data)
print(f"Exported {result['exported_count']} findings to {result['log_path']}")
```

---

## Step 4: Test with wazuh-logtest

On the Wazuh server, open logtest:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a sample log line (this is what EndpointForge outputs):

```json
{"timestamp":"2025-03-23T15:30:00.000+0000","endpointforge":{"module":"processes","type":"wrong_path","severity":"critical","message":"svchost.exe running from unexpected path: C:\\Users\\Public\\Downloads\\svchost.exe","details":"Expected: C:\\Windows\\System32\\svchost.exe","process":"svchost.exe","pid":6672,"mitre":{"id":"T1036.005","technique":"Masquerading: Match Legitimate Name or Location"},"registry_key":"","value_name":""},"agent":{"name":"WORKSTATION-01","ip":"192.168.46.50"},"source":"endpointforge","version":"1.0.0"}
```

Expected output should show:
- Decoder: `endpointforge`
- Rule: `100120` (level 14)
- MITRE: `T1036.005`

---

## Step 5: Verify in Wazuh Dashboard

1. Open Wazuh dashboard: `https://192.168.46.100`
2. Go to **Security Events** — EndpointForge alerts should appear with the `endpointforge` group
3. Go to **MITRE ATT&CK** — technique IDs from EndpointForge findings should map to the MITRE visualization
4. Filter by: `rule.groups: endpointforge`

---

## Rule ID Reference

| Rule ID | Level | Trigger | MITRE |
|---------|-------|---------|-------|
| 100100 | 3 | Any EndpointForge event | — |
| 100101 | 3 | Scan completed | — |
| 100110 | 14 | Critical severity finding | — |
| 100111 | 12 | High severity finding | — |
| 100112 | 8 | Medium severity finding | — |
| 100120 | 14 | Core process wrong path | T1036.005 |
| 100121 | 14 | Core process wrong parent | T1036.005 |
| 100122 | 12 | Excess process instances | T1036.005 |
| 100123 | 12 | Suspicious process name | T1204.002 |
| 100124 | 12 | Suspicious command line | T1059.001 |
| 100130 | 14 | Shell/netcat listener | T1059 |
| 100131 | 12 | Suspicious port | T1571 |
| 100132 | 8 | Unusual external connection | T1071.001 |
| 100140 | 14 | Critical file modified | T1112 |
| 100141 | 14 | Critical file missing | T1070.001 |
| 100142 | 12 | New suspicious file | T1204.002 |
| 100150 | 12 | Suspicious registry value | T1547.001 |
| 100160 | 12 | Suspicious scheduled task | T1053.005 |
| 100161 | 12 | Suspicious service | T1543.003 |
| 100163 | 12 | Suspicious cron job | T1053.003 |
| 100164 | 12 | Suspicious systemd service | T1543.002 |
| 100165 | 8 | Suspicious shell config | T1546.004 |

---

## Troubleshooting

**Agents show disconnected:**
```bash
# On the agent, check status
sudo systemctl status wazuh-agent

# Check agent can reach server
ping 192.168.46.100

# Check agent config has correct server IP
grep '<address>' /var/ossec/etc/ossec.conf
```

**No alerts appearing:**
```bash
# Check Wazuh manager logs for decoder/rule errors
sudo tail -f /var/ossec/logs/ossec.log

# Verify the log file exists on the agent
ls -la /var/log/endpointforge/endpointforge.json

# Check the agent is reading the file
sudo /var/ossec/bin/agent_control -l
```

**Decoder not matching:**
```bash
# Test manually with wazuh-logtest
sudo /var/ossec/bin/wazuh-logtest
# Paste a log line — if decoder shows 'unknown', check prematch string
```
