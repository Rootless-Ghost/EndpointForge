# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in EndpointForge, please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, please send an email or direct message with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if any)

## Security Considerations

EndpointForge is designed as a **security monitoring and triage tool** for authorized use on systems you own or have explicit permission to analyze.

- **Local Use Only:** The Flask web server is intended for local use. Do not expose it to the internet without proper authentication and HTTPS.
- **Privileged Access:** Some scans require elevated privileges (administrator/root) to access all process, registry, and filesystem information.
- **Demo Mode:** The demo mode contains simulated attack data for portfolio and educational purposes only. No actual malicious activity is performed.
- **Data Handling:** Scan results and baselines are stored locally. No data is transmitted externally.
- **No Exploitation:** EndpointForge does not perform any offensive actions. It is a passive monitoring and analysis tool.
