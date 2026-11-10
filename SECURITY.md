# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in EndpointForge, please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, report it privately through GitHub: open the repository's **Security** tab and click **Report a vulnerability** (or go directly to [the private reporting form](https://github.com/Rootless-Ghost/EndpointForge/security/advisories/new)). Please include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if any)

## Security Considerations

EndpointForge is designed as a **security monitoring and triage tool** for authorized use on systems you own or have explicit permission to analyze.

- **Local Use Only:** The Flask web server binds to `127.0.0.1` by default. Setting `ENDPOINTFORGE_HOST=0.0.0.0` makes it reachable from the network; only do this on an isolated lab network or behind a firewall, and put an HTTPS reverse proxy in front of it for anything beyond that. Never expose it to the internet.
- **Access Token:** Every page and API route requires an access token. A random token is generated on each start and printed in a login URL (`http://127.0.0.1:5005/?token=...`); set `ENDPOINTFORGE_TOKEN` to pin one. Browser sessions also require a per-session CSRF token on API calls. Scripted clients send `Authorization: Bearer <token>`.
- **Debug Mode:** `FLASK_DEBUG=1` enables the Werkzeug debugger, which allows code execution. The app refuses to start in debug mode unless it is bound to loopback.
- **Privileged Access:** Some scans require elevated privileges (administrator/root) to access all process, registry, and filesystem information.
- **Demo Mode:** The demo mode contains simulated attack data for portfolio and educational purposes only. No actual malicious activity is performed.
- **Data Handling:** Scan results and baselines are stored locally. No data is transmitted externally.
- **No Exploitation:** EndpointForge does not perform any offensive actions. It is a passive monitoring and analysis tool.

## Security Advisories

| Advisory | Severity | Affected | Fixed in |
| -------- | -------- | -------- | -------- |
| [GHSA-xqjv-256f-x94v](https://github.com/Rootless-Ghost/EndpointForge/security/advisories/GHSA-xqjv-256f-x94v) | Moderate | 1.0.x | 1.1.0 |
