# Security policy

Fellaga performs active DNS, HTTP, and TLS operations. Use it only on domains for which you have explicit authorization.

## Supported versions

Security fixes target the latest version published on [GitHub Releases](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases). The `main` branch receives fixes for the next release but may change before publication. Older releases do not receive guaranteed support.

## Report a vulnerability in Fellaga

1. Open the repository's **Security** tab and choose **Report a vulnerability** to use GitHub private vulnerability reporting.
2. If private reporting is unavailable, open a public issue that asks only for a private contact channel. Do not include exploit details, secrets, target data, or an unredacted proof of concept.
3. In the private report, include the affected version or commit, operating system, relevant options, expected impact, and a minimal reproduction using controlled data.

Reports are handled on a best-effort basis without a contractual response time. A fix may be prepared under embargo before coordinated disclosure.

## Never attach

Do not send API keys, tokens, passwords, real SQLite databases, configuration files, unredacted scan output, or confidential target names. Replace sensitive values with placeholders and, whenever possible, reproduce the issue with a DNS laboratory zone you control.

## Scope of this policy

This policy covers vulnerabilities in Fellaga's code and published artifacts. It does not cover vulnerabilities discovered on scanned domains, outages of third-party providers, or consequences of an unauthorized scan. Report third-party vulnerabilities to their owners under the owners' disclosure process.
