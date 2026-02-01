# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest release receives security updates. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following methods:

1. **GitHub Private Vulnerability Reporting** (preferred): Use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository.
2. **Email**: Send details to **hello@coyote.cc**

### What to Include

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (if applicable)

### Response Timeline

| Severity | Initial Response | Resolution Target |
|----------|-----------------|-------------------|
| Critical | 48 hours        | 14 days           |
| High     | 72 hours        | 30 days           |
| Medium   | 1 week          | 90 days           |
| Low      | 2 weeks         | Best effort       |

We will acknowledge receipt of your report and keep you informed of progress toward a fix.

## Disclosure Policy

- We follow **coordinated disclosure**. We ask that you give us reasonable time to address the vulnerability before making it public.
- Once a fix is released, we will publish a security advisory on this repository crediting the reporter (unless anonymity is requested).

## Security Update Process

Security patches are released as new versions. To stay informed:

- Watch this repository for releases
- Review the [CHANGELOG](CHANGELOG.md) for security-related entries

## Scope

The following are in scope for security reports:

- Vulnerabilities in Coyote's scanning engine, CLI, or report generation
- Dependency vulnerabilities that affect Coyote's functionality
- Issues where Coyote could leak or mishandle secrets it discovers during scanning
- Injection vulnerabilities in report output (HTML, SARIF, JSON, Markdown)

The following are **out of scope**:

- Security issues in repositories that Coyote scans (those belong to the repository owner)
- Example credentials included in documentation for testing purposes
- Feature requests for additional detection rules

## Best Practices for Users

- **Do not pipe Coyote output to untrusted systems** without validating the content first
- **Review HTML reports** before sharing, as they may contain snippets of detected secrets
- **Store reports securely** since they may reference sensitive findings
- **Keep dependencies updated**: Run `pip install --upgrade -r requirements.txt` regularly
