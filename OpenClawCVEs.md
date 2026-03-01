# OpenClaw CVEs Scanned by Coyote

This document lists the OpenClaw CVEs currently scanned by Coyote via:

```bash
python3 -m coyote agent secure-openclaw /path/to/openclaw
```

## Coverage Summary

| CVE | Issue | Fixed In |
|-----|-------|----------|
| CVE-2026-25253 | One-click token exfiltration via `gatewayUrl` | 2026.1.29 |
| CVE-2026-24763 | Docker PATH command injection | 2026.1.29 |
| CVE-2026-25157 | Remote SSH path/target command injection | 2026.1.29 |
| CVE-2026-25475 | MEDIA path traversal / arbitrary file read | 2026.1.30 |
| CVE-2026-25593 | Unauthenticated local WebSocket `config.apply` injection | 2026.1.20 |
| CVE-2026-26324 | SSRF guard bypass via full-form IPv4-mapped IPv6 | 2026.2.14 |
| CVE-2026-26325 | `system.run` policy bypass via `rawCommand`/`command[]` mismatch | 2026.2.14 |
| CVE-2026-26316 | BlueBubbles webhook auth bypass in loopback trust flows | 2026.2.13 |
| CVE-2026-26326 | `skills.status` secret disclosure to `operator.read` clients | 2026.2.14 |
| CVE-2026-27003 | Telegram bot token disclosure in logs | 2026.2.15 |
| CVE-2026-27009 | Stored XSS in Control UI assistant identity rendering | 2026.2.15 |
| CVE-2026-26320 | macOS deep-link command prompt truncation / social engineering | 2026.2.14 |
| CVE-2026-27487 | macOS keychain refresh command injection | 2026.2.14 |
| CVE-2026-27486 | CLI cleanup can terminate unrelated processes | 2026.2.14 |
| CVE-2026-27485 | Skill packager symlink traversal can disclose local files | 2026.2.18 |

## Scan Logic per CVE

Each CVE check uses version awareness plus risk indicators from available config.

### Core Runtime CVEs

- `CVE-2026-25253` (`gatewayUrl` token exfiltration)
  - Indicators: external `gatewayUrl` source, disabled approvals, gateway exec host, privileged operator scopes.
- `CVE-2026-24763` (Docker PATH command injection)
  - Indicators: external Docker path source, shell metacharacters, shell-evaluated command templates.
- `CVE-2026-25157` (remote SSH path/target injection)
  - Indicators: remote mode with untrusted path/target sources, shell metacharacters, shell interpolation.
- `CVE-2026-25475` (MEDIA path arbitrary file read)
  - Indicators: untrusted media path sources, traversal segments, absolute paths, allow-absolute toggles.
- `CVE-2026-25593` (unauthenticated `config.apply` injection)
  - Indicators: local unauthenticated WebSocket, enabled `config.apply`, untrusted config source, privileged scopes.

### February 2026 CVEs

- `CVE-2026-26324` (SSRF IPv4-mapped IPv6 bypass)
  - Indicators: untrusted URL source, permissive SSRF toggles, full-form mapped-IPv6 patterns in config.
- `CVE-2026-26325` (`system.run` command-model mismatch bypass)
  - Indicators: node-host execution path, allowlist policy mode, ask-on-miss, mixed `rawCommand` + `command[]` fields.
- `CVE-2026-26316` (BlueBubbles webhook auth bypass)
  - Indicators: BlueBubbles enabled, weak/missing webhook secret, disabled webhook auth, loopback trust assumptions.
- `CVE-2026-26326` (`skills.status` secret disclosure)
  - Indicators: `operator.read` scope, enabled status endpoint, token-bearing integration fields.
- `CVE-2026-27003` (Telegram token log exposure)
  - Indicators: Telegram token patterns, Telegram API usage, disabled token-redaction flags.
- `CVE-2026-27009` (Control UI stored XSS)
  - Indicators: script-like payloads in assistant identity fields, unsafe inline CSP settings, trusted HTML rendering flags.
- `CVE-2026-26320` (macOS deep-link prompt truncation)
  - Indicators: macOS context, deep-link enablement, `openclaw://agent` targets, missing unattended key.
  - Version note: only versions in/after the known affected range are treated as vulnerable.
- `CVE-2026-27487` (macOS keychain command injection)
  - Indicators: macOS context, Claude auth/keychain refresh usage, shell-evaluated keychain command templates.
- `CVE-2026-27486` (cleanup cross-process termination)
  - Indicators: enabled cleanup, global/system scope, broad `pkill`/`killall` style command usage.
- `CVE-2026-27485` (skill packager symlink disclosure)
  - Indicators: symlink-following packaging flags and local `package_skill.py` packaging script presence.

## Status Semantics

- `VULNERABLE`: version is below the fixed release for that CVE (and within affected range when known)
- `WARNING`: version looks patched, but risky configuration patterns are present
- `UNKNOWN`: version cannot be determined
- `SAFE`: version is patched and no risky patterns were detected
