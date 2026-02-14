# OpenClaw CVEs Scanned by Coyote

This document lists the OpenClaw CVEs currently scanned by Coyote via:

```bash
python3 -m coyote agent secure-openclaw /path/to/openclaw
```

## Coverage Summary

| CVE | Published | Issue | Fixed In |
|-----|-----------|-------|----------|
| CVE-2026-25253 | 2026-02-01 | One-click token exfiltration via `gatewayUrl`, can lead to gateway compromise | 2026.1.29 |
| CVE-2026-24763 | 2026-02-02 | Command injection via Docker PATH handling | 2026.1.29 |
| CVE-2026-25157 | 2026-02-04 | SSH command injection in remote mode path/target handling | 2026.1.29 |
| CVE-2026-25475 | 2026-02-04 | MEDIA path handling allows arbitrary file reads | 2026.1.30 |
| CVE-2026-25593 | 2026-02-06 | Unauthenticated local WebSocket `config.apply` path to command injection | 2026.1.20 |

## Scan Logic per CVE

### CVE-2026-25253 (`gatewayUrl` Token Exfiltration)
- Check ID: `CVE-2026-25253`
- Version logic: `VULNERABLE` if OpenClaw version is lower than `2026.1.29`
- Risk indicators:
- `gatewayUrl` source appears external (query/env/user driven)
- `exec.approvals` disabled
- `tools.exec.host` set to `gateway`
- high-risk operator scopes enabled (`operator.admin`, `operator.approvals`)

### CVE-2026-24763 (Docker PATH Command Injection)
- Check ID: `CVE-2026-24763`
- Version logic: `VULNERABLE` if OpenClaw version is lower than `2026.1.29`
- Risk indicators:
- Docker path source appears external (query/env/user driven)
- configured Docker path contains shell metacharacters
- Docker command template interpolates untrusted path values
- Docker command appears shell-evaluated

### CVE-2026-25157 (Remote SSH Path/Target Injection)
- Check ID: `CVE-2026-25157`
- Version logic: `VULNERABLE` if OpenClaw version is lower than `2026.1.29`
- Risk indicators:
- remote mode enabled with path/target sourced from untrusted input
- SSH path/target values contain shell metacharacters
- SSH command templates interpolate path/target values
- SSH command appears shell-evaluated in remote mode

### CVE-2026-25475 (MEDIA Path Arbitrary File Read)
- Check ID: `CVE-2026-25475`
- Version logic: `VULNERABLE` if OpenClaw version is lower than `2026.1.30`
- Risk indicators:
- MEDIA path source appears external
- MEDIA path includes traversal (`..`) segments
- MEDIA path is absolute
- config allows absolute MEDIA paths

### CVE-2026-25593 (Unauthenticated WebSocket `config.apply` Injection)
- Check ID: `CVE-2026-25593`
- Version logic: `VULNERABLE` if OpenClaw version is lower than `2026.1.20`
- Risk indicators:
- local WebSocket listener appears unauthenticated
- `config.apply` enabled while WebSocket authentication is disabled
- `config.apply` source appears external
- `config.apply` enabled with privileged operator scopes

## Status Semantics

- `VULNERABLE`: version is below the fixed release for that CVE
- `WARNING`: version looks patched, but risky configuration patterns are present
- `UNKNOWN`: version cannot be determined
- `SAFE`: version is patched and no risky patterns were detected
