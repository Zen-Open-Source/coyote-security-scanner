# Coyote

**Security Scanner for Repositories and AI Agents**

Coyote is a dual-purpose security tool:
1. **Repository Scanning** - Detect secrets, credentials, and security issues in code
2. **AI Agent Analysis** - Analyze OpenClaw/Moltbot agents for security risks before running them

```
                       .
                      /|
                     / |  /|        "Sniffing out secrets..."
               /\   /  | / |
              /  \_/   |/  |
             / o       <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /   \_/
```

## Features

### Repository Scanning
- **Comprehensive Detection**: Secrets, credentials, sensitive files, and security anti-patterns
- **Entropy Detection**: Find high-randomness strings that are likely secrets (custom tokens, passwords)
- **Git History Scanning**: Detect secrets in past commits, even if later "removed"
- **Finding Suppression**: Ignore false positives via `.coyote-ignore` file
- **Scan Diffing**: Compare scans against a baseline to track new vs. fixed findings
- **Webhook Notifications**: Get Slack/Discord alerts when security issues are detected
- **Continuous Monitoring**: Polls GitHub repos for new commits and auto-scans on changes
- **Rich TUI**: Interactive terminal interface with live updates and keyboard controls
- **Multiple Output Formats**: JSON, Markdown, and SARIF reports
- **SARIF Output**: GitHub Code Scanning compatible output for CI/CD integration

### AI Agent Security (NEW in v0.9)
- **Agent Intake Analysis**: Static analysis of agent configs, prompts, and tools
- **Capability Manifests**: Structured representation of what an agent can do
- **Permission Diffing**: Track changes when agents are updated
- **Risk Assessment**: Automatic risk level classification (LOW to CRITICAL)
- **Runtime Guardrails**: Lightweight monitoring and first-use prompting
- **Policy Generation**: Machine-readable security policies for runtime enforcement

## Installation

### Requirements

- Python 3.9+
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/coyote-repo-scanner.git
cd coyote-repo-scanner

# Install dependencies
pip install -r requirements.txt

# Make the watcher script executable
chmod +x coyote.sh
```

## Quick Start

### Repository Scanning

```bash
# Scan a repository
python3 -m coyote scan --repo /path/to/your/repo

# Or use legacy syntax (backward compatible)
python3 -m coyote --repo /path/to/your/repo

# Save reports after scanning
python3 -m coyote scan --repo /path/to/your/repo --report

# Interactive TUI mode
python3 -m coyote scan --repo /path/to/your/repo --interactive
```

**Keyboard Controls (Interactive Mode):**
- `S` - Run scan now
- `R` - Save report
- `Q` - Quit

### AI Agent Security Analysis

```bash
# Analyze an agent config
python3 -m coyote agent analyze ./my-agent.json

# Track permission changes over time
python3 -m coyote agent analyze ./my-agent.json --register
python3 -m coyote agent diff my-agent-id

# Generate a security policy
python3 -m coyote agent policy my-agent-id --strict --output policy.json
```

### Watch a Remote Repository

```bash
# Monitor a GitHub repo for new commits
./coyote.sh scan --repo-url https://github.com/user/repo --interval 60

# Run once and exit
./coyote.sh scan --repo-url https://github.com/user/repo --once

# Analyze an agent
./coyote.sh agent analyze ./my-agent.json
```

## Usage

### Commands

Coyote has two main commands:

```bash
python3 -m coyote scan [OPTIONS]    # Repository scanning
python3 -m coyote agent [COMMAND]   # AI agent analysis
```

### Repository Scanning Options

```bash
python3 -m coyote scan [OPTIONS]

Options:
  --repo PATH            Path to repository to scan
  --config FILE          Path to config file (default: config.yaml)
  --interactive, -i      Run interactive TUI
  --report, -r           Save reports after scan
  --save-baseline        Save scan as baseline for future comparisons
  --diff                 Compare scan against baseline (show new/fixed)
  --baseline-path        Path to baseline file (default: .coyote-baseline.json)
  --fail-on-new          Exit with code 1 if new findings (for CI)
  --notify               Enable webhook notifications (uses config)
  --slack-webhook URL    Slack webhook URL (overrides config)
  --discord-webhook URL  Discord webhook URL (overrides config)
  --history              Scan git history for secrets in past commits
  --max-commits N        Max commits to scan in history mode (default: 100)
  --branch BRANCH        Branch to scan in history mode (default: HEAD)
  --entropy              Enable entropy-based secret detection
  --entropy-threshold N  Entropy threshold (default: 4.5)
  --ignore-file PATH     Use custom ignore file
  --no-ignore            Disable suppression, report all findings
  --sarif FILE           Output results in SARIF format (use - for stdout)
  --sarif-output FILE    Write SARIF output to FILE
```

### Bash Watcher

```bash
./coyote.sh [OPTIONS]

Options:
  --repo-url URL         GitHub repo URL to watch
  --branch NAME          Branch to watch (default: main)
  --local-path PATH      Local clone path (default: ./watched_repo)
  --interval SECONDS     Poll interval in seconds (default: 60)
  --once                 Run scan once and exit
  --interactive, -i      Launch interactive TUI
  --report, -r           Save reports after scan
  --config FILE          Config file path (default: config.yaml)
  --save-baseline        Save scan as baseline for future comparisons
  --diff                 Compare scan against baseline (show new/fixed)
  --baseline-path        Path to baseline file (default: .coyote-baseline.json)
  --fail-on-new          Exit with code 1 if new findings (for CI)
  --notify               Enable webhook notifications (uses config)
  --slack-webhook URL    Slack webhook URL (overrides config)
  --discord-webhook URL  Discord webhook URL (overrides config)
  --history              Scan git history for secrets
  --max-commits N        Max commits to scan (default: 100)
  --entropy              Enable entropy-based detection
  --entropy-threshold N  Entropy threshold (default: 4.5)
  --ignore-file PATH     Use custom ignore file
  --no-ignore            Disable suppression
  --sarif FILE           Output results in SARIF format
  --help, -h             Show help
```

### Programmatic Usage

```python
from coyote.scanner import run_scan
from coyote.reporter import generate_markdown_report, save_reports

# Run a scan
result = run_scan("/path/to/repo")

# Check results
print(f"Found {result.total_count} issues")
print(f"  HIGH: {result.high_count}")
print(f"  MEDIUM: {result.medium_count}")
print(f"  LOW: {result.low_count}")

# Generate reports
markdown = generate_markdown_report(result, commit_hash="abc1234")
print(markdown)

# Save reports to disk
saved_files = save_reports(result, report_dir="./reports", formats=["json", "markdown"])
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and customize:

```yaml
target:
  repo_url: "https://github.com/user/repo"
  branch: "main"
  local_path: "./watched_repo"

polling:
  interval_seconds: 60

scan:
  exclude_paths:
    - "node_modules/"
    - "venv/"
    - ".git/"
    - "vendor/"
    - "__pycache__/"
  exclude_extensions:
    - ".min.js"
    - ".map"
    - ".lock"
  max_file_size_mb: 5

output:
  report_dir: "./reports"
  format: ["json", "markdown"]
```

## What Coyote Detects

### Secrets & Credentials (HIGH Severity)

| Type | Pattern Example |
|------|-----------------|
| AWS Access Key | `AKIA...` (20 chars) |
| AWS Secret Key | 40-char base64 near AWS context |
| GitHub Token | `ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...` |
| GitLab Token | `glpat-...` |
| Slack Token | `xoxb-...`, `xoxp-...`, `xoxa-...` |
| Slack Webhook | `https://hooks.slack.com/services/...` |
| Discord Webhook | `https://discord.com/api/webhooks/...` |
| OpenAI Key | `sk-...` (48 chars) |
| Anthropic Key | `sk-ant-...` (90+ chars) |
| Stripe Live Key | `sk_live_...`, `rk_live_...` |
| Twilio API Key | `SK...` (32 hex chars) |
| SendGrid Key | `SG....` (specific format) |
| Google API Key | `AIza...` (39 chars) |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` etc. |
| Generic Secrets | `password = "..."`, `api_key = "..."` |
| JWT Tokens | `eyJ...` (three base64 segments) |
| Basic Auth URLs | `https://user:pass@host/...` |

### Sensitive Files (HIGH/MEDIUM Severity)

| File Pattern | Risk |
|--------------|------|
| `.env`, `.env.*` | Environment secrets |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Certificates/keys |
| `id_rsa`, `id_dsa`, `id_ed25519`, `id_ecdsa` | SSH private keys |
| `*.sql`, `*.dump`, `*.sqlite`, `*.db` | Database dumps |
| `credentials.json`, `service-account*.json` | Cloud credentials |
| `.htpasswd`, `.netrc`, `.npmrc` | Auth config files |
| `terraform.tfstate`, `*.tfvars` | Infrastructure secrets |
| `*.bak`, `*.backup`, `*.old` | Backup files |

### Security Smells (MEDIUM Severity)

| Pattern | Risk |
|---------|------|
| `DEBUG = True` | Debug mode in production |
| `verify = False` | Disabled SSL verification (Python) |
| `NODE_TLS_REJECT_UNAUTHORIZED = 0` | Disabled TLS (Node.js) |
| `Access-Control-Allow-Origin: *` | Overly permissive CORS |
| `eval(...)` | Code injection risk |
| `dangerouslySetInnerHTML` | XSS risk (React) |
| `TODO: security`, `FIXME: auth` | Security debt markers |
| `192.168.x.x`, `10.x.x.x` | Hardcoded internal IPs |

### Git-Specific Checks (LOW Severity)

- Missing `.gitignore` file
- Incomplete `.gitignore` (missing common secret patterns)
- Large binary files (>10MB)

## Scan Diffing / Baseline Mode

Compare scans over time to track new vs. fixed vs. existing findings. Perfect for CI/CD pipelines where you only want to fail on **new** security issues.

### How It Works

1. **Save a baseline** after your initial scan (or when you've triaged existing findings)
2. **Run diff scans** against the baseline to see what's changed
3. **Fail on new findings** in CI to prevent security regressions

### Usage

```bash
# Step 1: Run initial scan and save as baseline
python3 -m coyote --repo /path/to/repo --save-baseline

# Step 2: Later, run a diff scan to see changes
python3 -m coyote --repo /path/to/repo --diff

# Step 3: In CI, fail if new findings are introduced
python3 -m coyote --repo /path/to/repo --diff --fail-on-new
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--save-baseline` | Save current scan as baseline for future comparisons |
| `--diff` | Compare current scan against saved baseline |
| `--baseline-path PATH` | Custom baseline file path (default: `.coyote-baseline.json`) |
| `--fail-on-new` | Exit with code 1 if new findings detected (for CI) |

### Diff Output

When running with `--diff`, you'll see a breakdown of:

```
╭────────────────────── Scan Diff: 3 NEW findings ──────────────────────╮
│   NEW:        3  (2 HIGH, 1 MED, 0 LOW)                               │
│   FIXED:      1                                                       │
│   EXISTING:  12                                                       │
│                                                                       │
│   Baseline: 2024-01-15T10:30:00Z (commit: abc1234)                    │
╰───────────────────────────────────────────────────────────────────────╯
```

- **NEW**: Findings in current scan but not in baseline (requires attention)
- **FIXED**: Findings in baseline but not in current scan (resolved issues)
- **EXISTING**: Findings present in both scans (known issues)

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    # First run: create baseline (commit this file)
    # python3 -m coyote --repo . --save-baseline

    # Subsequent runs: fail only on new findings
    python3 -m coyote --repo . --diff --fail-on-new
```

### Baseline File Format

The baseline is stored as JSON (`.coyote-baseline.json` by default):

```json
{
  "version": "0.3",
  "timestamp": "2024-01-15T10:30:00+00:00",
  "commit": "abc1234",
  "summary": {
    "total": 15,
    "high": 3,
    "medium": 8,
    "low": 4
  },
  "findings": [...]
}
```

**Tip**: Add `.coyote-baseline.json` to your `.gitignore` if you don't want to track it, or commit it if you want consistent baselines across your team.

---

## Git History Scanning

Scan git commit history to find secrets that were ever committed, even if they were later "deleted". **Secrets in git history are still exposed** - anyone with repo access can see them in past commits.

### Why This Matters

```
Commit 1: Added config.py with AWS_KEY="AKIA..."
Commit 2: Removed the secret from config.py

The secret is STILL in git history and can be found with:
  git log -p | grep AKIA
```

Even after "removing" a secret, it remains in your git history forever unless you rewrite history. Coyote's history scan finds these exposed secrets.

### Usage

```bash
# Scan last 100 commits (default)
python3 -m coyote --repo /path/to/repo --history

# Scan more history
python3 -m coyote --repo /path/to/repo --history --max-commits 500

# Scan a specific branch
python3 -m coyote --repo /path/to/repo --history --branch develop

# Fail in CI if secrets found in history
python3 -m coyote --repo /path/to/repo --history --fail-on-new
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--history` | Enable git history scanning mode |
| `--max-commits N` | Maximum commits to scan (default: 100) |
| `--branch BRANCH` | Branch to scan (default: HEAD) |
| `--fail-on-new` | Exit with code 1 if secrets found (for CI) |

### Example Output

```
╭─────────────────────── History Scan: 3 secrets found ────────────────────────╮
│   Commits scanned: 150                                                       │
│   Secrets found:   3 in 2 commits                                            │
│   Severity:        2 HIGH | 1 MED | 0 LOW                                    │
│                                                                              │
│ ┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ Sev  ┃ Commit  ┃ Rule            ┃ File              ┃ Author            ┃ │
│ ┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩ │
│ │ HIGH │ a1b2c3d │ AWS Access Key  │ config.py         │ dev@example.com   │ │
│ │ HIGH │ a1b2c3d │ AWS Secret Key  │ config.py         │ dev@example.com   │ │
│ │  MED │ e4f5g6h │ Generic Secret  │ .env.example      │ dev@example.com   │ │
│ └──────┴─────────┴─────────────────┴───────────────────┴───────────────────┘ │
│                                                                              │
│   ⚠️  These secrets are in git history and may be exposed!                    │
│   Consider rotating credentials and rewriting history.                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### What To Do If Secrets Are Found

1. **Rotate the credentials immediately** - Assume they are compromised
2. **Rewrite git history** (optional but recommended):
   ```bash
   # Using git-filter-repo (recommended)
   pip install git-filter-repo
   git filter-repo --invert-paths --path secrets.py

   # Or using BFG Repo-Cleaner
   bfg --delete-files secrets.py
   ```
3. **Force push** to update remote (requires coordination with team)
4. **Invalidate old credentials** in your cloud provider console

### CI/CD Integration

```yaml
# GitHub Actions - block PRs with secrets in history
- name: Check for secrets in history
  run: |
    python3 -m coyote --repo . --history --max-commits 50 --fail-on-new
```

---

## Entropy-Based Detection

Detect high-randomness strings that are likely secrets, even if they don't match known patterns. This catches:
- Custom API keys and tokens
- Randomly generated passwords
- Internal secrets with non-standard formats

### How It Works

Coyote calculates the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of strings in your code. High entropy = high randomness = likely a secret.

| String Type | Typical Entropy |
|-------------|-----------------|
| English text | ~4.0 bits |
| Code/variables | ~4.0-4.5 bits |
| **Secrets/tokens** | **~5.0-6.0 bits** |
| Random base64 | ~5.5-6.0 bits |

### Usage

```bash
# Enable entropy detection
python3 -m coyote --repo /path/to/repo --entropy

# Adjust sensitivity (lower = more findings, more false positives)
python3 -m coyote --repo /path/to/repo --entropy --entropy-threshold 4.0

# Combine with pattern scanning (default + entropy)
python3 -m coyote --repo /path/to/repo --entropy
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--entropy` | Enable entropy-based detection |
| `--entropy-threshold N` | Entropy threshold (default: 4.5, lower = more sensitive) |

### Example Output

```
╭───────────────────────── Scan Results (2 findings) ──────────────────────────╮
│ ┏━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓ │
│ ┃ Sev  ┃ ID       ┃ Rule                 ┃ File               ┃ Desc       ┃ │
│ ┡━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩ │
│ │  MED │ 39441a36 │ High Entropy (base64)│ config.py:1        │ entropy:   │ │
│ │      │          │                      │                    │ 5.12       │ │
│ │  MED │ 54140021 │ High Entropy (base64)│ tokens.py:3        │ entropy:   │ │
│ │      │          │                      │                    │ 4.89       │ │
│ └──────┴──────────┴──────────────────────┴────────────────────┴────────────┘ │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Confidence Levels

Findings are assigned confidence based on:
- **High**: Very high entropy + near a keyword like "key", "secret", "token"
- **Medium**: High entropy or entropy + keyword context
- **Low**: Borderline entropy, might be false positive

### Reducing False Positives

Coyote automatically filters out:
- UUIDs and git commit hashes
- Version strings
- File paths and URLs
- Common placeholder values
- Repeated characters

If you're getting too many false positives, try increasing the threshold:
```bash
python3 -m coyote --repo . --entropy --entropy-threshold 5.0
```

---

## Finding Suppression

Suppress specific findings that are false positives or accepted risks. Create a `.coyote-ignore` file in your repository root.

### File Format

```bash
# .coyote-ignore - Suppress findings from Coyote scans

# Suppress by finding ID (8 hex chars)
a1b2c3d4                    # False positive - test fixture
e5f6g7h8                    # Accepted risk - example API key

# Suppress by rule name (affects all findings of that type)
rule:Generic Secret         # Too noisy for this codebase
rule:Missing .gitignore     # We use a different ignore mechanism

# Suppress by file path prefix
file:tests/fixtures/        # Test data contains fake secrets
file:docs/examples/         # Documentation examples

# Suppress by file path regex pattern
pattern:.*_test\.py$        # All test files
pattern:mock_.*\.json$      # All mock data files
```

### Usage

```bash
# Scan with default .coyote-ignore in repo root
python3 -m coyote --repo /path/to/repo

# Use a custom ignore file
python3 -m coyote --repo /path/to/repo --ignore-file /path/to/.coyote-ignore

# Disable suppression (scan everything)
python3 -m coyote --repo /path/to/repo --no-ignore
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--ignore-file PATH` | Use a custom ignore file |
| `--no-ignore` | Disable suppression, report all findings |

### Example Output

When findings are suppressed, Coyote shows how many:

```
╭───────────────────────── Scan Results (5 findings) ──────────────────────────╮
│ ...                                                                          │
│   Summary: 2 HIGH | 2 MEDIUM | 1 LOW | 50 files scanned                      │
│   (3 findings suppressed via .coyote-ignore)                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Getting Finding IDs

Run a scan and note the ID column:

```
│ Sev  │ ID       │ Rule           │ File              │
│ HIGH │ 666daffe │ AWS Access Key │ config.py:42      │
```

Then add to your `.coyote-ignore`:
```bash
666daffe  # False positive - AWS example key in docs
```

### Best Practices

1. **Always add a comment** explaining why the finding is suppressed
2. **Prefer ID suppression** over rule suppression for precision
3. **Review suppressed findings periodically** - they might become real issues
4. **Commit your .coyote-ignore** so the whole team benefits
5. **Use file/pattern suppression** for test fixtures and example code

---

## Webhook Notifications

Get instant alerts in Slack or Discord when Coyote detects security issues. Perfect for monitoring repos continuously.

### Supported Platforms

| Platform | Message Format |
|----------|---------------|
| **Slack** | Rich attachments with color-coded severity |
| **Discord** | Embeds with severity breakdown and finding list |

### Quick Start

```bash
# Send a one-time notification with results
python3 -m coyote --repo /path/to/repo --slack-webhook "https://hooks.slack.com/services/XXX/YYY/ZZZ"

# Or Discord
python3 -m coyote --repo /path/to/repo --discord-webhook "https://discord.com/api/webhooks/XXX/YYY"

# Use with diff mode for "new findings only" alerts
python3 -m coyote --repo /path/to/repo --diff --slack-webhook "https://hooks.slack.com/..."
```

### Configuration

Add webhook settings to your `config.yaml`:

```yaml
notifications:
  # Enable notifications
  enabled: true

  # Webhook URLs
  slack_webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  discord_webhook_url: "https://discord.com/api/webhooks/XXX/YYY"

  # When to notify
  notify_on_completion: true       # Notify after every scan
  notify_only_on_findings: false   # Only notify if findings exist
  notify_only_on_new: false        # Only notify on NEW findings (diff mode)

  # Minimum severity to trigger (LOW, MEDIUM, HIGH)
  min_severity: "LOW"

  # Include finding details in message
  include_finding_list: true
  max_findings_in_message: 10
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--notify` | Enable notifications using config file settings |
| `--slack-webhook URL` | Slack webhook URL (overrides config) |
| `--discord-webhook URL` | Discord webhook URL (overrides config) |

### Example Slack Message

```
🚨 Coyote: 3 HIGH severity findings in my-repo

┌─────────────────────────────────────┐
│ HIGH: 3  │  MEDIUM: 5  │  LOW: 2   │
├─────────────────────────────────────┤
│ Findings:                           │
│ • [HIGH] AWS Access Key - config.py │
│ • [HIGH] Private Key - secrets.pem  │
│ • [HIGH] Generic Secret - .env      │
└─────────────────────────────────────┘
```

### Example Discord Message

Discord notifications appear as rich embeds with:
- Color-coded severity (red for HIGH, orange for MEDIUM, blue for LOW)
- Finding count breakdown
- List of detected issues with file locations
- Repository name and scan timestamp

### Setting Up Webhooks

**Slack:**
1. Go to [api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks)
2. Create a new Slack app or use an existing one
3. Enable "Incoming Webhooks"
4. Create a webhook for your channel
5. Copy the webhook URL

**Discord:**
1. Open Server Settings > Integrations > Webhooks
2. Click "New Webhook"
3. Choose the channel and customize the name/avatar
4. Copy the webhook URL

### Watcher Loop with Notifications

```bash
# Watch a repo and get Slack alerts on new findings
./coyote.sh --repo-url https://github.com/org/repo \
            --interval 300 \
            --diff \
            --notify \
            --slack-webhook "https://hooks.slack.com/..."

# The coyote will howl at you when it finds something! 🐺
```

---

## SARIF Output

Coyote supports SARIF (Static Analysis Results Interchange Format) output, the industry-standard format for static analysis tools. SARIF is supported by:
- GitHub Code Scanning
- VS Code SARIF Viewer
- Azure DevOps
- Many other security tools

### Usage

```bash
# Output SARIF to stdout
python3 -m coyote --repo /path/to/repo --sarif -

# Output SARIF to a file
python3 -m coyote --repo /path/to/repo --sarif results.sarif

# Alternative: use --sarif-output
python3 -m coyote --repo /path/to/repo --sarif-output results.sarif

# Combine with other options
python3 -m coyote --repo /path/to/repo --entropy --sarif results.sarif
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--sarif FILE` | Output SARIF to FILE (use `-` for stdout) |
| `--sarif-output FILE` | Write SARIF output to FILE |

### GitHub Code Scanning Integration

Upload SARIF results to GitHub Code Scanning in your CI/CD workflow:

```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]

jobs:
  coyote-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Coyote
        run: pip install -r requirements.txt

      - name: Run Coyote scan
        run: python3 -m coyote --repo . --sarif results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### SARIF Format Details

The SARIF output includes:
- **Tool information**: Coyote version, documentation URL
- **Rules**: All detection rules with descriptions and severity levels
- **Results**: Each finding with location, message, and fingerprints
- **Severity mapping**: HIGH → error, MEDIUM → warning, LOW → note

Example SARIF structure:
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Coyote",
        "version": "0.8.0",
        "rules": [...]
      }
    },
    "results": [
      {
        "ruleId": "coyote/aws-access-key",
        "level": "error",
        "message": { "text": "AWS Access Key ID detected" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "config.py" },
            "region": { "startLine": 42 }
          }
        }]
      }
    ]
  }]
}
```

### Viewing SARIF Results

- **VS Code**: Install the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- **GitHub**: Upload via Code Scanning to see results in the Security tab
- **CLI**: Use `jq` to query the JSON: `jq '.runs[].results | length' results.sarif`

---

## Finding IDs

Every finding includes a stable, deterministic **finding ID** - an 8-character hex string that uniquely identifies the issue.

### How It Works

The ID is generated by hashing key attributes of the finding:
- Rule name (e.g., "AWS Access Key")
- File path (relative)
- Line number
- Matched value

```
Finding ID: 666daffe
Rule: AWS Access Key
File: src/config.py:42
```

### Properties

| Property | Behavior |
|----------|----------|
| **Deterministic** | Same finding always produces the same ID |
| **Stable** | ID remains constant across scan runs |
| **Unique** | Different findings produce different IDs |
| **Location-sensitive** | If line number changes, ID changes |
| **Content-sensitive** | If matched value changes, ID changes |

### Use Cases

- **Diffing scans**: Compare two scan results to find new vs. existing issues
- **Suppression**: Ignore specific findings by ID (planned feature)
- **Tracking**: Monitor finding lifecycle over time
- **CI/CD integration**: Fail builds only on new findings

### Example Output

**JSON Report:**
```json
{
  "id": "666daffe",
  "rule": "AWS Access Key",
  "severity": "HIGH",
  "file": "src/config.py",
  "line": 42
}
```

**Markdown Report:**
```
- **AWS Access Key**: AWS Access Key ID detected
  - ID: `666daffe`
  - Location: `src/config.py:42`
```

**TUI Display:**
```
│ Sev  │ ID       │ Rule           │ File              │
│ HIGH │ 666daffe │ AWS Access Key │ src/config.py:42  │
```

## Testing

### Quick Test: Scan This Repository

```bash
# Scan the coyote repo itself
python3 -m coyote --repo .

# Expected: Will find some MEDIUM findings (the pattern strings in patterns.py
# trigger on themselves - this is expected behavior)
```

### Test with Fake Secrets

Create a test directory with intentional security issues:

```bash
# Create test directory
mkdir -p /tmp/coyote-test
cd /tmp/coyote-test

# Create files with fake secrets
cat > config.py << 'EOF'
# Fake AWS credentials (not real!)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DEBUG = True
password = "supersecretpassword123"
EOF

cat > .env << 'EOF'
SECRET_KEY=fake_secret_for_testing
DATABASE_URL=postgres://user:pass@localhost/db
EOF

cat > app.js << 'EOF'
// Security issues for testing
const data = eval(userInput);
// TODO: security - fix this injection vulnerability
EOF

cat > Component.jsx << 'EOF'
export default function Component({ html }) {
  return <div dangerouslySetInnerHTML={{__html: html}} />;
}
EOF

# Run the scan
cd /path/to/coyote-repo-scanner
python3 -m coyote --repo /tmp/coyote-test

# Clean up
rm -rf /tmp/coyote-test
```

**Expected Output:**
- HIGH: AWS Access Key found in `config.py`
- HIGH: Generic Secret (password) in `config.py`
- HIGH: Sensitive File `.env`
- MEDIUM: Debug Mode Enabled in `config.py`
- MEDIUM: Eval Usage in `app.js`
- MEDIUM: Security Debt Marker in `app.js`
- MEDIUM: dangerouslySetInnerHTML in `Component.jsx`
- LOW: Missing .gitignore

### Test the TUI

```bash
# Interactive mode (requires terminal with raw input support)
python3 -m coyote --repo /tmp/coyote-test --interactive

# Press 'S' to scan, 'R' to save report, 'Q' to quit
```

### Test Report Generation

```bash
# Generate reports
python3 -m coyote --repo /tmp/coyote-test --report

# Check the reports directory
ls -la reports/
cat reports/coyote_report_*.md
cat reports/coyote_report_*.json
```

### Test the Watcher Loop

```bash
# Watch a public repo (will clone it first)
./coyote.sh --repo-url https://github.com/octocat/Hello-World --once

# Or watch with polling (Ctrl+C to stop)
./coyote.sh --repo-url https://github.com/octocat/Hello-World --interval 30
```

### Test Baseline / Diff Mode

```bash
# Step 1: Create a baseline from the test directory
python3 -m coyote --repo /tmp/coyote-test --save-baseline --baseline-path /tmp/test-baseline.json

# Step 2: Add a new security issue
echo 'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"' >> /tmp/coyote-test/config.py

# Step 3: Run diff to see the new finding
python3 -m coyote --repo /tmp/coyote-test --diff --baseline-path /tmp/test-baseline.json

# Expected output:
#   NEW:        1  (1 HIGH, 0 MED, 0 LOW)   <- The new GitHub token
#   FIXED:      0
#   EXISTING:   8                           <- Original findings

# Step 4: Test CI mode (should exit with code 1)
python3 -m coyote --repo /tmp/coyote-test --diff --fail-on-new --baseline-path /tmp/test-baseline.json
echo "Exit code: $?"  # Should print: Exit code: 1
```

### Test Webhook Notifications

```bash
# Test Slack notification (replace with your webhook URL)
python3 -m coyote --repo /tmp/coyote-test \
    --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Test Discord notification
python3 -m coyote --repo /tmp/coyote-test \
    --discord-webhook "https://discord.com/api/webhooks/YOUR/WEBHOOK"

# Test with diff mode (only notifies on new findings)
python3 -m coyote --repo /tmp/coyote-test --diff \
    --baseline-path /tmp/test-baseline.json \
    --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# You should see output like:
# Slack: Slack notification sent
```

**Tip**: For testing without a real webhook, you can use [webhook.site](https://webhook.site) to get a temporary URL and inspect the payloads Coyote sends.

### Test Finding Suppression

```bash
# Create test repo with a finding
mkdir -p /tmp/suppress-test
echo 'API_KEY = "AKIAIOSFODNN7EXAMPLE"' > /tmp/suppress-test/config.py

# Scan and note the finding ID
python3 -m coyote --repo /tmp/suppress-test
# Look for: │ HIGH │ 666daffe │ AWS Access Key │ config.py:1

# Create ignore file to suppress it
echo "666daffe  # False positive - example key" > /tmp/suppress-test/.coyote-ignore

# Scan again - finding should be suppressed
python3 -m coyote --repo /tmp/suppress-test
# Expected: "(1 findings suppressed via .coyote-ignore)"

# Test rule-based suppression
echo "rule:AWS Access Key" > /tmp/suppress-test/.coyote-ignore
python3 -m coyote --repo /tmp/suppress-test
# Expected: All AWS Access Key findings suppressed

# Disable suppression to see all findings
python3 -m coyote --repo /tmp/suppress-test --no-ignore

# Cleanup
rm -rf /tmp/suppress-test
```

### Test Entropy Detection

```bash
# Create test files with high-entropy strings
mkdir -p /tmp/entropy-test
cd /tmp/entropy-test

# A custom token that wouldn't match known patterns
echo 'my_token = "aX7kL9mN2pQ5rS8tU1vW4xY7zA0bC3dE6fG9hJ2kL5"' > tokens.py

# A normal variable (low entropy) - should NOT be flagged
echo 'greeting = "hello world how are you today"' >> tokens.py

# Run with entropy detection
cd /path/to/coyote-repo-scanner
python3 -m coyote --repo /tmp/entropy-test --entropy

# Expected: Finds "High Entropy (base64)" for the token
# The greeting string should NOT be flagged (low entropy)

# Test with different thresholds
python3 -m coyote --repo /tmp/entropy-test --entropy --entropy-threshold 5.0  # Less sensitive
python3 -m coyote --repo /tmp/entropy-test --entropy --entropy-threshold 4.0  # More sensitive

# Cleanup
rm -rf /tmp/entropy-test
```

### Test Git History Scanning

```bash
# Create a test repo with a secret that gets "removed"
mkdir -p /tmp/history-test && cd /tmp/history-test
git init

# Commit 1: innocent file
echo "hello" > readme.txt
git add readme.txt && git commit -m "initial"

# Commit 2: add a secret
echo 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"' > config.py
git add config.py && git commit -m "added config"

# Commit 3: "remove" the secret
echo "# cleaned" > config.py
git add config.py && git commit -m "removed secret"

# Now scan history - should find the secret from commit 2!
cd /path/to/coyote-repo-scanner
python3 -m coyote --repo /tmp/history-test --history

# Expected: Finds 1 HIGH severity finding (AWS Access Key) in commit 2
# Even though it was "removed" in commit 3, it's still in git history!

# Cleanup
rm -rf /tmp/history-test
```

### Unit Test the Scanner Module

```python
python3 << 'EOF'
import tempfile
import os
import shutil

from coyote.scanner import run_scan
from coyote.patterns import Severity

# Create test repo
test_dir = tempfile.mkdtemp()

# Add a file with a fake AWS key
with open(os.path.join(test_dir, "config.py"), "w") as f:
    f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

# Run scan
result = run_scan(test_dir)

# Assertions
assert result.total_count >= 1, "Should find at least 1 issue"
assert result.high_count >= 1, "Should find at least 1 HIGH issue"

aws_findings = [f for f in result.findings if "AWS" in f.rule_name]
assert len(aws_findings) >= 1, "Should detect AWS key"
assert aws_findings[0].severity == Severity.HIGH

print("All tests passed!")

# Cleanup
shutil.rmtree(test_dir)
EOF
```

### Test Pattern Detection

```python
python3 << 'EOF'
from coyote.patterns import SECRET_PATTERNS, SMELL_PATTERNS
import re

# Test secret patterns
test_cases = [
    ("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", True),
    ("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz12", True),
    ("OpenAI Key", "sk-" + "a" * 48, True),
    ("Slack Token", "xoxb-123-456-abc", True),
    ("Not a secret", "hello world", False),
]

for name, text, should_match in test_cases:
    matched = False
    for pattern in SECRET_PATTERNS:
        if pattern.pattern.search(text):
            matched = True
            break

    status = "PASS" if matched == should_match else "FAIL"
    print(f"[{status}] {name}: '{text[:30]}...' -> matched={matched}")

print("\nPattern tests complete!")
EOF
```

## AI Agent Security

Coyote can analyze OpenClaw/Moltbot AI agents before you run them, helping you understand what capabilities they have and what risks they pose.

### Why Agent Security Matters

When you import an AI agent from Moltbook or other sources, you're giving it access to your machine. Agents can:
- Read sensitive files (SSH keys, credentials, browser data)
- Make network requests (potentially exfiltrating data)
- Execute shell commands
- Spawn other agents
- Self-modify their behavior

Coyote's agent analysis helps you understand these risks **before** running the agent.

### Agent Analysis Commands

```bash
# Analyze an agent config file
python3 -m coyote agent analyze ./my-agent.json

# Output in different formats
python3 -m coyote agent analyze ./my-agent.json --format markdown
python3 -m coyote agent analyze ./my-agent.json --format json

# Register agent for tracking
python3 -m coyote agent analyze ./my-agent.json --register

# Show permission changes between versions
python3 -m coyote agent diff my-agent-id

# Generate runtime security policy
python3 -m coyote agent policy my-agent-id --strict

# List all tracked agents
python3 -m coyote agent list
```

### Example Safety Summary

```
============================================================
AGENT SAFETY SUMMARY
============================================================

Agent: File Manager Pro
Version: 1.2.0
Author: random-dev-42

Overall Risk:  CRITICAL

Capabilities by Risk Level:
   CRITICAL: 3
   HIGH: 2
   MEDIUM: 12

HIGH-RISK CAPABILITIES:
----------------------------------------
   Read Files
     Scope: ~/.ssh/config
     Why risky: SSH keys provide authentication to remote systems

   Run Commands
     Scope: execute_command
     Why risky: Can execute arbitrary system commands
```

### Permission Diffing

When agents are updated, Coyote tracks what changed:

```
============================================================
AGENT PERMISSION CHANGES
============================================================

Agent: file-manager-pro
Version: 1.2.0 -> 1.3.0

RISK ESCALATIONS:
----------------------------------------
  Read Kubernetes config
    NONE -> CRITICAL
    Scope: ~/.kube/config

NEW CAPABILITIES (3):
----------------------------------------
  +  Spawn Agents: spawn_agent
  +  Execute Code: eval_script
```

### Risk Levels

| Level | Meaning | Examples |
|-------|---------|----------|
| CRITICAL | Severe risk, requires careful review | SSH key access, code evaluation, shell execution |
| HIGH | Significant risk | Credential access, agent spawning, browser data |
| MEDIUM | Noteworthy | File read/write, network requests |
| LOW | Minor concern | System info, clipboard access |

### Capability Categories

| Category | Description |
|----------|-------------|
| `file_read` | Read files from filesystem |
| `file_write` | Write/modify files |
| `network_outbound` | Make HTTP/WebSocket requests |
| `process_spawn` | Execute shell commands |
| `code_execution` | Eval/exec dynamic code |
| `secret_access` | Access stored credentials |
| `self_modification` | Modify own config/prompt |
| `agent_spawning` | Create other agents |
| `browser_access` | Control browser, read data |

---

## Project Structure

```
coyote-repo-scanner/
├── coyote.sh              # Bash watcher/runner script
├── coyote/
│   ├── __init__.py        # Package init (version)
│   ├── __main__.py        # Entry point for python -m coyote
│   ├── patterns.py        # Regex patterns for repo scanning
│   ├── scanner.py         # Core repo scanning engine
│   ├── coyote_art.py      # ASCII art poses
│   ├── tui.py             # Rich-based terminal UI
│   ├── config.py          # YAML configuration loader
│   ├── reporter.py        # JSON/Markdown/SARIF report generation
│   ├── sarif.py           # SARIF output format
│   ├── baseline.py        # Scan diffing/baseline
│   ├── entropy.py         # Entropy-based detection
│   ├── history.py         # Git history scanning
│   ├── suppress.py        # Finding suppression
│   ├── notifications.py   # Webhook notifications
│   └── agents/            # AI Agent Security module
│       ├── __init__.py    # Agent security exports
│       ├── analyzer.py    # Static analysis engine
│       ├── models.py      # Data models (Capability, Manifest, etc.)
│       ├── tracker.py     # Permission tracking and diffing
│       ├── runtime.py     # Runtime guardrails
│       ├── output.py      # Safety summary generation
│       └── examples/      # Example agent configs
├── config.example.yaml    # Example configuration
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Coyote Poses

The coyote character changes based on scanner state:

**Idle/Watching** (howling coyote silhouette):
```
                       .
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / o       <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
```

**Alert/Found Issues** (hackles up):
```
                       . !
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / O    !  <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /^^^\_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
```

**Scanning** (sniffing the air):
```
                       .     ~
                      /|    ~
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / -       <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
```

**All Clear** (happy):
```
                       .
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / ^       <   |
            /  __\_w_//    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
```

## Limitations

- **Self-Detection**: The scanner may flag its own pattern definitions as matches (expected behavior)
- **No Auto-Remediation**: Reports issues but doesn't automatically fix them
- **Pattern-Based**: While entropy detection helps, some custom secrets may require adding custom patterns

## Future Improvements

- [x] ~~Git history scanning (detect secrets in past commits)~~ - **Added in v0.5!**
- [x] ~~Webhook notifications (Slack, Discord)~~ - **Added in v0.4!**
- [x] ~~Entropy-based secret detection~~ - **Added in v0.6!**
- [x] ~~Finding suppression by ID~~ - **Added in v0.7!**
- [x] ~~SARIF output for GitHub Code Scanning~~ - **Added in v0.8!**
- [x] ~~AI Agent security analysis~~ - **Added in v0.9!**
- [ ] Custom pattern definitions via config
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Agent runtime sandboxing
- [ ] Community agent reputation scores
- [x] ~~Scan diffing (compare scans to detect new findings)~~ - **Added in v0.3!**

## License

MIT License - see [LICENSE](LICENSE) file.
