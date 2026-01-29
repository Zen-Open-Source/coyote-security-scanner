# Coyote

**Autonomous Repository Security Scanner**

Coyote monitors public GitHub repos, detects new commits, and scans for security issues. It features a TUI with an ASCII coyote character that reacts to scan results.

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

- **Continuous Monitoring**: Polls GitHub repos for new commits and auto-scans on changes
- **Comprehensive Detection**: Secrets, credentials, sensitive files, and security anti-patterns
- **Rich TUI**: Interactive terminal interface with live updates and keyboard controls
- **Multiple Output Formats**: JSON and Markdown reports
- **Stable Finding IDs**: Deterministic IDs for each finding enable diffing, suppression, and tracking
- **Configurable**: YAML-based configuration with sensible defaults

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

### Scan a Local Repository

```bash
# Single scan with TUI output
python3 -m coyote --repo /path/to/your/repo

# Save reports after scanning
python3 -m coyote --repo /path/to/your/repo --report
```

### Interactive Mode

```bash
# Launch the full TUI with keyboard controls
python3 -m coyote --repo /path/to/your/repo --interactive
```

**Keyboard Controls:**
- `S` - Run scan now
- `R` - Save report
- `Q` - Quit

### Watch a Remote Repository

```bash
# Monitor a GitHub repo for new commits
./coyote.sh --repo-url https://github.com/user/repo --interval 60

# Run once and exit
./coyote.sh --repo-url https://github.com/user/repo --once
```

## Usage

### Python Module

```bash
python3 -m coyote [OPTIONS]

Options:
  --repo PATH        Path to repository to scan
  --config FILE      Path to config file (default: config.yaml)
  --interactive, -i  Run interactive TUI
  --report, -r       Save reports after scan
```

### Bash Watcher

```bash
./coyote.sh [OPTIONS]

Options:
  --repo-url URL       GitHub repo URL to watch
  --branch NAME        Branch to watch (default: main)
  --local-path PATH    Local clone path (default: ./watched_repo)
  --interval SECONDS   Poll interval in seconds (default: 60)
  --once               Run scan once and exit
  --interactive, -i    Launch interactive TUI
  --report, -r         Save reports after scan
  --config FILE        Config file path (default: config.yaml)
  --help, -h           Show help
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

## Project Structure

```
coyote-repo-scanner/
├── coyote.sh              # Bash watcher loop
├── coyote/
│   ├── __init__.py        # Package init (version)
│   ├── __main__.py        # Entry point for python -m coyote
│   ├── patterns.py        # Regex patterns for detection
│   ├── scanner.py         # Core scanning engine
│   ├── coyote_art.py      # ASCII art poses
│   ├── tui.py             # Rich-based terminal UI
│   ├── config.py          # YAML configuration loader
│   └── reporter.py        # JSON/Markdown report generation
├── config.example.yaml    # Example configuration
├── requirements.txt       # Python dependencies
├── progress.txt           # Build log and learnings
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

- **No Git History Scanning**: Currently only scans the current working tree, not historical commits
- **No Entropy Analysis**: Relies on pattern matching, not entropy-based secret detection
- **Self-Detection**: The scanner may flag its own pattern definitions as matches (expected behavior)
- **No Auto-Remediation**: Reports issues but doesn't automatically fix them

## Future Improvements

- [ ] Git history scanning (detect secrets in past commits)
- [ ] Webhook notifications (Slack, Discord, email)
- [ ] Entropy-based secret detection
- [ ] Custom pattern definitions via config
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Scan diffing (compare scans to detect new findings) - enabled by finding IDs
- [ ] Finding suppression by ID (ignore known false positives) - enabled by finding IDs

## License

MIT License - see [LICENSE](LICENSE) file.
