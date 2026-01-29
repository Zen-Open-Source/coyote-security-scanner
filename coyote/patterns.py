"""Security detection patterns for Coyote scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class PatternMatch:
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    description: str
    matched_text: str = ""


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str
    near_context: Optional[re.Pattern] = None  # require nearby context


# --- Secrets & Credentials ---

SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
        severity=Severity.HIGH,
        description="AWS Access Key ID detected",
    ),
    SecretPattern(
        name="AWS Secret Key",
        pattern=re.compile(r'(?<![A-Za-z0-9/+])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9/+=])'),
        severity=Severity.HIGH,
        description="Possible AWS Secret Access Key detected",
        near_context=re.compile(r'(?i)(aws|amazon|secret.?access|secret.?key)', re.IGNORECASE),
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        severity=Severity.HIGH,
        description="GitHub personal access token detected",
    ),
    SecretPattern(
        name="GitLab Token",
        pattern=re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
        severity=Severity.HIGH,
        description="GitLab personal access token detected",
    ),
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r'xox[baprs]-[0-9A-Za-z\-]+'),
        severity=Severity.HIGH,
        description="Slack API token detected",
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
        severity=Severity.HIGH,
        description="Slack webhook URL detected",
    ),
    SecretPattern(
        name="Discord Webhook",
        pattern=re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'),
        severity=Severity.HIGH,
        description="Discord webhook URL detected",
    ),
    SecretPattern(
        name="OpenAI Key",
        pattern=re.compile(r'sk-[A-Za-z0-9]{48}'),
        severity=Severity.HIGH,
        description="OpenAI API key detected",
    ),
    SecretPattern(
        name="Anthropic Key",
        pattern=re.compile(r'sk-ant-[A-Za-z0-9\-_]{90,}'),
        severity=Severity.HIGH,
        description="Anthropic API key detected",
    ),
    SecretPattern(
        name="Stripe Live Key",
        pattern=re.compile(r'(?:sk|rk)_live_[A-Za-z0-9]{24,}'),
        severity=Severity.HIGH,
        description="Stripe live API key detected",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r'SK[a-f0-9]{32}'),
        severity=Severity.HIGH,
        description="Twilio API key detected",
    ),
    SecretPattern(
        name="SendGrid Key",
        pattern=re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
        severity=Severity.HIGH,
        description="SendGrid API key detected",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        severity=Severity.HIGH,
        description="Google API key detected",
    ),
    SecretPattern(
        name="Private Key",
        pattern=re.compile(r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----'),
        severity=Severity.HIGH,
        description="Private key block detected",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(
            r'''(?i)(?:password|passwd|secret|api_key|apikey|access_token|auth_token|private_key)'''
            r'''[\s]*[=:]\s*['"][^'"]{8,}['"]'''
        ),
        severity=Severity.HIGH,
        description="Hardcoded secret/password assignment detected",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        severity=Severity.HIGH,
        description="JSON Web Token detected",
    ),
    SecretPattern(
        name="Basic Auth URL",
        pattern=re.compile(r'https?://[^:\s]+:[^@\s]+@'),
        severity=Severity.HIGH,
        description="URL with embedded credentials detected",
    ),
]


# --- Sensitive Files ---

SENSITIVE_FILE_PATTERNS: list[tuple[str, str, Severity]] = [
    # (glob pattern, description, severity)
    (".env", "Environment file with potential secrets", Severity.HIGH),
    (".env.local", "Local environment file", Severity.HIGH),
    (".env.production", "Production environment file", Severity.HIGH),
    (".env.*", "Environment variant file", Severity.HIGH),
    ("*.pem", "PEM certificate/key file", Severity.HIGH),
    ("*.key", "Private key file", Severity.HIGH),
    ("*.p12", "PKCS#12 certificate file", Severity.HIGH),
    ("*.pfx", "PFX certificate file", Severity.HIGH),
    ("id_rsa", "RSA private key", Severity.HIGH),
    ("id_dsa", "DSA private key", Severity.HIGH),
    ("id_ed25519", "Ed25519 private key", Severity.HIGH),
    ("id_ecdsa", "ECDSA private key", Severity.HIGH),
    ("*.sql", "SQL dump file", Severity.MEDIUM),
    ("*.dump", "Database dump file", Severity.MEDIUM),
    ("*.sqlite", "SQLite database file", Severity.MEDIUM),
    ("*.db", "Database file", Severity.MEDIUM),
    ("*.bak", "Backup file", Severity.LOW),
    ("*.backup", "Backup file", Severity.LOW),
    ("*.old", "Old file backup", Severity.LOW),
    ("credentials.json", "Credentials file", Severity.HIGH),
    ("service-account*.json", "GCP service account key", Severity.HIGH),
    (".htpasswd", "Apache password file", Severity.HIGH),
    (".netrc", "Netrc credentials file", Severity.HIGH),
    (".npmrc", "NPM config (may contain auth tokens)", Severity.MEDIUM),
    ("terraform.tfstate", "Terraform state (may contain secrets)", Severity.HIGH),
    ("*.tfvars", "Terraform variables (may contain secrets)", Severity.MEDIUM),
]

# Patterns for matching sensitive filenames (compiled from the above)
SENSITIVE_FILENAME_EXACT: dict[str, tuple[str, Severity]] = {}
SENSITIVE_FILENAME_GLOBS: list[tuple[str, str, Severity]] = []

for _pat, _desc, _sev in SENSITIVE_FILE_PATTERNS:
    if "*" in _pat:
        SENSITIVE_FILENAME_GLOBS.append((_pat, _desc, _sev))
    else:
        SENSITIVE_FILENAME_EXACT[_pat] = (_desc, _sev)


# --- Security Smells ---

@dataclass
class SmellPattern:
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str
    file_extensions: list[str] = field(default_factory=list)  # empty = all files


SMELL_PATTERNS: list[SmellPattern] = [
    SmellPattern(
        name="Debug Mode Enabled",
        pattern=re.compile(r'DEBUG\s*=\s*(?:True|true|1)'),
        severity=Severity.MEDIUM,
        description="Debug mode appears to be enabled",
        file_extensions=[".py", ".cfg", ".ini", ".conf", ".yaml", ".yml", ".toml", ".env"],
    ),
    SmellPattern(
        name="SSL Verification Disabled",
        pattern=re.compile(r'verify\s*=\s*False'),
        severity=Severity.MEDIUM,
        description="SSL certificate verification is disabled",
        file_extensions=[".py"],
    ),
    SmellPattern(
        name="Node TLS Rejection Disabled",
        pattern=re.compile(r'''NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0'''),
        severity=Severity.MEDIUM,
        description="Node.js TLS certificate rejection is disabled",
        file_extensions=[".js", ".ts", ".mjs", ".cjs", ".env"],
    ),
    SmellPattern(
        name="Permissive CORS",
        pattern=re.compile(r'Access-Control-Allow-Origin.*\*'),
        severity=Severity.MEDIUM,
        description="Overly permissive CORS configuration (allows all origins)",
        file_extensions=[],
    ),
    SmellPattern(
        name="Eval Usage (JS)",
        pattern=re.compile(r'\beval\s*\('),
        severity=Severity.MEDIUM,
        description="Use of eval() poses code injection risk",
        file_extensions=[".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"],
    ),
    SmellPattern(
        name="Eval Usage (Python)",
        pattern=re.compile(r'\beval\s*\('),
        severity=Severity.MEDIUM,
        description="Use of eval() poses code injection risk",
        file_extensions=[".py"],
    ),
    SmellPattern(
        name="dangerouslySetInnerHTML",
        pattern=re.compile(r'dangerouslySetInnerHTML'),
        severity=Severity.MEDIUM,
        description="dangerouslySetInnerHTML usage poses XSS risk",
        file_extensions=[".jsx", ".tsx", ".js", ".ts"],
    ),
    SmellPattern(
        name="Security Debt Marker",
        pattern=re.compile(r'(?i)(?:TODO|FIXME|HACK|XXX)\s*[:\-]?\s*(?:security|auth|password|secret|cred|vuln)'),
        severity=Severity.MEDIUM,
        description="Security-related TODO/FIXME comment found",
        file_extensions=[],
    ),
    SmellPattern(
        name="Hardcoded Internal IP",
        pattern=re.compile(r'(?:192\.168\.|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.)'),
        severity=Severity.MEDIUM,
        description="Hardcoded internal/private IP address detected",
        file_extensions=[],
    ),
]


# --- Git-Specific Checks ---

GITIGNORE_SHOULD_CONTAIN: list[str] = [
    ".env",
    "*.pem",
    "*.key",
    "id_rsa",
    "*.p12",
    "*.pfx",
    ".env.*",
    "*.sqlite",
    "*.db",
    "terraform.tfstate",
    "*.tfvars",
    "credentials.json",
]

# Max size in bytes for binary file warnings
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
