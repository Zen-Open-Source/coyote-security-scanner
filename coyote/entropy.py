"""Entropy-based secret detection for Coyote.

Uses Shannon entropy to detect high-randomness strings that are likely
secrets, even if they don't match known patterns. This catches:
- Custom API keys and tokens
- Randomly generated passwords
- Base64-encoded secrets
- Hex-encoded secrets
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Generator

from .patterns import Severity


# Character set patterns for classification
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS = set("0123456789abcdefABCDEF")
ALPHANUMERIC_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# Keywords that suggest a string might be a secret
SECRET_KEYWORDS = [
    "key", "secret", "token", "password", "passwd", "pwd", "auth",
    "credential", "api_key", "apikey", "access_key", "private",
    "bearer", "authorization", "api-key", "api_secret", "client_secret",
]

# Patterns to extract potential secret strings
# Matches quoted strings and assignment values
STRING_PATTERNS = [
    # Double-quoted strings
    re.compile(r'"([^"]{20,})"'),
    # Single-quoted strings
    re.compile(r"'([^']{20,})'"),
    # Assignment values (key=value, key: value)
    re.compile(r'[=:]\s*([A-Za-z0-9+/=_\-]{20,})(?:\s|$|"|\'|,|;)'),
    # Backtick strings
    re.compile(r'`([^`]{20,})`'),
]

# False positive patterns - things that look high-entropy but aren't secrets
FALSE_POSITIVE_PATTERNS = [
    # UUIDs
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
    # Git commit hashes
    re.compile(r'^[0-9a-f]{40}$', re.I),
    # Short git hashes
    re.compile(r'^[0-9a-f]{7,8}$', re.I),
    # Version strings
    re.compile(r'^\d+\.\d+\.\d+'),
    # File paths
    re.compile(r'^[/\\]|[/\\].*[/\\]'),
    # URLs (without credentials)
    re.compile(r'^https?://[^:@]+$'),
    # Common placeholder values
    re.compile(r'^(xxx+|your[_-]?(key|token|secret)|example|placeholder|changeme|todo)', re.I),
    # Lorem ipsum
    re.compile(r'lorem|ipsum', re.I),
    # Repeated characters
    re.compile(r'^(.)\1{5,}$'),
    # All same case letters (likely not a secret)
    re.compile(r'^[a-z]+$'),
    re.compile(r'^[A-Z]+$'),
    # Package/module names (dots and underscores, no mixed case randomness)
    re.compile(r'^[a-z][a-z0-9_.]+[a-z0-9]$'),
]


@dataclass
class EntropyFinding:
    """A potential secret found via entropy analysis."""

    string_value: str
    entropy: float
    char_set: str  # "base64", "hex", "alphanumeric", "mixed"
    file_path: str
    line_number: int
    line_content: str
    context_keyword: str  # Nearby keyword that triggered detection, if any
    confidence: str  # "high", "medium", "low"

    @property
    def masked_value(self) -> str:
        """Return masked version of the string for display."""
        if len(self.string_value) <= 8:
            return "*" * len(self.string_value)
        return self.string_value[:4] + "*" * (len(self.string_value) - 8) + self.string_value[-4:]

    @property
    def severity(self) -> Severity:
        """Map confidence to severity."""
        if self.confidence == "high":
            return Severity.HIGH
        elif self.confidence == "medium":
            return Severity.MEDIUM
        return Severity.LOW


def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy = more random/unpredictable.
    - English text: ~4.0-4.5 bits
    - Random base64: ~5.5-6.0 bits
    - Random hex: ~4.0 bits
    - Passwords/keys: typically 4.5+ bits

    Args:
        s: The string to analyze

    Returns:
        Entropy in bits per character
    """
    if not s:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    length = len(s)
    entropy = 0.0

    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def classify_char_set(s: str) -> str:
    """Classify the character set of a string."""
    chars = set(s)

    if chars <= HEX_CHARS:
        return "hex"
    elif chars <= BASE64_CHARS:
        return "base64"
    elif chars <= ALPHANUMERIC_CHARS:
        return "alphanumeric"
    else:
        return "mixed"


def is_false_positive(s: str) -> bool:
    """Check if a string matches known false positive patterns."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(s):
            return True
    return False


def find_nearby_keyword(line: str, match_start: int) -> str:
    """Find if there's a secret-related keyword near the match."""
    # Check the part of the line before the match
    prefix = line[:match_start].lower()

    for keyword in SECRET_KEYWORDS:
        if keyword in prefix:
            return keyword

    # Also check if line starts with a keyword pattern
    line_lower = line.lower()
    for keyword in SECRET_KEYWORDS:
        if keyword in line_lower:
            return keyword

    return ""


def extract_candidate_strings(line: str) -> Generator[tuple[str, int], None, None]:
    """
    Extract candidate secret strings from a line.

    Yields (string_value, position) tuples.
    """
    for pattern in STRING_PATTERNS:
        for match in pattern.finditer(line):
            value = match.group(1)
            yield (value, match.start(1))


def analyze_string(
    s: str,
    line: str,
    position: int,
    file_path: str,
    line_number: int,
    base_entropy_threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 500,
) -> EntropyFinding | None:
    """
    Analyze a string for potential secret detection.

    Args:
        s: The candidate string
        line: Full line content
        position: Position in line where string starts
        file_path: Path to source file
        line_number: Line number in file
        base_entropy_threshold: Base entropy threshold
        min_length: Minimum string length to consider
        max_length: Maximum string length to consider

    Returns:
        EntropyFinding if string looks like a secret, None otherwise
    """
    # Length checks
    if len(s) < min_length or len(s) > max_length:
        return None

    # Skip false positives
    if is_false_positive(s):
        return None

    # Calculate entropy
    entropy = calculate_entropy(s)

    # Classify character set
    char_set = classify_char_set(s)

    # Adjust threshold based on character set
    # Hex has lower max entropy (~4.0) so lower threshold
    # Base64 can have higher entropy (~6.0) so higher threshold
    if char_set == "hex":
        threshold = base_entropy_threshold - 0.5  # 4.0
    elif char_set == "base64":
        threshold = base_entropy_threshold + 0.5  # 5.0
    else:
        threshold = base_entropy_threshold  # 4.5

    # Check for nearby keywords - lowers threshold
    keyword = find_nearby_keyword(line, position)
    if keyword:
        threshold -= 0.5  # Lower threshold if keyword present

    # Check if entropy exceeds threshold
    if entropy < threshold:
        return None

    # Determine confidence based on how far above threshold
    entropy_margin = entropy - threshold
    if entropy_margin > 1.0 and keyword:
        confidence = "high"
    elif entropy_margin > 0.5 or keyword:
        confidence = "medium"
    else:
        confidence = "low"

    return EntropyFinding(
        string_value=s,
        entropy=entropy,
        char_set=char_set,
        file_path=file_path,
        line_number=line_number,
        line_content=line[:200] if len(line) > 200 else line,
        context_keyword=keyword,
        confidence=confidence,
    )


def scan_content_for_entropy(
    content: str,
    file_path: str,
    entropy_threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 500,
) -> list[EntropyFinding]:
    """
    Scan file content for high-entropy strings.

    Args:
        content: File content to scan
        file_path: Path to file (for reporting)
        entropy_threshold: Base entropy threshold
        min_length: Minimum string length
        max_length: Maximum string length

    Returns:
        List of EntropyFinding objects
    """
    findings: list[EntropyFinding] = []
    seen_values: set[str] = set()  # Deduplicate

    for line_number, line in enumerate(content.split('\n'), start=1):
        # Skip very short lines
        if len(line) < min_length:
            continue

        # Skip comment-heavy lines (but not all comments - secrets can be in comments!)
        stripped = line.strip()
        if stripped.startswith('//') and 'key' not in stripped.lower() and 'secret' not in stripped.lower():
            continue

        # Extract and analyze candidate strings
        for value, position in extract_candidate_strings(line):
            # Skip if we've seen this value
            if value in seen_values:
                continue

            finding = analyze_string(
                value,
                line,
                position,
                file_path,
                line_number,
                entropy_threshold,
                min_length,
                max_length,
            )

            if finding:
                seen_values.add(value)
                findings.append(finding)

    return findings


def generate_entropy_finding_id(finding: EntropyFinding) -> str:
    """Generate a stable ID for an entropy finding."""
    import hashlib

    # Use file, line, and a hash of the value for stability
    value_hash = hashlib.sha256(finding.string_value.encode()).hexdigest()[:8]
    id_source = f"entropy|{finding.file_path}|{finding.line_number}|{value_hash}"
    return hashlib.sha256(id_source.encode()).hexdigest()[:8]
