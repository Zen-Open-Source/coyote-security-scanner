"""Attack path analysis for Coyote scanner.

Chains individual findings into exploitable attack paths showing how an
attacker would combine them to escalate from initial access to full
compromise. Each path gets a composite severity score and blast radius.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .patterns import PatternMatch, Severity


class FindingCategory(Enum):
    CREDENTIAL = "credential"
    PRIVATE_KEY = "private_key"
    SENSITIVE_FILE = "sensitive_file"
    NETWORK_WEAKNESS = "network_weak"
    CODE_INJECTION = "code_injection"
    DEBUG_CONFIG = "debug_config"
    INFRASTRUCTURE = "infrastructure"
    AUTH_TOKEN = "auth_token"
    GATEWAY_EXPLOIT = "gateway_exploit"
    WEBSOCKET_ISSUE = "websocket"


# Map rule_name -> FindingCategory
RULE_CATEGORY_MAP: dict[str, FindingCategory] = {
    # CREDENTIAL
    "AWS Access Key": FindingCategory.CREDENTIAL,
    "AWS Secret Key": FindingCategory.CREDENTIAL,
    "GitHub Token": FindingCategory.CREDENTIAL,
    "GitLab Token": FindingCategory.CREDENTIAL,
    "Slack Token": FindingCategory.CREDENTIAL,
    "Slack Webhook": FindingCategory.CREDENTIAL,
    "Discord Webhook": FindingCategory.CREDENTIAL,
    "OpenAI Key": FindingCategory.CREDENTIAL,
    "Anthropic Key": FindingCategory.CREDENTIAL,
    "Stripe Live Key": FindingCategory.CREDENTIAL,
    "Twilio API Key": FindingCategory.CREDENTIAL,
    "SendGrid Key": FindingCategory.CREDENTIAL,
    "Google API Key": FindingCategory.CREDENTIAL,
    "Generic Secret": FindingCategory.CREDENTIAL,
    # PRIVATE_KEY
    "Private Key": FindingCategory.PRIVATE_KEY,
    # AUTH_TOKEN
    "JWT Token": FindingCategory.AUTH_TOKEN,
    "Basic Auth URL": FindingCategory.AUTH_TOKEN,
    # SENSITIVE_FILE
    "Sensitive File": FindingCategory.SENSITIVE_FILE,
    # DEBUG_CONFIG
    "Debug Mode Enabled": FindingCategory.DEBUG_CONFIG,
    # NETWORK_WEAKNESS
    "SSL Verification Disabled": FindingCategory.NETWORK_WEAKNESS,
    "Node TLS Rejection Disabled": FindingCategory.NETWORK_WEAKNESS,
    "Permissive CORS": FindingCategory.NETWORK_WEAKNESS,
    # CODE_INJECTION
    "Eval Usage (JS)": FindingCategory.CODE_INJECTION,
    "Eval Usage (Python)": FindingCategory.CODE_INJECTION,
    "dangerouslySetInnerHTML": FindingCategory.CODE_INJECTION,
    # INFRASTRUCTURE
    "Hardcoded Internal IP": FindingCategory.INFRASTRUCTURE,
    "Security Debt Marker": FindingCategory.INFRASTRUCTURE,
    # GATEWAY_EXPLOIT
    "Clawdbot GatewayUrl Query Override": FindingCategory.GATEWAY_EXPLOIT,
    # WEBSOCKET_ISSUE
    "Clawdbot WebSocket Origin Not Validated": FindingCategory.WEBSOCKET_ISSUE,
}


@dataclass
class ChainRule:
    name: str
    source_category: FindingCategory
    target_category: FindingCategory
    relationship: str
    escalated_severity: str
    blast_radius: str
    title_template: str
    description_template: str


CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        name="cred_network",
        source_category=FindingCategory.CREDENTIAL,
        target_category=FindingCategory.NETWORK_WEAKNESS,
        relationship="enables abuse via",
        escalated_severity="CRITICAL",
        blast_radius="Account compromise via credential theft + CORS/SSL bypass",
        title_template="Credential Theft -> API Abuse",
        description_template="Attacker steals {source} and exploits {target} to access resources from any origin",
    ),
    ChainRule(
        name="cred_sensitive",
        source_category=FindingCategory.CREDENTIAL,
        target_category=FindingCategory.SENSITIVE_FILE,
        relationship="leaks alongside",
        escalated_severity="CRITICAL",
        blast_radius="Environment compromise with credential leakage",
        title_template="Credential + Config Exposure",
        description_template="Credential {source} found alongside sensitive file {target}, enabling full environment compromise",
    ),
    ChainRule(
        name="debug_injection",
        source_category=FindingCategory.DEBUG_CONFIG,
        target_category=FindingCategory.CODE_INJECTION,
        relationship="amplifies",
        escalated_severity="CRITICAL",
        blast_radius="RCE via debug mode + code injection",
        title_template="Debug Mode -> RCE",
        description_template="Debug mode {source} combined with {target} enables remote code execution",
    ),
    ChainRule(
        name="privkey_infra",
        source_category=FindingCategory.PRIVATE_KEY,
        target_category=FindingCategory.INFRASTRUCTURE,
        relationship="enables lateral movement via",
        escalated_severity="CRITICAL",
        blast_radius="Lateral movement across internal network",
        title_template="Private Key -> Lateral Movement",
        description_template="Private key {source} combined with {target} enables lateral movement across infrastructure",
    ),
    ChainRule(
        name="auth_network",
        source_category=FindingCategory.AUTH_TOKEN,
        target_category=FindingCategory.NETWORK_WEAKNESS,
        relationship="can be hijacked via",
        escalated_severity="HIGH",
        blast_radius="Session hijacking via token + network bypass",
        title_template="Token Hijack -> Session Theft",
        description_template="Auth token {source} can be hijacked via {target} for session takeover",
    ),
    ChainRule(
        name="gateway_websocket",
        source_category=FindingCategory.GATEWAY_EXPLOIT,
        target_category=FindingCategory.WEBSOCKET_ISSUE,
        relationship="chains with",
        escalated_severity="CRITICAL",
        blast_radius="Full RCE via agent hijack (CVE-2026-25253)",
        title_template="Gateway Override -> Agent Hijack",
        description_template="Gateway URL override {source} chains with {target} for full agent RCE",
    ),
    ChainRule(
        name="injection_network",
        source_category=FindingCategory.CODE_INJECTION,
        target_category=FindingCategory.NETWORK_WEAKNESS,
        relationship="exfiltrates data via",
        escalated_severity="HIGH",
        blast_radius="Data exfiltration via injected code",
        title_template="Code Injection -> Data Exfiltration",
        description_template="Code injection {source} exploits {target} to exfiltrate data",
    ),
    ChainRule(
        name="sensitive_infra",
        source_category=FindingCategory.SENSITIVE_FILE,
        target_category=FindingCategory.INFRASTRUCTURE,
        relationship="reveals",
        escalated_severity="HIGH",
        blast_radius="Network reconnaissance from config exposure",
        title_template="Config Exposure -> Network Recon",
        description_template="Sensitive file {source} reveals {target} enabling network reconnaissance",
    ),
    ChainRule(
        name="auth_injection",
        source_category=FindingCategory.AUTH_TOKEN,
        target_category=FindingCategory.CODE_INJECTION,
        relationship="escalates via",
        escalated_severity="CRITICAL",
        blast_radius="Privilege escalation via token + injection",
        title_template="Token + Injection -> Privilege Escalation",
        description_template="Auth token {source} combined with {target} enables privilege escalation",
    ),
    ChainRule(
        name="cred_injection",
        source_category=FindingCategory.CREDENTIAL,
        target_category=FindingCategory.CODE_INJECTION,
        relationship="enables authenticated execution via",
        escalated_severity="CRITICAL",
        blast_radius="Full compromise via authenticated code execution",
        title_template="Credential + Injection -> Full Compromise",
        description_template="Credential {source} enables authenticated code execution via {target}",
    ),
]


@dataclass
class AttackNode:
    finding: PatternMatch
    category: FindingCategory
    node_id: str


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    chain_rule_name: str
    relationship: str
    escalated_severity: str


@dataclass
class AttackPath:
    path_id: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    composite_score: float
    blast_radius: str
    escalated_severity: str
    title: str
    description: str


@dataclass
class AttackPathResult:
    paths: list[AttackPath]
    total_findings_analyzed: int
    findings_in_paths: int
    worst_severity: str


SEVERITY_SCORE = {
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
}

ESCALATION_BONUS = {
    "CRITICAL": 2.0,
    "HIGH": 1.0,
    "MEDIUM": 0.5,
}


class AttackPathAnalyzer:
    """Analyzes scan findings to identify exploitable attack paths."""

    def analyze(self, findings: list[PatternMatch]) -> AttackPathResult:
        # Step 1: Categorize findings
        nodes: list[AttackNode] = []
        for f in findings:
            cat = RULE_CATEGORY_MAP.get(f.rule_name)
            if cat is None:
                continue
            nodes.append(AttackNode(finding=f, category=cat, node_id=f.finding_id))

        if not nodes:
            return AttackPathResult(
                paths=[], total_findings_analyzed=len(findings),
                findings_in_paths=0, worst_severity="NONE",
            )

        # Step 2: Build adjacency via chain rules
        # node_id -> AttackNode
        node_map = {n.node_id: n for n in nodes}
        # adjacency: source_id -> list[(target_id, ChainRule)]
        adjacency: dict[str, list[tuple[str, ChainRule]]] = {}

        for rule in CHAIN_RULES:
            sources = [n for n in nodes if n.category == rule.source_category]
            targets = [n for n in nodes if n.category == rule.target_category]
            for s in sources:
                for t in targets:
                    if s.node_id == t.node_id:
                        continue
                    adjacency.setdefault(s.node_id, []).append((t.node_id, rule))

        # Step 3: DFS to find all paths (max depth 4)
        raw_paths: list[tuple[list[str], list[ChainRule]]] = []

        def dfs(current: str, visited: list[str], rules: list[ChainRule], depth: int) -> None:
            if depth > 4:
                return
            neighbors = adjacency.get(current, [])
            extended = False
            for target_id, rule in neighbors:
                if target_id in visited:
                    continue
                extended = True
                new_visited = visited + [target_id]
                new_rules = rules + [rule]
                # Record path at each extension
                raw_paths.append((list(new_visited), list(new_rules)))
                dfs(target_id, new_visited, new_rules, depth + 1)
            # No need to record dead-ends without edges

        for node_id in adjacency:
            dfs(node_id, [node_id], [], 1)

        # Step 4: Deduplicate by frozenset of node_ids, keep highest scoring
        seen: dict[str, AttackPath] = {}
        for node_ids, rules in raw_paths:
            if len(rules) == 0:
                continue
            path_key = hashlib.sha256(
                str(sorted(node_ids)).encode()
            ).hexdigest()[:12]

            path_nodes = [node_map[nid] for nid in node_ids if nid in node_map]
            path_edges = []
            for i, rule in enumerate(rules):
                path_edges.append(AttackEdge(
                    source_id=node_ids[i],
                    target_id=node_ids[i + 1],
                    chain_rule_name=rule.name,
                    relationship=rule.relationship,
                    escalated_severity=rule.escalated_severity,
                ))

            # Find highest escalation in edges
            escalation_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
            best_escalation = max(
                (e.escalated_severity for e in path_edges),
                key=lambda s: escalation_order.get(s, 0),
            )

            # Score
            base = min(sum(SEVERITY_SCORE.get(n.finding.severity, 1.0) for n in path_nodes), 6.0)
            chain_bonus = min(len(path_edges) * 0.5, 2.0)
            esc_bonus = ESCALATION_BONUS.get(best_escalation, 0.0)
            composite = min(base + chain_bonus + esc_bonus, 10.0)

            # Build title/description from the last rule (most impactful)
            last_rule = rules[-1]
            title = last_rule.title_template
            source_name = path_nodes[0].finding.rule_name
            target_name = path_nodes[-1].finding.rule_name
            description = last_rule.description_template.format(
                source=source_name, target=target_name,
            )
            blast_radius = last_rule.blast_radius

            path = AttackPath(
                path_id=path_key,
                nodes=path_nodes,
                edges=path_edges,
                composite_score=composite,
                blast_radius=blast_radius,
                escalated_severity=best_escalation,
                title=title,
                description=description,
            )

            if path_key not in seen or seen[path_key].composite_score < composite:
                seen[path_key] = path

        # Step 5: Sort by score descending
        paths = sorted(seen.values(), key=lambda p: p.composite_score, reverse=True)

        # Gather stats
        finding_ids_in_paths = set()
        for p in paths:
            for n in p.nodes:
                finding_ids_in_paths.add(n.node_id)

        worst = "NONE"
        if paths:
            worst = paths[0].escalated_severity

        return AttackPathResult(
            paths=paths,
            total_findings_analyzed=len(findings),
            findings_in_paths=len(finding_ids_in_paths),
            worst_severity=worst,
        )
