# Moltsec - Agent Security Analysis for Moltbot/OpenClaw

A security analysis system for AI agents imported from Moltbook into local Moltbot/OpenClaw environments.

## Problem Statement

Users import AI agents from social platforms without understanding:
- What data the agent can access
- What external services it communicates with
- Whether it can exfiltrate data
- How its behavior changes over time

This is the "npm install but with autonomy" problem.

## Solution Overview

Moltsec provides:

1. **Agent Intake Analysis** - Static analysis of agent configs, prompts, and tools
2. **Capability Manifests** - Structured representation of what an agent can do
3. **Permission Diffing** - Track changes when agents are updated
4. **Runtime Guardrails** - Lightweight monitoring and prompting
5. **User-Facing Reports** - Clear, actionable safety summaries

## Quick Start

```bash
# Analyze an agent
python -m moltsec analyze ./my-agent.json

# Register and track an agent
python -m moltsec analyze ./my-agent.json --register

# Show permission changes
python -m moltsec diff my-agent-id

# Generate runtime policy
python -m moltsec policy my-agent-id --strict --output policy.json
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MOLTBOOK AGENT IMPORT FLOW                          │
└─────────────────────────────────────────────────────────────────────────────┘

  Moltbook ──────▶ INTAKE ANALYZER ──────▶ CAPABILITY MANIFEST
  (agent config,     (static analysis)        (structured output)
   prompt, tools)

                           │
                           ▼
                   PERMISSION TRACKER
                   (versioned storage,
                    diff computation)
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
      SAFETY SUMMARY    POLICY FILE    RUNTIME GUARD
      (human-readable)  (.molt-policy)  (action logging,
                                         first-use prompts)
```

## Data Model

### Capability Manifest

```json
{
  "manifest_version": "1.0",
  "metadata": {
    "agent_id": "file-manager-pro",
    "name": "File Manager Pro",
    "version": "1.2.0",
    "author": "random-dev-42"
  },
  "capabilities": [
    {
      "category": "file_read",
      "description": "Read SSH keys and config",
      "scope": "~/.ssh/*",
      "risk_level": "critical",
      "risk_reason": "SSH keys provide authentication to remote systems",
      "source": "prompt",
      "confidence": 1.0
    }
  ],
  "summary": {
    "total_capabilities": 15,
    "max_risk_level": "critical",
    "by_risk": {"critical": 2, "high": 3, "medium": 10}
  }
}
```

### Capability Categories

| Category | Description | Default Risk |
|----------|-------------|--------------|
| `file_read` | Read files from filesystem | Medium |
| `file_write` | Write/modify files | Medium |
| `network_outbound` | Make HTTP/WebSocket requests | Medium |
| `network_inbound` | Accept incoming connections | High |
| `process_spawn` | Execute shell commands | High |
| `code_execution` | Eval/exec dynamic code | Critical |
| `secret_access` | Access stored credentials | High |
| `self_modification` | Modify own config/prompt | Critical |
| `agent_spawning` | Create other agents | High |
| `browser_access` | Control browser, read data | Critical |
| `clipboard_access` | Read/write clipboard | Medium |

### Risk Levels

| Level | Meaning | Default Action |
|-------|---------|----------------|
| `none` | No security concern | Allow |
| `low` | Minor concern | Allow |
| `medium` | Noteworthy | Log |
| `high` | Significant risk | Prompt |
| `critical` | Severe risk | Block or Prompt |

## Components

### 1. Analyzer (`analyzer.py`)

Static analysis using deterministic pattern matching:

```python
from moltsec import analyze_agent

manifest = analyze_agent(
    agent_id="my-agent",
    config={"name": "My Agent", "tools": [...]},
    prompt="You are a helpful assistant that can read files...",
    tools=[{"name": "bash", "description": "Run shell commands"}]
)

print(f"Risk level: {manifest.max_risk_level}")
for cap in manifest.capabilities:
    if cap.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        print(f"  - {cap.description}: {cap.scope}")
```

**Pattern Categories:**
- File access patterns (SSH keys, AWS creds, .env files)
- Network patterns (HTTP requests, webhooks, WebSockets)
- Execution patterns (shell, eval, subprocess)
- Self-modification patterns (update self, download code)
- Agent spawning patterns (create/delegate agents)
- Secret access patterns (API keys, keychain, vault)

**When to use LLM analysis:**
The analyzer is deterministic by default. LLM analysis could be added for:
- Inferring capabilities from vague tool descriptions
- Detecting prompt injection vulnerabilities
- Understanding complex multi-step attack chains

### 2. Permission Tracker (`tracker.py`)

Tracks manifests over time and computes diffs:

```python
from moltsec import PermissionTracker

tracker = PermissionTracker()

# Register agent (saves versioned manifest)
path, diff = tracker.register_agent(manifest)

if diff and diff.has_risk_escalation:
    print("WARNING: This update increases risk!")
    for cap, old_risk, new_risk in diff.risk_escalations:
        print(f"  {cap.description}: {old_risk} → {new_risk}")
```

**Storage Structure:**
```
.moltsec/
  manifests/
    <agent_id>/
      v1_0_0_20240115_103000.json
      v1_1_0_20240116_142000.json
      latest.json -> symlink
```

### 3. Runtime Guard (`runtime.py`)

Lightweight runtime monitoring:

```python
from moltsec import RuntimeGuard, AgentPolicy

policy = tracker.generate_policy("my-agent", strictness="normal")
guard = RuntimeGuard(policy, prompt_callback=my_prompt_function)

# Check each action before executing
allowed, reason = guard.check_action(
    category=CapabilityCategory.FILE_READ,
    scope="/etc/passwd",
    detail="Reading system password file"
)

if not allowed:
    print(f"Blocked: {reason}")
```

**Policy Actions:**
- `allow` - Permit without logging
- `log` - Permit and log
- `prompt` - Ask user on first use
- `deny` - Block the action

### 4. Output Generator (`output.py`)

Human-readable safety reports:

```python
from moltsec.output import SafetySummaryGenerator, generate_intake_warning

generator = SafetySummaryGenerator()

# Text summary for terminal
print(generator.generate_text_summary(manifest))

# Markdown for docs/GitHub
print(generator.generate_markdown_summary(manifest))

# Warning message if warranted
warning = generate_intake_warning(manifest)
if warning:
    show_warning_dialog(warning)
```

## Example Output

### Safety Summary (Text)

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

### Permission Diff

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

  Spawn other agents
    NONE -> HIGH
    Scope: spawn_agent

NEW CAPABILITIES (10):
----------------------------------------
  +  Read Files: ~/.kube/*
  +  Spawn Agents: spawn_agent
  +  Execute Code: eval_script
```

## Integration Points

### Moltbot Runtime Hook

```python
# In moltbot/runtime.py

from moltsec import RuntimeGuard, PermissionTracker

class AgentRuntime:
    def __init__(self, agent_config):
        tracker = PermissionTracker()
        manifest = tracker.store.get_latest_manifest(agent_config["id"])
        policy = tracker.generate_policy(agent_config["id"])

        self.guard = RuntimeGuard(
            policy,
            prompt_callback=self.prompt_user
        )

    def execute_tool(self, tool_name, params):
        category = self.tool_to_category(tool_name)
        scope = self.extract_scope(tool_name, params)

        allowed, reason = self.guard.check_action(category, scope)
        if not allowed:
            raise PermissionDenied(reason)

        return self.actually_execute(tool_name, params)
```

### Moltbook Import Hook

```python
# In moltbook/import.py

from moltsec import analyze_agent, PermissionTracker
from moltsec.output import SafetySummaryGenerator, generate_intake_warning

def import_agent(agent_data):
    # Analyze before import
    manifest = analyze_agent(
        agent_id=agent_data["id"],
        config=agent_data,
        prompt=agent_data.get("prompt", ""),
        tools=agent_data.get("tools", [])
    )

    # Show safety summary
    generator = SafetySummaryGenerator()
    print(generator.generate_text_summary(manifest))

    # Show warning if warranted
    warning = generate_intake_warning(manifest)
    if warning:
        if not confirm_with_user(warning):
            return False

    # Track the agent
    tracker = PermissionTracker()
    tracker.register_agent(manifest)

    return True
```

## Limitations

1. **Static analysis only** - Cannot catch runtime-generated capabilities
2. **Pattern-based** - Novel attack patterns may be missed
3. **Confidence varies** - Some capabilities are inferred, not declared
4. **No sandboxing** - Runtime guard logs/prompts but doesn't enforce

## Future Extensions

1. **LLM-assisted analysis** - For ambiguous tool descriptions
2. **Behavior fingerprinting** - Learn normal patterns, detect anomalies
3. **Community reputation** - Trust scores from Moltbook community
4. **Capability attestation** - Cryptographic proofs of declared capabilities
5. **Sandbox integration** - Optional OS-level isolation for high-risk agents

## Security Considerations

- Manifests are stored locally, not sent anywhere
- No network access required for analysis
- Deterministic analysis means reproducible results
- Policy files can be version-controlled
- Audit logs enable forensic analysis

## License

MIT
