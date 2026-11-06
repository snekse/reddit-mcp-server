export type ScanFinding = {
  readonly ruleId: string
  readonly category:
    "prompt_injection" | "mcp_tool_poisoning" | "unicode_smuggling" | "malicious_command" | "suspicious_url"
  readonly severity: "high" | "medium"
  readonly description: string
  readonly snippet: string
}

export type ScanResult = {
  readonly quarantined: boolean
  readonly findings: readonly ScanFinding[]
}

export type QuarantinedItemRecord = {
  readonly itemType: "post" | "comment"
  readonly id: string
  readonly subreddit: string
  readonly author: string
  readonly createdUtc: number
  readonly permalink: string
  readonly findings: readonly ScanFinding[]
  readonly excerpt: string
  readonly scannedAt: string
}

type DetectionRule = {
  readonly id: string
  readonly category: ScanFinding["category"]
  readonly severity: ScanFinding["severity"]
  readonly description: string
  readonly pattern: RegExp
}

// Tuned per OWASP LLM01:2025, Invariant Labs / CSA MCP Tool-Poisoning advisories, and CVE-2021-42574
// to catch indirect prompt injection, MCP tool hijacking, invisible Unicode tag/bidi smuggling,
// and shell/beacon traps while avoiding false positives on pinball/electronics terminology
// (e.g., "kill switch", "Williams System 11", "blow a fuse", "short circuit", "crimp terminal", "EPROM dump").
const DETECTION_RULES: readonly DetectionRule[] = [
  {
    id: "PI_IGNORE_INSTRUCTIONS",
    category: "prompt_injection",
    severity: "high",
    description: "Attempts to override or ignore prior LLM/system instructions (OWASP LLM01)",
    pattern:
      /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|developer)\s+(?:instructions|prompts|rules|directives|guidelines)\b/i,
  },
  {
    id: "PI_SYSTEM_DELIMITER",
    category: "prompt_injection",
    severity: "high",
    description: "Spoofs LLM chat/system template delimiters",
    pattern:
      /(?:<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[\/?INST\]|<<SYS>>|<\/?(?:system_prompt|system_instructions|claude_instructions)>)/i,
  },
  {
    id: "PI_ROLE_HIJACK",
    category: "prompt_injection",
    severity: "high",
    description: "Directs an AI assistant/agent to adopt a new persona or execute hidden instructions",
    pattern:
      /\b(?:new\s+instructions\s+for\s+(?:the\s+)?(?:ai|assistant|agent|llm|model)|important\s+message\s+for\s+(?:the\s+)?(?:ai|assistant|claude|gemini|chatgpt)|as\s+an\s+ai\s+assistant\s+reading\s+this)\b/i,
  },
  {
    id: "MCP_TOOL_POISONING",
    category: "mcp_tool_poisoning",
    severity: "high",
    description: "Contains pseudo-MCP/tool invocation tags or sensitive credential exfiltration directives",
    pattern:
      /(?:<\s*\/?\s*(?:tool_call|function_call|function_calls|antml:function_calls|mcp_tool|use_mcp_tool|system_instruction)\b[^>]*>|\b(?:send|upload|exfiltrate|post|append)\s+(?:the\s+contents\s+of\s+)?(?:~\/\.ssh|\/etc\/passwd|\/etc\/shadow|\.env\b|id_rsa|api[_-]?key|client[_-]?secret|claude_desktop_config|mcp_config\.json))/i,
  },
  {
    id: "UNICODE_TAG_SMUGGLING",
    category: "unicode_smuggling",
    severity: "high",
    description: "Contains invisible Unicode Tag block characters (U+E0000..U+E007F) used for ASCII smuggling",
    pattern: /[\u{E0000}-\u{E007F}]/u,
  },
  {
    id: "UNICODE_BIDI_OVERRIDE",
    category: "unicode_smuggling",
    severity: "medium",
    description: "Contains Trojan Source Unicode bidirectional override control characters (CVE-2021-42574)",
    pattern: /[\u202A-\u202E\u2066-\u2069\u061C]/,
  },
  {
    id: "UNICODE_ZERO_WIDTH_CLUSTER",
    category: "unicode_smuggling",
    severity: "medium",
    description: "Contains 3+ consecutive invisible zero-width or variation-selector characters (arXiv:2603.00164)",
    pattern: /[\u200B-\u200D\u2060\uFEFF\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{3,}/u,
  },
  {
    id: "CMD_PIPE_OR_REVERSE_SHELL",
    category: "malicious_command",
    severity: "high",
    description: "Contains pipe-to-shell download, reverse shell, or encoded PowerShell payload",
    pattern:
      /(?:\b(?:curl|wget)\b[^\n|]{1,120}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,80}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bbash\s+-i\s+>&\s*\/dev\/tcp\/|\bnc\s+-e\s+\/bin\/(?:ba)?sh\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,})/i,
  },
  {
    id: "CMD_DESTRUCTIVE_RM",
    category: "malicious_command",
    severity: "high",
    description: "Contains destructive root/home directory deletion command",
    pattern: /\brm\s+-[rf]{1,2}\s+(?:\/|--no-preserve-root|~\/|\$HOME)\b/i,
  },
  {
    id: "URL_DANGEROUS_OR_BEACON",
    category: "suspicious_url",
    severity: "high",
    description: "Contains executable javascript:/data: link or Markdown image exfiltration beacon",
    pattern:
      /(?:\[[^\]]+\]\(\s*(?:javascript|vbscript|data\s*:\s*text\/html):|!\[[^\]]*\]\(https?:\/\/[^)]+\?(?:data|leak|prompt|key|token|secret)=[^)]+\))/i,
  },
]

const SNIPPET_MAX_LEN = 140

function extractSnippet(text: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 30)
  const end = Math.min(text.length, matchIndex + matchLength + 50)
  const raw = text.slice(start, end).replace(/\s+/g, " ").trim()
  return raw.length > SNIPPET_MAX_LEN ? `${raw.slice(0, SNIPPET_MAX_LEN)}...` : raw
}

/**
 * Scans post or comment text for indirect prompt injection, MCP tool poisoning,
 * invisible Unicode smuggling, and dangerous shell/URI payloads.
 */
export function scanContent(text: string): ScanResult {
  if (text.trim() === "") {
    return { quarantined: false, findings: [] }
  }

  const findings: ScanFinding[] = DETECTION_RULES.flatMap((rule): readonly ScanFinding[] => {
    const match = rule.pattern.exec(text)
    if (match === null) return []
    return [
      {
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        snippet: extractSnippet(text, match.index, match[0].length),
      },
    ]
  })

  return {
    quarantined: findings.length > 0,
    findings,
  }
}
