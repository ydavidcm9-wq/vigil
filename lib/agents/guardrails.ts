import { AgentRecord } from "@/lib/agents/types";

export interface GuardrailDecision {
  allowed: boolean;
  sanitizedInput: string;
  warnings: string[];
  blocks: string[];
}

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+previous\s+instructions/i,
  /reveal\s+system\s+prompt/i,
  /developer\s+mode/i,
  /jailbreak/i,
  /override\s+safety/i,
  /act\s+as\s+root/i,
];

const BLOCK_PATTERNS: Array<{ regex: RegExp; reason: string }> = [
  { regex: /rm\s+-rf/i, reason: "Destructive shell command request detected." },
  { regex: /drop\s+table/i, reason: "Database destruction request detected." },
  { regex: /format\s+c:/i, reason: "Filesystem wipe request detected." },
  { regex: /ssh\s+root@/i, reason: "Privileged raw SSH execution is blocked." },
  {
    regex: /exfiltrat(e|ion)|steal\s+data|dump\s+credentials/i,
    reason: "Data exfiltration intent detected.",
  },
];

function stripControlCharacters(input: string): string {
  return input.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
}

export function evaluateRunPolicy(
  agent: Pick<AgentRecord, "risk_level" | "autonomy_mode">,
  rawInput: string
): GuardrailDecision {
  const sanitizedInput = stripControlCharacters(rawInput);
  const warnings: string[] = [];
  const blocks: string[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(sanitizedInput)) {
      warnings.push("Prompt injection pattern detected; input was sandboxed.");
      break;
    }
  }

  for (const item of BLOCK_PATTERNS) {
    if (item.regex.test(sanitizedInput)) {
      blocks.push(item.reason);
    }
  }

  if (agent.risk_level === "critical" && agent.autonomy_mode === "autonomous") {
    warnings.push(
      "Critical-risk agents should run in assisted mode; execution is constrained."
    );
  }

  return {
    allowed: blocks.length === 0,
    sanitizedInput,
    warnings,
    blocks,
  };
}

export function redactSecrets(input: string): string {
  return input
    .replace(/(api[_-]?key\s*[:=]\s*)([^\s]+)/gi, "$1[REDACTED]")
    .replace(/(token\s*[:=]\s*)([^\s]+)/gi, "$1[REDACTED]")
    .replace(/(password\s*[:=]\s*)([^\s]+)/gi, "$1[REDACTED]");
}
