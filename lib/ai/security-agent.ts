import { chat, chatStream, ChatMessage } from "./ollama-client";
import crypto from "crypto";
import {
  SECURITY_SYSTEM_PROMPT,
  ANALYSIS_PROMPT,
  TICKET_PROMPT,
} from "./prompts/security-system";
import { query } from "@/lib/db/pool";
import {
  buildKnowledgeContext,
  type KnowledgeHit,
  searchKnowledge,
} from "@/lib/ai/knowledge-store";

export interface SecurityChatOptions {
  userId?: string;
}

export interface SecurityChatResult {
  response: string;
  sources: KnowledgeHit[];
}

const SUMMARY_CACHE_TTL_MS = Math.max(
  60_000,
  Number.parseInt(process.env.REPORT_SUMMARY_CACHE_TTL_MS || "900000", 10) || 900000
);
const SUMMARY_CACHE_MAX_ENTRIES = Math.max(
  20,
  Number.parseInt(process.env.REPORT_SUMMARY_CACHE_MAX || "500", 10) || 500
);
const scanSummaryCache = new Map<string, { expiresAt: number; value: string }>();
const scanSummaryInflight = new Map<string, Promise<string>>();

function pruneSummaryCache(now: number): void {
  for (const [key, entry] of scanSummaryCache.entries()) {
    if (entry.expiresAt <= now) {
      scanSummaryCache.delete(key);
    }
  }

  if (scanSummaryCache.size <= SUMMARY_CACHE_MAX_ENTRIES) return;
  const overflow = scanSummaryCache.size - SUMMARY_CACHE_MAX_ENTRIES;
  let removed = 0;
  for (const key of scanSummaryCache.keys()) {
    scanSummaryCache.delete(key);
    removed += 1;
    if (removed >= overflow) break;
  }
}

export async function securityChat(
  userMessage: string,
  conversationHistory: ChatMessage[] = [],
  options: SecurityChatOptions = {}
): Promise<SecurityChatResult> {
  let sources: KnowledgeHit[] = [];
  if (options.userId) {
    try {
      sources = await searchKnowledge(options.userId, userMessage);
    } catch (err) {
      console.error("[security-agent] Knowledge lookup warning:", err);
    }
  }
  const knowledgeContext = buildKnowledgeContext(sources);
  const messages: ChatMessage[] = [
    {
      role: "system",
      content: knowledgeContext
        ? `${SECURITY_SYSTEM_PROMPT}

## Local Knowledge Base
${knowledgeContext}

When knowledge is relevant, use it directly and cite the source title inline.`
        : SECURITY_SYSTEM_PROMPT,
    },
    ...conversationHistory,
    { role: "user", content: userMessage },
  ];
  const response = await chat(messages);
  return { response, sources };
}

export async function securityChatStream(
  userMessage: string,
  conversationHistory: ChatMessage[],
  onChunk: (text: string) => void,
  options: SecurityChatOptions = {}
): Promise<string> {
  let sources: KnowledgeHit[] = [];
  if (options.userId) {
    try {
      sources = await searchKnowledge(options.userId, userMessage);
    } catch (err) {
      console.error("[security-agent] Knowledge lookup warning:", err);
    }
  }
  const knowledgeContext = buildKnowledgeContext(sources);
  const messages: ChatMessage[] = [
    {
      role: "system",
      content: knowledgeContext
        ? `${SECURITY_SYSTEM_PROMPT}

## Local Knowledge Base
${knowledgeContext}`
        : SECURITY_SYSTEM_PROMPT,
    },
    ...conversationHistory,
    { role: "user", content: userMessage },
  ];
  return chatStream(messages, onChunk);
}

export async function analyzeFinding(finding: {
  title: string;
  severity: string;
  description: string;
  evidence?: string;
  cve_id?: string;
  scanner: string;
  target_url?: string;
}): Promise<string> {
  const messages: ChatMessage[] = [
    { role: "system", content: ANALYSIS_PROMPT },
    {
      role: "user",
      content: `Analyze this security finding:

**Title:** ${finding.title}
**Severity:** ${finding.severity}
**Scanner:** ${finding.scanner}
**Target:** ${finding.target_url || "N/A"}
**CVE:** ${finding.cve_id || "N/A"}

**Description:**
${finding.description}

**Evidence:**
${finding.evidence || "No evidence provided"}`,
    },
  ];
  return chat(messages, { temperature: 0.2 });
}

export async function generateTicketText(finding: {
  title: string;
  severity: string;
  description: string;
  evidence?: string;
  poc?: string;
  remediation?: string;
  cve_id?: string;
  cvss_score?: number;
  scanner: string;
  target_url?: string;
  created_at: string;
}): Promise<string> {
  const messages: ChatMessage[] = [
    { role: "system", content: TICKET_PROMPT },
    {
      role: "user",
      content: `Generate a support ticket for this finding:

Title: ${finding.title}
Severity: ${finding.severity}
Scanner: ${finding.scanner}
Target: ${finding.target_url || "N/A"}
Date: ${finding.created_at}
CVE: ${finding.cve_id || "N/A"}
CVSS: ${finding.cvss_score || "N/A"}

Description: ${finding.description}
Evidence: ${finding.evidence || "N/A"}
Proof of Concept: ${finding.poc || "N/A"}
Known Remediation: ${finding.remediation || "N/A"}`,
    },
  ];
  return chat(messages, { temperature: 0.1 });
}

export async function recommendScans(
  targetDescription: string
): Promise<string> {
  const messages: ChatMessage[] = [
    { role: "system", content: SECURITY_SYSTEM_PROMPT },
    {
      role: "user",
      content: `I want to security audit this target: ${targetDescription}

What scans do you recommend I run? Explain each one briefly and why it's important for this target. List them in priority order.`,
    },
  ];
  return chat(messages);
}

export async function summarizeScanResults(
  scanId: string
): Promise<string> {
  const findings = await query(
    `SELECT title, severity, category, description, cve_id
     FROM findings WHERE scan_id = $1
     ORDER BY
       CASE severity
         WHEN 'critical' THEN 1
         WHEN 'high' THEN 2
         WHEN 'medium' THEN 3
         WHEN 'low' THEN 4
         ELSE 5
       END`,
    [scanId]
  );

  if (findings.length === 0) {
    return "No findings were detected in this scan. Your target appears to be secure against the tests that were run.";
  }

  const fingerprint = crypto
    .createHash("sha256")
    .update(
      findings
        .map((f: Record<string, unknown>) =>
          `${f.title || ""}|${f.severity || ""}|${f.category || ""}|${f.cve_id || ""}`
        )
        .join("\n")
    )
    .digest("hex");
  const cacheKey = `${scanId}:${fingerprint}`;

  const now = Date.now();
  const cached = scanSummaryCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }
  if (cached) {
    scanSummaryCache.delete(cacheKey);
  }

  const pending = scanSummaryInflight.get(cacheKey);
  if (pending) return pending;

  const findingsSummary = findings
    .map(
      (f: Record<string, unknown>) =>
        `- [${(f.severity as string).toUpperCase()}] ${f.title}${f.cve_id ? ` (${f.cve_id})` : ""}`
    )
    .join("\n");

  const messages: ChatMessage[] = [
    { role: "system", content: ANALYSIS_PROMPT },
    {
      role: "user",
      content: `Summarize these scan findings in plain English. Give an overall security assessment and prioritize what to fix first:

${findingsSummary}

Total: ${findings.length} findings`,
    },
  ];
  const task = chat(messages)
    .then((summary) => {
      pruneSummaryCache(Date.now());
      scanSummaryCache.set(cacheKey, {
        value: summary,
        expiresAt: Date.now() + SUMMARY_CACHE_TTL_MS,
      });
      return summary;
    })
    .finally(() => {
      scanSummaryInflight.delete(cacheKey);
    });

  scanSummaryInflight.set(cacheKey, task);
  return task;
}
