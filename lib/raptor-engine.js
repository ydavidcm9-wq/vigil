/**
 * Vigil — Raptor Engine (Adversarial Security Analysis)
 * Inspired by RAPTOR's MUST-GATE reasoning and exploitability validation.
 *
 * Adapts Raptor's adversarial thinking patterns:
 *   - 7 MUST-GATEs (forced reasoning constraints)
 *   - 4-step exploitability validation (Source Control → Sanitizer → Reachability → Impact)
 *   - Adversarial prioritization (Secrets > Input Validation > Auth > Crypto > Config)
 *   - No-hedging enforcement (every "maybe" must be verified)
 */

// ── MUST-GATE Reasoning Constraints ─────────────────────────────────────

const MUST_GATES = [
  { id: 'ASSUME-EXPLOIT', rule: 'If you think something is not exploitable, investigate under the assumption that it IS exploitable first. Only rule out after thorough analysis.' },
  { id: 'STRICT-SEQUENCE', rule: 'Follow the analysis framework steps in order. Do not skip steps. Present any deviations separately at the end.' },
  { id: 'CHECKLIST', rule: 'Maintain a compliance checklist. For each step, mark whether the check passed, failed, or needs more investigation.' },
  { id: 'NO-HEDGING', rule: 'If your output includes "if", "maybe", "uncertain", "unclear", or "could potentially" — immediately verify that claim. Do not leave unverified hedging language.' },
  { id: 'FULL-COVERAGE', rule: 'Analyze the entire relevant code path. No sampling, estimating, or guessing. Trace the full data flow from source to sink.' },
  { id: 'PROOF', rule: 'Always provide proof: show the vulnerable code, the attack vector, and a concrete proof-of-concept. No theoretical-only findings.' },
  { id: 'CONSISTENCY', rule: 'Verify that vuln_type, severity, and exploitability status all match your description and proof. Contradictions invalidate the finding.' },
];

// ── Adversarial Priority Order ──────────────────────────────────────────

const PRIORITY_ORDER = [
  'Secrets & Credentials exposure',
  'Input Validation failures (injection, traversal)',
  'Authentication & Authorization bypasses',
  'Cryptographic weaknesses',
  'Configuration & Deployment issues',
];

// ── 4-Step Exploitability Framework ─────────────────────────────────────

const EXPLOITABILITY_STEPS = [
  {
    step: 1,
    name: 'Source Control Analysis',
    question: 'Who controls the input data? Can an external attacker provide or influence it?',
    criteria: 'PASS if attacker can directly control or influence the input. FAIL if input is entirely internal/trusted.',
  },
  {
    step: 2,
    name: 'Sanitizer Effectiveness Analysis',
    question: 'Is there sanitization/validation between input and sink? Can it be bypassed?',
    criteria: 'PASS if no sanitization exists OR if bypasses are possible (encoding, truncation, type juggling, double encoding). FAIL if sanitization is provably complete.',
  },
  {
    step: 3,
    name: 'Reachability Analysis',
    question: 'Can an attacker actually trigger this code path? What prerequisites are needed?',
    criteria: 'PASS if the vulnerable path is reachable via normal application flow (HTTP request, WebSocket, file upload, API call). FAIL if requires impossible preconditions.',
  },
  {
    step: 4,
    name: 'Impact Assessment',
    question: 'What is the worst-case outcome if exploited? What data/access is at risk?',
    criteria: 'Rate impact: CRITICAL (RCE/full compromise), HIGH (data breach/auth bypass), MEDIUM (limited data exposure), LOW (information disclosure only).',
  },
];

/**
 * Build the adversarial analysis prompt with MUST-GATE constraints.
 * @param {string} target - What to analyze (URL, code snippet, finding description)
 * @param {string} context - Additional context (scan results, code, configuration)
 * @returns {string}
 */
function buildAdversarialPrompt(target, context) {
  const gateRules = MUST_GATES.map(g => `[${g.id}] ${g.rule}`).join('\n');
  const priorities = PRIORITY_ORDER.map((p, i) => `${i + 1}. ${p}`).join('\n');

  return `You are an elite adversarial security analyst using the MUST-GATE reasoning framework.

## MANDATORY REASONING CONSTRAINTS (MUST-GATEs)
${gateRules}

## ADVERSARIAL PRIORITY ORDER
${priorities}

## TARGET
${target}

## CONTEXT
${context || 'No additional context provided.'}

## YOUR TASK
Perform a rigorous adversarial security analysis. Think like an attacker but communicate like a professional security researcher.

For each finding:
1. Identify the vulnerability class (CWE ID)
2. Trace the complete attack path (source → processing → sink)
3. Assess exploitability using the 4-step framework:
   - Source Control: Who controls the input?
   - Sanitizer Effectiveness: Can validation be bypassed?
   - Reachability: Can an attacker trigger this path?
   - Impact: What is the worst-case outcome?
4. Provide a concrete proof-of-concept
5. Assign a verdict: EXPLOITABLE, LIKELY_EXPLOITABLE, NEEDS_INVESTIGATION, or FALSE_POSITIVE
6. Recommend specific remediation

## OUTPUT FORMAT (JSON)
{
  "findings": [
    {
      "title": "...",
      "cwe": "CWE-XXX",
      "severity": "critical|high|medium|low",
      "verdict": "exploitable|likely_exploitable|needs_investigation|false_positive",
      "confidence": 1-10,
      "attack_path": "source → ... → sink",
      "proof_of_concept": "...",
      "impact": "...",
      "remediation": "...",
      "must_gate_checklist": {
        "assume_exploit": "pass|fail - explanation",
        "full_coverage": "pass|fail - explanation",
        "proof": "pass|fail - explanation",
        "no_hedging": "pass|fail - explanation"
      }
    }
  ],
  "summary": "...",
  "risk_rating": "critical|high|medium|low",
  "next_steps": ["...", "..."]
}`;
}

/**
 * Build the exploitability validation prompt for a specific finding.
 * @param {object} finding - The finding to validate
 * @param {string} codeContext - Source code around the finding
 * @returns {string}
 */
function buildExploitabilityPrompt(finding, codeContext) {
  const steps = EXPLOITABILITY_STEPS.map(s =>
    `### Step ${s.step}: ${s.name}\n**Question:** ${s.question}\n**Criteria:** ${s.criteria}`
  ).join('\n\n');

  const gateRules = MUST_GATES.map(g => `- [${g.id}] ${g.rule}`).join('\n');

  return `You are a senior penetration tester validating whether a security finding is actually exploitable.

## MUST-GATE CONSTRAINTS
${gateRules}

## FINDING TO VALIDATE
Title: ${finding.title || 'Unknown'}
Type: ${finding.vulnType || finding.type || 'Unknown'}
Severity: ${finding.severity || 'Unknown'}
File: ${finding.file || 'Unknown'}
Line: ${finding.line || 'Unknown'}
Description: ${finding.description || finding.details || 'No description'}
Data Flow: ${finding.dataFlow || 'Not specified'}
Original PoC: ${finding.poc || 'None provided'}

## SOURCE CODE CONTEXT
${codeContext || 'No source code available. Analyze based on the finding description.'}

## 4-STEP EXPLOITABILITY VALIDATION
Execute each step in order. Do not skip any step.

${steps}

## FINAL VERDICT
After completing all 4 steps:
- Mark EXPLOITABLE only if ALL steps pass
- Mark FALSE_POSITIVE if ANY step definitively fails
- Mark NEEDS_INVESTIGATION if steps are inconclusive
- Mark LIKELY_EXPLOITABLE if most steps pass but one needs more data

## OUTPUT FORMAT (JSON)
{
  "verdict": "exploitable|likely_exploitable|needs_investigation|false_positive",
  "confidence": 1-10,
  "steps": [
    { "step": 1, "name": "Source Control Analysis", "result": "pass|fail|inconclusive", "analysis": "..." },
    { "step": 2, "name": "Sanitizer Effectiveness Analysis", "result": "pass|fail|inconclusive", "analysis": "..." },
    { "step": 3, "name": "Reachability Analysis", "result": "pass|fail|inconclusive", "analysis": "..." },
    { "step": 4, "name": "Impact Assessment", "result": "critical|high|medium|low", "analysis": "..." }
  ],
  "attack_vector": "...",
  "proof_of_concept": "...",
  "remediation": "...",
  "reasoning": "..."
}`;
}

/**
 * Run adversarial analysis on a target.
 * @param {string} target - Target description
 * @param {string} context - Additional context
 * @param {object} opts
 * @param {Function} opts.askAIJSON - Vigil AI JSON function
 * @param {number} [opts.timeout] - Timeout in ms
 * @returns {Promise<object>}
 */
async function adversarialAnalysis(target, context, opts = {}) {
  const { askAIJSON, timeout = 120000 } = opts;
  if (!askAIJSON) throw new Error('askAIJSON function required');

  const prompt = buildAdversarialPrompt(target, context);
  const result = await askAIJSON(prompt, { timeout, includeSystemPrompt: false });

  if (!result) return { findings: [], summary: 'Analysis returned no results', risk_rating: 'unknown', next_steps: [] };

  return {
    findings: result.findings || [],
    summary: result.summary || 'No summary',
    risk_rating: result.risk_rating || 'unknown',
    next_steps: result.next_steps || [],
    must_gates: MUST_GATES.map(g => g.id),
    framework: 'raptor-adversarial',
  };
}

/**
 * Validate a specific finding's exploitability.
 * @param {object} finding - The finding to validate
 * @param {object} opts
 * @param {Function} opts.askAIJSON - Vigil AI JSON function
 * @param {string} [opts.codeContext] - Source code around the finding
 * @param {number} [opts.timeout] - Timeout in ms
 * @returns {Promise<object>}
 */
async function validateExploitability(finding, opts = {}) {
  const { askAIJSON, codeContext, timeout = 120000 } = opts;
  if (!askAIJSON) throw new Error('askAIJSON function required');

  const prompt = buildExploitabilityPrompt(finding, codeContext);
  const result = await askAIJSON(prompt, { timeout, includeSystemPrompt: false });

  if (!result) return { verdict: 'needs_investigation', confidence: 0, steps: [], reasoning: 'Validation returned no results' };

  return {
    verdict: result.verdict || 'needs_investigation',
    confidence: Math.min(10, Math.max(0, result.confidence || 0)),
    steps: result.steps || [],
    attack_vector: result.attack_vector || '',
    proof_of_concept: result.proof_of_concept || '',
    remediation: result.remediation || '',
    reasoning: result.reasoning || '',
    framework: 'raptor-exploitability',
    finding_id: finding.id,
  };
}

module.exports = {
  adversarialAnalysis,
  validateExploitability,
  buildAdversarialPrompt,
  buildExploitabilityPrompt,
  MUST_GATES,
  EXPLOITABILITY_STEPS,
  PRIORITY_ORDER,
};
