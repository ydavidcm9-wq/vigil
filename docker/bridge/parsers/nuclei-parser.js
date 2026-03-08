/**
 * Parse nuclei JSONL output into structured JSON array.
 *
 * Each line in the JSONL is a JSON object representing a finding.
 * Nuclei v3 output format includes:
 *   template, template-url, template-id, template-path,
 *   info (name, author, severity, description, tags, reference, classification),
 *   matcher-name, matcher-status,
 *   type, host, matched-at, extracted-results,
 *   ip, timestamp, curl-command,
 *   request, response
 *
 * Returns: [{
 *   template_id, name, severity, description,
 *   tags, references, classification,
 *   matched_at, host, ip, type,
 *   matcher_name, extracted_results,
 *   curl_command, timestamp,
 *   request, response
 * }]
 */
function parseNucleiJsonl(jsonlContent) {
  if (!jsonlContent || typeof jsonlContent !== "string") {
    return [];
  }

  const lines = jsonlContent.split("\n").filter((line) => line.trim());
  const findings = [];

  for (const line of lines) {
    try {
      const raw = JSON.parse(line);
      const info = raw.info || {};
      const classification = info.classification || {};

      findings.push({
        template_id: raw["template-id"] || raw.templateID || "",
        name: info.name || raw.name || "",
        severity: normalizeSeverity(info.severity || "info"),
        description: info.description || "",
        tags: normalizeTags(info.tags),
        references: normalizeArray(info.reference),
        classification: {
          cve_id: classification["cve-id"]
            ? normalizeArray(classification["cve-id"])
            : [],
          cwe_id: classification["cwe-id"]
            ? normalizeArray(classification["cwe-id"])
            : [],
          cvss_metrics: classification["cvss-metrics"] || "",
          cvss_score: parseFloat(classification["cvss-score"]) || null,
          epss_score: parseFloat(classification["epss-score"]) || null,
          epss_percentile:
            parseFloat(classification["epss-percentile"]) || null,
        },
        matched_at: raw["matched-at"] || "",
        host: raw.host || "",
        ip: raw.ip || "",
        type: raw.type || "",
        matcher_name: raw["matcher-name"] || "",
        extracted_results: normalizeArray(raw["extracted-results"]),
        curl_command: raw["curl-command"] || "",
        timestamp: raw.timestamp || "",
        request: raw.request || null,
        response: raw.response || null,
      });
    } catch (_) {
      // Skip malformed lines
    }
  }

  // Sort by severity: critical > high > medium > low > info
  const severityOrder = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  findings.sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  return findings;
}

/**
 * Normalize severity string to standard levels.
 */
function normalizeSeverity(severity) {
  const s = (severity || "").toLowerCase().trim();
  const valid = ["critical", "high", "medium", "low", "info"];
  return valid.includes(s) ? s : "info";
}

/**
 * Normalize tags — nuclei may provide comma-separated string or array.
 */
function normalizeTags(tags) {
  if (!tags) return [];
  if (Array.isArray(tags)) return tags;
  if (typeof tags === "string") {
    return tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
  }
  return [];
}

/**
 * Normalize a value to an array.
 */
function normalizeArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  return [val];
}

module.exports = { parseNucleiJsonl };
