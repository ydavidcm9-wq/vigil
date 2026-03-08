const express = require("express");
const { execFile, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { parseNmapXml } = require("./parsers/nmap-parser");
const { parseNucleiJsonl } = require("./parsers/nuclei-parser");

const app = express();
app.use(express.json({ limit: "10mb" }));

const PORT = parseInt(process.env.PORT || "9877", 10);
const DEFAULT_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT || "300", 10) * 1000;
const BRIDGE_SHARED_TOKEN = (process.env.BRIDGE_SHARED_TOKEN || "").trim();

if (!BRIDGE_SHARED_TOKEN) {
  console.warn(
    "[bridge] BRIDGE_SHARED_TOKEN is not configured; bridge auth is disabled."
  );
}

function isAuthorized(req) {
  if (!BRIDGE_SHARED_TOKEN) return true;
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return false;

  const token = header.slice(7).trim();
  const expected = Buffer.from(BRIDGE_SHARED_TOKEN);
  const received = Buffer.from(token);
  if (expected.length !== received.length) return false;

  return crypto.timingSafeEqual(expected, received);
}

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (!isAuthorized(req)) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  return next();
});

// ══════════════════════════════════════════════════════════════════
// Utility helpers
// ══════════════════════════════════════════════════════════════════

function tmpFile(ext) {
  return path.join(
    os.tmpdir(),
    `sec-${crypto.randomBytes(8).toString("hex")}${ext}`
  );
}

function cleanupFile(filepath) {
  try {
    if (filepath && fs.existsSync(filepath)) fs.unlinkSync(filepath);
  } catch (_) {}
}

function validateTarget(target) {
  if (!target || typeof target !== "string") return false;
  if (target.length > 2048) return false;
  // Block shell metacharacters
  if (/[;&|`$(){}[\]!<>\\]/.test(target)) return false;
  return true;
}

function runCommand(cmd, args, options = {}) {
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  return new Promise((resolve, reject) => {
    const proc = execFile(
      cmd,
      args,
      {
        timeout,
        maxBuffer: 50 * 1024 * 1024, // 50MB
        env: { ...process.env, ...(options.env || {}) },
      },
      (error, stdout, stderr) => {
        if (error && error.killed) {
          reject(new Error(`Command timed out after ${timeout / 1000}s`));
        } else if (error && !options.ignoreExitCode) {
          reject(
            new Error(
              error.message + (stderr ? `\nStderr: ${stderr}` : "")
            )
          );
        } else {
          resolve({ stdout, stderr, exitCode: error ? error.code : 0 });
        }
      }
    );
  });
}

function errorResponse(res, status, message, details) {
  return res.status(status).json({
    success: false,
    error: message,
    ...(details ? { details } : {}),
  });
}

// ══════════════════════════════════════════════════════════════════
// Available tools registry
// ══════════════════════════════════════════════════════════════════

const TOOLS = [
  {
    name: "nmap",
    description: "Network mapper — port scanning, service detection, OS fingerprinting",
    binary: "nmap",
    endpoint: "/nmap/scan",
  },
  {
    name: "nuclei",
    description: "Template-based vulnerability scanner",
    binary: "nuclei",
    endpoint: "/nuclei/scan",
  },
  {
    name: "nikto",
    description: "Web server vulnerability scanner",
    binary: "nikto",
    endpoint: "/nikto/scan",
  },
  {
    name: "sqlmap",
    description: "Automatic SQL injection detection and exploitation",
    binary: "sqlmap",
    endpoint: "/sqlmap/scan",
  },
  {
    name: "gobuster",
    description: "Directory/file brute-forcing, DNS subdomain enumeration",
    binary: "gobuster",
    endpoint: "/gobuster/scan",
  },
  {
    name: "subfinder",
    description: "Passive subdomain discovery",
    binary: "subfinder",
    endpoint: null,
  },
  {
    name: "httpx",
    description: "HTTP probe and technology fingerprinting",
    binary: "httpx",
    endpoint: null,
  },
  {
    name: "whois",
    description: "Domain/IP WHOIS lookup",
    binary: "whois",
    endpoint: null,
  },
  {
    name: "dnsrecon",
    description: "DNS enumeration and reconnaissance",
    binary: "dnsrecon",
    endpoint: null,
  },
  {
    name: "hydra",
    description: "Network login brute-forcer",
    binary: "hydra",
    endpoint: null,
  },
  {
    name: "dirb",
    description: "Web content directory scanner",
    binary: "dirb",
    endpoint: null,
  },
];

// ══════════════════════════════════════════════════════════════════
// Health & metadata endpoints
// ══════════════════════════════════════════════════════════════════

app.get("/health", async (_req, res) => {
  const available = [];
  const unavailable = [];

  for (const tool of TOOLS) {
    try {
      await runCommand("which", [tool.binary], { timeout: 5000 });
      available.push(tool.name);
    } catch {
      unavailable.push(tool.name);
    }
  }

  res.json({
    status: unavailable.length === 0 ? "healthy" : "degraded",
    uptime: process.uptime(),
    tools: { available, unavailable },
    timestamp: new Date().toISOString(),
  });
});

app.get("/tools", (_req, res) => {
  res.json({
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      endpoint: t.endpoint,
    })),
  });
});

// ══════════════════════════════════════════════════════════════════
// POST /nmap/scan
// Body: { target, flags?: string[], timeout?: number }
// ══════════════════════════════════════════════════════════════════

app.post("/nmap/scan", async (req, res) => {
  const { target, flags = [], timeout } = req.body;

  if (!validateTarget(target)) {
    return errorResponse(res, 400, "Invalid target");
  }

  const outputFile = tmpFile(".xml");

  try {
    const baseFlags = ["-oX", outputFile];

    // Sanitize user flags — block dangerous ones
    const blocked = ["-iL", "--script-args-file", "--resume"];
    const safeFlags = (Array.isArray(flags) ? flags : []).filter(
      (f) => typeof f === "string" && !blocked.some((b) => f.startsWith(b))
    );

    const args = [...baseFlags, ...safeFlags, target];

    await runCommand("nmap", args, {
      timeout: timeout || DEFAULT_TIMEOUT,
      ignoreExitCode: true,
    });

    const xmlContent = fs.readFileSync(outputFile, "utf-8");
    const parsed = parseNmapXml(xmlContent);

    res.json({
      success: true,
      scanner: "nmap",
      target,
      result: parsed,
      raw_xml: xmlContent,
    });
  } catch (err) {
    errorResponse(res, 500, "Nmap scan failed", err.message);
  } finally {
    cleanupFile(outputFile);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /nuclei/scan
// Body: { target, templates?: string[], severity?: string[], timeout?: number }
// ══════════════════════════════════════════════════════════════════

app.post("/nuclei/scan", async (req, res) => {
  const { target, templates = [], severity = [], timeout } = req.body;

  if (!validateTarget(target)) {
    return errorResponse(res, 400, "Invalid target");
  }

  const outputFile = tmpFile(".jsonl");

  try {
    const args = ["-u", target, "-jsonl", "-o", outputFile, "-silent"];

    if (Array.isArray(templates) && templates.length > 0) {
      for (const t of templates) {
        if (typeof t === "string" && /^[a-zA-Z0-9\-_/:.]+$/.test(t)) {
          args.push("-t", t);
        }
      }
    }

    if (Array.isArray(severity) && severity.length > 0) {
      const validSeverities = ["info", "low", "medium", "high", "critical"];
      const filtered = severity.filter((s) => validSeverities.includes(s));
      if (filtered.length > 0) {
        args.push("-severity", filtered.join(","));
      }
    }

    await runCommand("nuclei", args, {
      timeout: timeout || DEFAULT_TIMEOUT,
      ignoreExitCode: true,
    });

    let jsonlContent = "";
    if (fs.existsSync(outputFile)) {
      jsonlContent = fs.readFileSync(outputFile, "utf-8");
    }

    const parsed = parseNucleiJsonl(jsonlContent);

    res.json({
      success: true,
      scanner: "nuclei",
      target,
      findings: parsed,
      total: parsed.length,
    });
  } catch (err) {
    errorResponse(res, 500, "Nuclei scan failed", err.message);
  } finally {
    cleanupFile(outputFile);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /nikto/scan
// Body: { target, port?: number, tuning?: string, timeout?: number }
// ══════════════════════════════════════════════════════════════════

app.post("/nikto/scan", async (req, res) => {
  const { target, port, tuning, timeout } = req.body;

  if (!validateTarget(target)) {
    return errorResponse(res, 400, "Invalid target");
  }

  const outputFile = tmpFile(".json");

  try {
    const args = ["-h", target, "-Format", "json", "-o", outputFile, "-nointeractive"];

    if (port && Number.isInteger(port) && port > 0 && port <= 65535) {
      args.push("-p", String(port));
    }

    if (tuning && typeof tuning === "string" && /^[0-9a-cx]+$/.test(tuning)) {
      args.push("-Tuning", tuning);
    }

    await runCommand("nikto", args, {
      timeout: timeout || DEFAULT_TIMEOUT,
      ignoreExitCode: true,
    });

    let result = {};
    if (fs.existsSync(outputFile)) {
      const content = fs.readFileSync(outputFile, "utf-8").trim();
      if (content) {
        try {
          result = JSON.parse(content);
        } catch {
          result = { raw: content };
        }
      }
    }

    res.json({
      success: true,
      scanner: "nikto",
      target,
      result,
    });
  } catch (err) {
    errorResponse(res, 500, "Nikto scan failed", err.message);
  } finally {
    cleanupFile(outputFile);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /sqlmap/scan
// Body: { target, level?: 1-5, risk?: 1-3, timeout?: number }
// ══════════════════════════════════════════════════════════════════

app.post("/sqlmap/scan", async (req, res) => {
  const { target, level = 1, risk = 1, timeout } = req.body;

  if (!validateTarget(target)) {
    return errorResponse(res, 400, "Invalid target");
  }

  const outputDir = tmpFile("");

  try {
    fs.mkdirSync(outputDir, { recursive: true });

    const args = [
      "-u",
      target,
      "--batch",
      "--forms",
      "--output-dir",
      outputDir,
      "--level",
      String(Math.min(Math.max(parseInt(level) || 1, 1), 5)),
      "--risk",
      String(Math.min(Math.max(parseInt(risk) || 1, 1), 3)),
      "--disable-coloring",
    ];

    const { stdout, stderr } = await runCommand("sqlmap", args, {
      timeout: timeout || DEFAULT_TIMEOUT,
      ignoreExitCode: true,
    });

    // Parse sqlmap text output for findings
    const vulnerabilities = [];
    const lines = stdout.split("\n");
    let currentParam = null;

    for (const line of lines) {
      const paramMatch = line.match(
        /Parameter: (.+?) \((.+?)\)/
      );
      if (paramMatch) {
        currentParam = {
          parameter: paramMatch[1],
          place: paramMatch[2],
        };
      }

      const typeMatch = line.match(
        /Type: (.+)/
      );
      if (typeMatch && currentParam) {
        vulnerabilities.push({
          ...currentParam,
          type: typeMatch[1].trim(),
        });
      }
    }

    res.json({
      success: true,
      scanner: "sqlmap",
      target,
      vulnerabilities,
      total: vulnerabilities.length,
      raw_output: stdout,
    });
  } catch (err) {
    errorResponse(res, 500, "SQLMap scan failed", err.message);
  } finally {
    try {
      fs.rmSync(outputDir, { recursive: true, force: true });
    } catch (_) {}
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /gobuster/scan
// Body: { target, wordlist?, extensions?, threads?, timeout? }
// ══════════════════════════════════════════════════════════════════

app.post("/gobuster/scan", async (req, res) => {
  const {
    target,
    wordlist = "/usr/share/wordlists/dirb/common.txt",
    extensions = [],
    threads = 10,
    timeout,
  } = req.body;

  if (!validateTarget(target)) {
    return errorResponse(res, 400, "Invalid target");
  }

  try {
    const args = [
      "dir",
      "-u",
      target,
      "-w",
      wordlist,
      "-t",
      String(Math.min(Math.max(parseInt(threads) || 10, 1), 50)),
      "-q",
      "--no-color",
      "--no-progress",
    ];

    if (Array.isArray(extensions) && extensions.length > 0) {
      const safeExts = extensions
        .filter((e) => typeof e === "string" && /^[a-z0-9]+$/.test(e))
        .join(",");
      if (safeExts) {
        args.push("-x", safeExts);
      }
    }

    const { stdout } = await runCommand("gobuster", args, {
      timeout: timeout || DEFAULT_TIMEOUT,
      ignoreExitCode: true,
    });

    // Parse gobuster output: /path (Status: 200) [Size: 1234]
    const results = [];
    const lines = stdout.split("\n").filter((l) => l.trim());

    for (const line of lines) {
      const match = line.match(
        /^(\/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]/
      );
      if (match) {
        results.push({
          path: match[1],
          status: parseInt(match[2]),
          size: parseInt(match[3]),
        });
      } else {
        // Alternate format: /path  [Status=200] [Size=1234]
        const altMatch = line.match(
          /^(\/\S+)\s+\[Status=(\d+)\]\s+\[Size=(\d+)\]/
        );
        if (altMatch) {
          results.push({
            path: altMatch[1],
            status: parseInt(altMatch[2]),
            size: parseInt(altMatch[3]),
          });
        }
      }
    }

    res.json({
      success: true,
      scanner: "gobuster",
      target,
      results,
      total: results.length,
      raw_output: stdout,
    });
  } catch (err) {
    errorResponse(res, 500, "Gobuster scan failed", err.message);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /osint/domain
// Body: { domain, timeout? }
// ══════════════════════════════════════════════════════════════════

app.post("/osint/domain", async (req, res) => {
  const { domain, timeout } = req.body;

  if (!domain || typeof domain !== "string") {
    return errorResponse(res, 400, "Invalid domain");
  }

  // Validate domain format
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return errorResponse(res, 400, "Invalid domain format");
  }

  const scriptFile = tmpFile(".py");
  const resultFile = tmpFile(".json");

  try {
    // Write Python OSINT script
    const pythonScript = `
import json
import sys
import socket
import ssl
import subprocess

domain = sys.argv[1]
output_file = sys.argv[2]
results = {}

# WHOIS lookup
try:
    import whois
    w = whois.whois(domain)
    results["whois"] = {
        "registrar": w.registrar,
        "creation_date": str(w.creation_date) if w.creation_date else None,
        "expiration_date": str(w.expiration_date) if w.expiration_date else None,
        "name_servers": w.name_servers if w.name_servers else [],
        "status": w.status if w.status else [],
        "emails": w.emails if w.emails else [],
        "org": w.org,
        "country": w.country,
    }
except Exception as e:
    results["whois"] = {"error": str(e)}

# DNS records
try:
    import dns.resolver
    dns_records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_records[rtype] = [str(r) for r in answers]
        except:
            pass
    results["dns"] = dns_records
except Exception as e:
    results["dns"] = {"error": str(e)}

# Reverse IP (A records to hostnames)
try:
    ips = socket.getaddrinfo(domain, None, socket.AF_INET)
    ip_list = list(set([ip[4][0] for ip in ips]))
    reverse = {}
    for ip in ip_list[:5]:
        try:
            host = socket.gethostbyaddr(ip)
            reverse[ip] = {"hostname": host[0], "aliases": host[1]}
        except:
            reverse[ip] = {"hostname": None}
    results["reverse_ip"] = reverse
except Exception as e:
    results["reverse_ip"] = {"error": str(e)}

# SSL/TLS certificate info
try:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.settimeout(10)
        s.connect((domain, 443))
        cert = s.getpeercert()
        results["certificate"] = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", [])],
        }
except Exception as e:
    results["certificate"] = {"error": str(e)}

with open(output_file, "w") as f:
    json.dump(results, f)
`;

    fs.writeFileSync(scriptFile, pythonScript);

    await runCommand("python3", [scriptFile, domain, resultFile], {
      timeout: timeout || 60000,
      ignoreExitCode: true,
    });

    let result = {};
    if (fs.existsSync(resultFile)) {
      const content = fs.readFileSync(resultFile, "utf-8").trim();
      if (content) {
        result = JSON.parse(content);
      }
    }

    // Subfinder for subdomains
    try {
      const { stdout: subdomains } = await runCommand(
        "subfinder",
        ["-d", domain, "-silent"],
        { timeout: 30000, ignoreExitCode: true }
      );
      result.subdomains = subdomains
        .split("\n")
        .filter((s) => s.trim())
        .map((s) => s.trim());
    } catch {
      result.subdomains = [];
    }

    res.json({
      success: true,
      type: "domain",
      target: domain,
      result,
    });
  } catch (err) {
    errorResponse(res, 500, "Domain OSINT failed", err.message);
  } finally {
    cleanupFile(scriptFile);
    cleanupFile(resultFile);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /osint/ip
// Body: { ip, timeout? }
// ══════════════════════════════════════════════════════════════════

app.post("/osint/ip", async (req, res) => {
  const { ip, timeout } = req.body;

  if (!ip || typeof ip !== "string") {
    return errorResponse(res, 400, "Invalid IP address");
  }

  // Validate IPv4 or IPv6
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (!ipv4.test(ip) && !ipv6.test(ip)) {
    return errorResponse(res, 400, "Invalid IP address format");
  }

  try {
    // Geolocation via ipwho.is (free, no API key)
    const { stdout: geoData } = await runCommand(
      "curl",
      ["-s", "-m", "10", `https://ipwho.is/${ip}`],
      { timeout: 15000 }
    );

    let geolocation = {};
    try {
      geolocation = JSON.parse(geoData);
    } catch {
      geolocation = { raw: geoData };
    }

    // WHOIS for IP
    let whoisData = {};
    try {
      const { stdout: whoisRaw } = await runCommand("whois", [ip], {
        timeout: 15000,
        ignoreExitCode: true,
      });
      const lines = whoisRaw.split("\n").filter((l) => l.trim() && !l.startsWith("%") && !l.startsWith("#"));
      for (const line of lines) {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          const key = line.substring(0, colonIdx).trim().toLowerCase().replace(/\s+/g, "_");
          const value = line.substring(colonIdx + 1).trim();
          if (key && value) {
            whoisData[key] = value;
          }
        }
      }
    } catch {
      whoisData = { error: "WHOIS lookup failed" };
    }

    // Reverse DNS
    let reverseDns = null;
    try {
      const { stdout: dnsResult } = await runCommand(
        "dig",
        ["-x", ip, "+short"],
        { timeout: 10000, ignoreExitCode: true }
      );
      reverseDns = dnsResult.trim() || null;
    } catch {}

    res.json({
      success: true,
      type: "ip",
      target: ip,
      result: {
        geolocation,
        whois: whoisData,
        reverse_dns: reverseDns,
      },
    });
  } catch (err) {
    errorResponse(res, 500, "IP OSINT failed", err.message);
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /osint/phone
// Body: { number, country_code?: string, timeout? }
// ══════════════════════════════════════════════════════════════════

app.post("/osint/phone", async (req, res) => {
  const { number, country_code = "US", timeout } = req.body;

  if (!number || typeof number !== "string") {
    return errorResponse(res, 400, "Invalid phone number");
  }

  const scriptFile = tmpFile(".py");
  const resultFile = tmpFile(".json");

  try {
    const pythonScript = `
import json
import sys
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

number = sys.argv[1]
country = sys.argv[2]
output_file = sys.argv[3]

result = {}

try:
    parsed = phonenumbers.parse(number, country)
    result["valid"] = phonenumbers.is_valid_number(parsed)
    result["possible"] = phonenumbers.is_possible_number(parsed)
    result["number_type"] = phonenumbers.number_type(parsed)
    result["formatted"] = {
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
    }
    result["country_code"] = parsed.country_code
    result["national_number"] = parsed.national_number
    result["location"] = geocoder.description_for_number(parsed, "en")
    result["carrier"] = carrier.name_for_number(parsed, "en")
    result["timezones"] = list(timezone.time_zones_for_number(parsed))

    # Number type mapping
    type_map = {
        0: "fixed_line",
        1: "mobile",
        2: "fixed_line_or_mobile",
        3: "toll_free",
        4: "premium_rate",
        5: "shared_cost",
        6: "voip",
        7: "personal_number",
        8: "pager",
        9: "uan",
        10: "voicemail",
        27: "unknown",
    }
    result["number_type_name"] = type_map.get(result["number_type"], "unknown")

except Exception as e:
    result["error"] = str(e)
    result["valid"] = False

with open(output_file, "w") as f:
    json.dump(result, f)
`;

    fs.writeFileSync(scriptFile, pythonScript);

    await runCommand(
      "python3",
      [scriptFile, number, country_code, resultFile],
      { timeout: timeout || 15000 }
    );

    let result = {};
    if (fs.existsSync(resultFile)) {
      const content = fs.readFileSync(resultFile, "utf-8").trim();
      if (content) {
        result = JSON.parse(content);
      }
    }

    res.json({
      success: true,
      type: "phone",
      target: number,
      result,
    });
  } catch (err) {
    errorResponse(res, 500, "Phone OSINT failed", err.message);
  } finally {
    cleanupFile(scriptFile);
    cleanupFile(resultFile);
  }
});

// ══════════════════════════════════════════════════════════════════
// Start server
// ══════════════════════════════════════════════════════════════════

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Security Bridge listening on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Tools list:   http://localhost:${PORT}/tools`);
});
