/**
 * MCP Server Route — Model Context Protocol (Streamable HTTP)
 * Vigil Security — 15 tools, 3 resources, 4 prompts
 *
 * SDK: @modelcontextprotocol/sdk v1.x
 * Transport: Streamable HTTP (stateless, one request = one connection)
 */
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}

module.exports = function (app, ctx) {

  function createMcpServer() {
    const server = new McpServer({
      name: 'vigil-security',
      version: '1.0.0',
      instructions: 'Vigil Security — AI-powered security operations. Use tools to check security posture, scan for vulnerabilities, investigate threats, manage incidents, and generate reports.',
    });

    // ════════════════════════════════════════════════════════════════════════
    // TOOLS (15)
    // ════════════════════════════════════════════════════════════════════════

    // 1. check_posture
    server.tool('check_posture', 'Get current security posture score and breakdown', {},
      async () => {
        try {
          if (ctx.getPostureScore) {
            const posture = await ctx.getPostureScore();
            return { content: [{ type: 'text', text: JSON.stringify(posture, null, 2) }] };
          }
          return { content: [{ type: 'text', text: 'Posture scoring not available' }], isError: true };
        } catch (e) {
          return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
        }
      }
    );

    // 2. scan_ports
    server.tool('scan_ports', 'Run an nmap port scan on a target', {
      target: z.string().describe('IP address or hostname to scan'),
      ports: z.string().default('1-1024').describe('Port range (e.g., 1-1024, 22,80,443)'),
    }, async ({ target, ports }) => {
      try {
        if (!/^[a-zA-Z0-9.\-:]+$/.test(target)) return { content: [{ type: 'text', text: 'Invalid target format' }], isError: true };
        if (!/^[\d,\-]+$/.test(ports)) return { content: [{ type: 'text', text: 'Invalid port range' }], isError: true };
        const result = await ctx.execFileSafe('nmap', ['-Pn', '-p', ports, '--open', '-T4', target], { timeout: 120000 });
        return { content: [{ type: 'text', text: result.stdout || result.stderr || 'No output' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'nmap error: ' + e.message }], isError: true };
      }
    });

    // 3. scan_vulnerabilities
    server.tool('scan_vulnerabilities', 'Run a nuclei vulnerability scan on a target', {
      target: z.string().describe('URL or hostname to scan'),
      severity: z.string().default('critical,high').describe('Severity filter'),
    }, async ({ target, severity }) => {
      try {
        if (!/^[a-zA-Z0-9.\-:\/]+$/.test(target)) return { content: [{ type: 'text', text: 'Invalid target format' }], isError: true };
        const validSev = severity.split(',').filter(s => ['critical','high','medium','low','info'].includes(s.trim())).join(',') || 'critical,high';
        const result = await ctx.execFileSafe('nuclei', ['-u', target, '-severity', validSev, '-silent'], { timeout: 300000 });
        return { content: [{ type: 'text', text: result.stdout || 'No vulnerabilities found (or nuclei not installed)' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'nuclei error: ' + e.message }], isError: true };
      }
    });

    // 4. check_ssl
    server.tool('check_ssl', 'Check SSL/TLS certificate for a domain', {
      domain: z.string().describe('Domain to check SSL certificate'),
    }, async ({ domain }) => {
      try {
        const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, '');
        if (!safeDomain || safeDomain.length > 253) return { content: [{ type: 'text', text: 'Invalid domain' }], isError: true };
        const result = await ctx.execCommand(
          `echo | openssl s_client -servername ${safeDomain} -connect ${safeDomain}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`,
          { timeout: 15000 }
        );
        return { content: [{ type: 'text', text: result.stdout || 'Could not retrieve certificate' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'SSL check error: ' + e.message }], isError: true };
      }
    });

    // 5. query_logs (cross-platform — uses Vigil security data stores)
    server.tool('query_logs', 'Search security logs and events using natural language', {
      query: z.string().describe('What to search for (e.g., "recent threats", "critical vulnerabilities", "scan results")'),
    }, async ({ query }) => {
      try {
        // Gather from Vigil data stores (works on all platforms)
        const stores = {
          'audit-log': readJSON(path.join(DATA, 'audit-log.json'), []),
          'threats': readJSON(path.join(DATA, 'threats.json'), []),
          'alerts': readJSON(path.join(DATA, 'alerts.json'), []),
          'incidents': readJSON(path.join(DATA, 'incidents.json'), []),
          'hunts': readJSON(path.join(DATA, 'hunts.json'), []),
        };
        const summary = Object.entries(stores)
          .filter(([, v]) => v.length > 0)
          .map(([k, v]) => `${k}: ${v.length} records\n${v.slice(-5).map(e => JSON.stringify(e)).join('\n')}`)
          .join('\n\n');

        if (!summary) return { content: [{ type: 'text', text: 'No security events found. Run scans or use other Vigil features to generate data.' }] };

        if (ctx.askAI) {
          const prompt = `User query: "${query}"\n\nSecurity data:\n${summary.substring(0, 4000)}\n\nAnswer the query using the data. Be concise (3-5 sentences). No markdown.`;
          const analysis = await ctx.askAI(prompt, { timeout: 20000 });
          return { content: [{ type: 'text', text: analysis || summary.substring(0, 2000) }] };
        }
        return { content: [{ type: 'text', text: summary.substring(0, 3000) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Log query error: ' + e.message }], isError: true };
      }
    });

    // 6. osint_domain
    server.tool('osint_domain', 'Perform domain reconnaissance', {
      domain: z.string().describe('Domain to investigate'),
    }, async ({ domain }) => {
      try {
        const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, '');
        if (!safeDomain) return { content: [{ type: 'text', text: 'Invalid domain' }], isError: true };
        const results = {};
        try {
          const dig = await ctx.execFileSafe('dig', ['+short', 'A', safeDomain], { timeout: 10000 });
          results.A = dig.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        try {
          const mx = await ctx.execFileSafe('dig', ['+short', 'MX', safeDomain], { timeout: 10000 });
          results.MX = mx.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        try {
          const ns = await ctx.execFileSafe('dig', ['+short', 'NS', safeDomain], { timeout: 10000 });
          results.NS = ns.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        return { content: [{ type: 'text', text: JSON.stringify({ domain: safeDomain, dns: results }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'OSINT error: ' + e.message }], isError: true };
      }
    });

    // 7. osint_ip
    server.tool('osint_ip', 'Perform IP address lookup', {
      ip: z.string().describe('IP address to look up'),
    }, async ({ ip }) => {
      try {
        const http = require('http');
        const geo = await new Promise((resolve, reject) => {
          const r = http.get(`http://ip-api.com/json/${ip}`, { timeout: 10000 }, (resp) => {
            let d = '';
            resp.on('data', c => d += c);
            resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ error: 'parse failed' }); } });
          });
          r.on('error', reject);
          r.setTimeout(10000, () => { r.destroy(); reject(new Error('timeout')); });
        });
        return { content: [{ type: 'text', text: JSON.stringify(geo, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'IP lookup error: ' + e.message }], isError: true };
      }
    });

    // 8. triage_alert
    server.tool('triage_alert', 'AI triage of a security alert', {
      alertTitle: z.string().describe('Title of the alert'),
      alertDetails: z.string().describe('Alert details and context'),
      severity: z.string().default('medium').describe('Alert severity'),
    }, async ({ alertTitle, alertDetails, severity }) => {
      try {
        const prompt = `Triage this security alert. Respond with verdict (true_positive/false_positive/needs_investigation), confidence (0-100), and 2-3 sentence reasoning.\n\nAlert: ${alertTitle}\nSeverity: ${severity}\nDetails: ${alertDetails}`;
        const result = await ctx.askAI(prompt, { timeout: 20000 });
        return { content: [{ type: 'text', text: result || 'Triage unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Triage error: ' + e.message }], isError: true };
      }
    });

    // 9. hunt_threat
    server.tool('hunt_threat', 'Investigate a threat hypothesis', {
      hypothesis: z.string().describe('Threat hypothesis to investigate'),
    }, async ({ hypothesis }) => {
      try {
        if (process.platform === 'win32') {
          return { content: [{ type: 'text', text: 'Threat hunting requires Linux' }] };
        }
        // Gather quick evidence
        const cmds = {
          processes: 'ps aux --sort=-%cpu 2>/dev/null | head -15',
          connections: 'ss -tunapl 2>/dev/null | head -20',
          logins: 'last -10 2>/dev/null',
        };
        const evidence = {};
        for (const [key, cmd] of Object.entries(cmds)) {
          try {
            const r = await ctx.execCommand(cmd, { timeout: 10000 });
            evidence[key] = r.stdout.substring(0, 1000);
          } catch {}
        }
        const prompt = `Hypothesis: ${hypothesis}\n\nEvidence:\n${JSON.stringify(evidence, null, 2)}\n\nAnalyze the evidence. Is the hypothesis confirmed, not confirmed, or inconclusive? Explain in 3-5 sentences.`;
        const analysis = await ctx.askAI(prompt, { timeout: 30000 });
        return { content: [{ type: 'text', text: analysis || 'Analysis unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Hunt error: ' + e.message }], isError: true };
      }
    });

    // 10. run_agent
    server.tool('run_agent', 'Execute a security agent by name or slug', {
      agentSlug: z.string().describe('Agent slug or name (e.g., port-scanner, firewall-auditor)'),
      input: z.string().describe('Input data for the agent'),
    }, async ({ agentSlug, input }) => {
      try {
        const agents = readJSON(path.join(DATA, 'agents.json'), []);
        const agent = agents.find(a => a.slug === agentSlug || a.name.toLowerCase() === agentSlug.toLowerCase());
        if (!agent) return { content: [{ type: 'text', text: 'Agent not found: ' + agentSlug }], isError: true };
        const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, input);
        const output = await ctx.askAI(prompt, { timeout: 60000 });
        return { content: [{ type: 'text', text: output || 'No output from agent' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Agent error: ' + e.message }], isError: true };
      }
    });

    // 11. launch_campaign
    server.tool('launch_campaign', 'Start a multi-agent security campaign', {
      goal: z.string().describe('Campaign goal (e.g., "full security audit of example.com")'),
      maxAgents: z.number().default(3).describe('Maximum number of agents to run'),
    }, async ({ goal, maxAgents }) => {
      try {
        const agents = readJSON(path.join(DATA, 'agents.json'), []);
        const goalLower = goal.toLowerCase();
        const selected = agents.filter(a => a.enabled).filter(a => {
          const text = (a.name + ' ' + a.description + ' ' + a.category).toLowerCase();
          return goalLower.split(/\s+/).some(word => word.length > 3 && text.includes(word));
        }).slice(0, maxAgents);

        if (selected.length === 0) return { content: [{ type: 'text', text: 'No matching agents for this goal' }] };

        const results = [];
        for (const agent of selected) {
          try {
            const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, goal);
            const output = await ctx.askAI(prompt, { timeout: 60000 });
            results.push({ agent: agent.name, output: (output || 'No output').substring(0, 500) });
          } catch (e) {
            results.push({ agent: agent.name, error: e.message });
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify({ goal, agentsRun: results.length, results }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Campaign error: ' + e.message }], isError: true };
      }
    });

    // 12. generate_report
    server.tool('generate_report', 'Generate a security report', {
      type: z.enum(['security-audit', 'vulnerability', 'compliance', 'incident', 'executive']).describe('Report type'),
    }, async ({ type }) => {
      try {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const findings = [];
        for (const s of scans) { if (s.findings) findings.push(...s.findings); }
        const threats = readJSON(path.join(DATA, 'threats.json'), []);
        const incidents = readJSON(path.join(DATA, 'incidents.json'), []);

        const prompt = `Generate a brief ${type} security report.\n\nData:\n- Findings: ${findings.length} total (${findings.filter(f => f.severity === 'critical').length} critical)\n- Active threats: ${threats.filter(t => t.status === 'active').length}\n- Open incidents: ${incidents.filter(i => i.status !== 'closed').length}\n\nWrite a concise report with key findings, risks, and recommendations.`;
        const report = await ctx.askAI(prompt, { timeout: 30000 });
        return { content: [{ type: 'text', text: report || 'Report generation unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Report error: ' + e.message }], isError: true };
      }
    });

    // 13. compliance_check
    server.tool('compliance_check', 'Check compliance against a framework', {
      framework: z.enum(['soc2', 'iso27001', 'nist800-53']).describe('Compliance framework'),
    }, async ({ framework }) => {
      try {
        // Quick check summary
        const names = { soc2: 'SOC 2 Type II', iso27001: 'ISO 27001:2022', 'nist800-53': 'NIST 800-53 Rev. 5' };
        const prompt = `You are a compliance auditor. Give a brief (5-7 sentence) assessment of a server's likely compliance with ${names[framework] || framework}. Consider: access controls, encryption, logging, monitoring, incident response, vulnerability management. This is a Linux server running a Node.js security platform.`;
        const result = await ctx.askAI(prompt, { timeout: 20000 });
        return { content: [{ type: 'text', text: result || 'Compliance check unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Compliance error: ' + e.message }], isError: true };
      }
    });

    // 14. list_findings
    server.tool('list_findings', 'Get vulnerability findings', {
      severity: z.string().default('all').describe('Filter: critical, high, medium, low, or all'),
      limit: z.number().default(20).describe('Max findings to return'),
    }, async ({ severity, limit }) => {
      try {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        let findings = [];
        for (const s of scans) { if (s.findings) findings.push(...s.findings); }
        if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
        const result = findings.slice(0, limit).map(f => ({
          id: f.id, title: f.title, severity: f.severity, type: f.type, status: f.status,
        }));
        return { content: [{ type: 'text', text: JSON.stringify({ total: findings.length, findings: result }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
      }
    });

    // 15. incident_create
    server.tool('incident_create', 'Create a security incident', {
      title: z.string().describe('Incident title'),
      severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
      description: z.string().describe('Incident description'),
      type: z.string().default('security').describe('Incident type'),
    }, async ({ title, severity, description, type }) => {
      try {
        const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
        const incident = {
          id: crypto.randomUUID(),
          title, severity, description, type,
          status: 'open',
          timeline: [{ id: crypto.randomUUID(), event: 'Incident created via MCP', detail: description, timestamp: new Date().toISOString(), actor: 'mcp' }],
          createdAt: new Date().toISOString(),
          createdBy: 'mcp',
        };
        incidents.push(incident);
        fs.mkdirSync(DATA, { recursive: true });
        fs.writeFileSync(path.join(DATA, 'incidents.json'), JSON.stringify(incidents, null, 2));
        return { content: [{ type: 'text', text: 'Incident created: ' + incident.id + ' — ' + title }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
      }
    });

    // ════════════════════════════════════════════════════════════════════════
    // RESOURCES (3)
    // ════════════════════════════════════════════════════════════════════════

    server.resource('posture', 'vigil://posture', { description: 'Current security posture overview' },
      async (uri) => {
        let posture = { score: 'unknown', grade: 'N/A' };
        if (ctx.getPostureScore) {
          try { posture = await ctx.getPostureScore(); } catch {}
        }
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(posture, null, 2) }] };
      }
    );

    server.resource('threats', 'vigil://threats', { description: 'Active security threats' },
      async (uri) => {
        const threats = readJSON(path.join(DATA, 'threats.json'), []);
        const active = threats.filter(t => t.status === 'active').map(t => ({
          id: t.id, type: t.type, title: t.title, severity: t.severity, detectedAt: t.detectedAt,
        }));
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(active, null, 2) }] };
      }
    );

    server.resource('findings', 'vigil://findings', { description: 'Open vulnerability findings' },
      async (uri) => {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const findings = [];
        for (const s of scans) {
          if (s.findings) {
            for (const f of s.findings) {
              if (f.status === 'open') {
                findings.push({ id: f.id, title: f.title, severity: f.severity, type: f.type });
              }
            }
          }
        }
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(findings, null, 2) }] };
      }
    );

    // ════════════════════════════════════════════════════════════════════════
    // PROMPTS (4)
    // ════════════════════════════════════════════════════════════════════════

    server.prompt('security_audit', 'Full security assessment of the system', {},
      () => ({
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Perform a full security audit. Use check_posture to get the security score, list_findings to see vulnerabilities, and scan_ports on localhost to check open ports. Then generate a security-audit report with generate_report. Provide a comprehensive assessment with prioritized recommendations.' },
        }],
      })
    );

    server.prompt('incident_response', 'Guided incident investigation', {
      incident: z.string().describe('Brief description of the security incident'),
    }, ({ incident }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Investigate this security incident: "${incident}". Use hunt_threat to gather evidence, query_logs to search for related activity, and check_posture for overall security state. Create an incident with incident_create if warranted. Provide a step-by-step investigation report.` },
      }],
    }));

    server.prompt('threat_briefing', 'Daily security threat summary', {},
      () => ({
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Generate a daily threat briefing. Use check_posture for the security score, list_findings for open vulnerabilities, and read the vigil://threats resource for active threats. Summarize the current threat landscape, highlight critical items, and recommend actions for today.' },
        }],
      })
    );

    server.prompt('compliance_report', 'Framework compliance assessment', {
      framework: z.enum(['soc2', 'iso27001', 'nist800-53']).default('soc2').describe('Compliance framework'),
    }, ({ framework }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Assess compliance with ${framework}. Use compliance_check to evaluate the framework, check_posture for security score, and list_findings for vulnerabilities. Generate a compliance report with findings, gaps, and a remediation roadmap.` },
      }],
    }));

    return server;
  }

  // ── POST /mcp — Streamable HTTP MCP endpoint ──────────────────────────

  app.post('/mcp', ctx.requireAuth, async (req, res) => {
    try {
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on('close', () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: e.message }, id: null });
      }
    }
  });

  // GET /mcp — SSE not supported in stateless mode
  app.get('/mcp', ctx.requireAuth, (req, res) => {
    res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'SSE not supported in stateless mode. Use POST.' }, id: null }));
  });

  // DELETE /mcp — Session termination (no-op)
  app.delete('/mcp', ctx.requireAuth, (req, res) => {
    res.status(200).json({ success: true });
  });

  // ── POST /api/mcp/test — GUI test endpoint using InMemoryTransport ────

  app.post('/api/mcp/test', ctx.requireAuth, async (req, res) => {
    const { method, params } = req.body;
    if (!method) return res.status(400).json({ error: 'method required' });

    try {
      const server = createMcpServer();
      const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
      const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'vigil-test', version: '1.0.0' });
      await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

      let result;
      if (method === 'tools/list') {
        result = await client.listTools();
      } else if (method === 'resources/list') {
        result = await client.listResources();
      } else if (method === 'prompts/list') {
        result = await client.listPrompts();
      } else if (method === 'tools/call') {
        result = await client.callTool(params || {});
      } else if (method === 'prompts/get') {
        result = await client.getPrompt({ name: (params || {}).name, arguments: (params || {}).arguments || {} });
      } else if (method === 'resources/read') {
        result = await client.readResource(params || {});
      } else {
        result = { error: 'Unknown method: ' + method };
      }

      await client.close();
      await server.close();
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── MCP connection info ───────────────────────────────────────────────

  app.get('/api/mcp/info', ctx.requireAuth, (req, res) => {
    const host = req.headers.host || 'localhost:3001';
    const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const mcpUrl = protocol + '://' + host + '/mcp';
    res.json({
      url: mcpUrl,
      transport: 'streamable-http',
      version: '1.0.0',
      tools: 15,
      resources: 3,
      prompts: 4,
      instructions: {
        claudeDesktop: {
          config: {
            mcpServers: {
              vigil: {
                type: 'streamable-http',
                url: mcpUrl,
                headers: { Cookie: 'vigil_session=YOUR_SESSION_TOKEN' },
              },
            },
          },
          note: 'Replace YOUR_SESSION_TOKEN with your Vigil session cookie value',
        },
        claudeCode: 'claude mcp add --transport http vigil ' + mcpUrl,
        curl: 'curl -X POST ' + mcpUrl + ' -H "Content-Type: application/json" -b "vigil_session=TOKEN" -d \'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\'',
      },
    });
  });
};
