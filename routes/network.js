/**
 * Network Routes — Interfaces, connections, firewall, port scanning, DNS
 */
const fs = require('fs');
const path = require('path');
const dns = require('dns');

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, requireAdmin, execCommand } = ctx;

  // GET /api/network/interfaces
  app.get('/api/network/interfaces', requireAuth, async (req, res) => {
    try {
      const os = require('os');
      const ifaces = os.networkInterfaces();
      const interfaces = [];

      for (const [name, addrs] of Object.entries(ifaces)) {
        for (const addr of addrs) {
          interfaces.push({
            name,
            address: addr.address,
            netmask: addr.netmask,
            family: addr.family,
            mac: addr.mac,
            internal: addr.internal,
            cidr: addr.cidr,
          });
        }
      }

      // Try to get more detail on Linux
      if (process.platform !== 'win32') {
        try {
          const result = await execCommand('ip -br addr 2>/dev/null || ifconfig 2>/dev/null | head -50', { timeout: 5000 });
          if (result.stdout.trim()) {
            res.json({ interfaces, raw: result.stdout.trim() });
            return;
          }
        } catch {}
      }

      res.json({ interfaces });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/connections
  app.get('/api/network/connections', requireAuth, async (req, res) => {
    try {
      if (process.platform === 'win32') {
        try {
          const result = await execCommand('netstat -an | findstr "ESTABLISHED LISTENING" 2>NUL', { timeout: 10000 });
          const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
          const connections = lines.map(line => {
            const parts = line.trim().split(/\s+/);
            return { proto: parts[0], local: parts[1], foreign: parts[2], state: parts[3] || '' };
          });
          return res.json({ connections, total: connections.length });
        } catch {
          return res.json({ connections: [], error: 'Could not retrieve connections' });
        }
      }

      const result = await execCommand('ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null', { timeout: 10000 });
      const lines = (result.stdout || '').trim().split('\n');
      const header = lines.shift();
      const connections = lines.filter(Boolean).map(line => {
        const parts = line.trim().split(/\s+/);
        return {
          proto: parts[0] || '',
          state: parts[1] || '',
          recvQ: parts[2] || '',
          sendQ: parts[3] || '',
          local: parts[4] || '',
          peer: parts[5] || '',
          process: parts[6] || '',
        };
      });

      res.json({ connections, total: connections.length });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/firewall
  app.get('/api/network/firewall', requireAuth, async (req, res) => {
    try {
      if (process.platform === 'win32') {
        return res.json({
          tool: 'windows',
          status: 'Check Windows Firewall via Control Panel',
          rules: [],
          message: 'Windows Firewall management is done through Windows Security settings.',
        });
      }

      // Try ufw first
      try {
        const ufwResult = await execCommand('ufw status verbose 2>/dev/null', { timeout: 5000 });
        const output = ufwResult.stdout.trim();
        if (output.includes('Status:')) {
          const active = output.includes('active') && !output.includes('inactive');
          const rules = [];
          const lines = output.split('\n');
          for (const line of lines) {
            const match = line.match(/^(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)?\s*(.*)/i);
            if (match) {
              rules.push({ to: match[1].trim(), action: match[2], direction: match[3] || '', from: match[4].trim() });
            }
          }
          return res.json({ tool: 'ufw', status: active ? 'active' : 'inactive', rules, raw: output });
        }
      } catch {}

      // Try iptables
      try {
        const iptResult = await execCommand('iptables -L -n --line-numbers 2>/dev/null', { timeout: 5000 });
        if (iptResult.stdout.trim()) {
          const rules = [];
          const lines = iptResult.stdout.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/^(\d+)\s+(\w+)\s+(\w+)\s+--\s+(\S+)\s+(\S+)\s*(.*)/);
            if (match) {
              rules.push({ num: match[1], action: match[2], proto: match[3], source: match[4], dest: match[5], extra: match[6].trim() });
            }
          }
          return res.json({ tool: 'iptables', status: 'active', rules, raw: iptResult.stdout.trim().substring(0, 3000) });
        }
      } catch {}

      res.json({ tool: 'none', status: 'no firewall detected', rules: [] });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/network/scan — port scan
  app.post('/api/network/scan', requireRole('analyst'), async (req, res) => {
    try {
      const { target, ports } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });
      if (!/^[a-zA-Z0-9._\-:]+$/.test(target)) return res.status(400).json({ error: 'Invalid target format' });

      const portRange = ports || '1-1024';
      const cmd = `nmap -Pn -p ${portRange} --open -T4 ${target} 2>&1`;

      try {
        const result = await execCommand(cmd, { timeout: 120000 });
        const output = result.stdout || '';

        // Parse open ports
        const openPorts = [];
        const lines = output.split('\n');
        for (const line of lines) {
          const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
          if (match) {
            openPorts.push({
              port: parseInt(match[1]),
              protocol: match[2],
              service: match[3],
              version: match[4].trim() || '',
            });
          }
        }

        res.json({
          target,
          portRange,
          openPorts,
          total: openPorts.length,
          raw: output.substring(0, 5000),
          scannedAt: new Date().toISOString(),
        });
      } catch (e) {
        res.json({
          target,
          openPorts: [],
          error: 'nmap not available: ' + e.message,
          note: 'Install nmap: sudo apt install nmap',
        });
      }
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/dns — DNS lookup
  app.get('/api/network/dns', requireAuth, (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: 'domain query parameter required' });
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    const results = {};
    const lookups = [
      new Promise(resolve => {
        dns.resolve4(domain, (err, addrs) => { results.A = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolve6(domain, (err, addrs) => { results.AAAA = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveMx(domain, (err, addrs) => { results.MX = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveNs(domain, (err, addrs) => { results.NS = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveTxt(domain, (err, addrs) => { results.TXT = err ? [] : addrs.map(r => r.join('')); resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveCname(domain, (err, addrs) => { results.CNAME = err ? [] : addrs; resolve(); });
      }),
    ];

    Promise.all(lookups).then(() => {
      res.json({ domain, records: results });
    });
  });
};
