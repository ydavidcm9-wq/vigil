/**
 * System Routes — CPU, memory, disk, processes, hostname, uptime
 */
const os = require('os');
const path = require('path');
const fs = require('fs');

function getCpuPercent() {
  const cpus = os.cpus();
  let totalIdle = 0, totalTick = 0;
  for (const cpu of cpus) {
    for (const type of Object.keys(cpu.times)) totalTick += cpu.times[type];
    totalIdle += cpu.times.idle;
  }
  return Math.round(((totalTick - totalIdle) / totalTick) * 10000) / 100;
}

module.exports = function (app, ctx) {
  const { execCommand, requireAuth } = ctx;

  function getSystemInfo() {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const cpus = os.cpus();
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      release: os.release(),
      uptime: Math.floor(os.uptime()),
      uptimeHours: Math.round(os.uptime() / 3600 * 10) / 10,
      cpuModel: cpus[0] ? cpus[0].model : 'unknown',
      cpuCount: cpus.length,
      cpuPct: getCpuPercent(),
      totalMemMB: Math.round(totalMem / 1024 / 1024),
      usedMemMB: Math.round(usedMem / 1024 / 1024),
      freeMemMB: Math.round(freeMem / 1024 / 1024),
      usedMemPct: Math.round((usedMem / totalMem) * 10000) / 100,
      loadAvg: os.loadavg(),
      nodeVersion: process.version,
      pid: process.pid,
      ts: Date.now(),
    };
  }

  // Expose for broadcasts and other routes
  ctx.getSystemInfo = getSystemInfo;

  // GET /api/system
  app.get('/api/system', requireAuth, async (req, res) => {
    try {
      const info = getSystemInfo();

      // Try to get disk usage
      try {
        if (process.platform !== 'win32') {
          const df = await execCommand("df -h / | tail -1 | awk '{print $2, $3, $4, $5}'", { timeout: 5000 });
          const parts = df.stdout.trim().split(/\s+/);
          if (parts.length >= 4) {
            info.disk = {
              total: parts[0],
              used: parts[1],
              available: parts[2],
              usedPercent: parseInt(parts[3]) || 0,
            };
          }
        } else {
          const wmic = await execCommand('wmic logicaldisk get size,freespace,caption /format:csv 2>NUL', { timeout: 5000 });
          const lines = wmic.stdout.trim().split('\n').filter(l => l.trim() && !l.includes('Node'));
          const disks = [];
          for (const line of lines) {
            const cols = line.split(',').map(s => s.trim());
            if (cols.length >= 4 && cols[2]) {
              const free = parseInt(cols[1]) || 0;
              const total = parseInt(cols[3]) || 1;
              disks.push({
                drive: cols[0] || cols[2],
                total: Math.round(total / 1073741824) + 'G',
                free: Math.round(free / 1073741824) + 'G',
                usedPercent: Math.round(((total - free) / total) * 100),
              });
            }
          }
          if (disks.length) info.disks = disks;
        }
      } catch {}

      info.connectedClients = ctx.io ? ctx.io.engine.clientsCount || 0 : 0;
      res.json(info);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/system/processes
  app.get('/api/system/processes', requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 25, 100);
      const sortBy = req.query.sort === 'memory' ? 'mem' : 'cpu';

      if (process.platform === 'win32') {
        const result = await execCommand(
          `powershell -c "Get-Process | Sort-Object -Property ${sortBy === 'mem' ? 'WorkingSet64' : 'CPU'} -Descending | Select-Object -First ${limit} Id,ProcessName,CPU,@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} | ConvertTo-Json"`,
          { timeout: 10000 }
        );
        let procs = [];
        try { procs = JSON.parse(result.stdout || '[]'); } catch {}
        if (!Array.isArray(procs)) procs = [procs];
        res.json({
          processes: procs.map(p => ({
            pid: p.Id,
            name: p.ProcessName,
            cpu: p.CPU ? Math.round(p.CPU * 100) / 100 : 0,
            memMB: p.MemMB || 0,
          })),
        });
      } else {
        const cmd = `ps aux --sort=-%${sortBy} | head -${limit + 1}`;
        const result = await execCommand(cmd, { timeout: 10000 });
        const lines = result.stdout.trim().split('\n');
        const header = lines.shift();
        const processes = lines.map(line => {
          const parts = line.trim().split(/\s+/);
          return {
            user: parts[0],
            pid: parseInt(parts[1]) || 0,
            cpu: parseFloat(parts[2]) || 0,
            mem: parseFloat(parts[3]) || 0,
            vsz: parseInt(parts[4]) || 0,
            rss: parseInt(parts[5]) || 0,
            tty: parts[6],
            stat: parts[7],
            start: parts[8],
            time: parts[9],
            command: parts.slice(10).join(' '),
          };
        });
        res.json({ processes });
      }
    } catch (e) {
      res.status(500).json({ error: e.message, processes: [] });
    }
  });
};
