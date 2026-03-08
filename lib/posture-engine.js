// Vigil — Security posture scoring engine
const os = require('os');
const fs = require('fs');
const { execCommand } = require('./exec');
const neuralCache = require('./neural-cache');

const CACHE_TTL = 60000; // 60 seconds
const CACHE_KEY = 'posture:score';

// Check weights (must sum to 100)
const CHECKS = {
  ssh: { weight: 15, name: 'SSH Configuration' },
  firewall: { weight: 15, name: 'Firewall Status' },
  ports: { weight: 12, name: 'Open Ports' },
  authFailures: { weight: 12, name: 'Authentication Failures' },
  sslHealth: { weight: 10, name: 'SSL Certificate Health' },
  updates: { weight: 10, name: 'System Updates' },
  services: { weight: 8, name: 'Running Services' },
  filePerms: { weight: 10, name: 'File Permissions' },
  docker: { weight: 8, name: 'Docker Security' }
};

/**
 * Calculate overall security posture
 * @param {object} [systemInfo] - Optional system info override
 * @returns {Promise<object>} - { score, grade, breakdown, recommendations }
 */
async function calculatePosture(systemInfo) {
  // Check cache
  const cached = neuralCache.get(CACHE_KEY);
  if (cached) return cached;

  const platform = os.platform();
  const isLinux = platform === 'linux';
  const breakdown = {};
  const recommendations = [];
  let totalScore = 0;

  // 1. SSH Configuration
  breakdown.ssh = await checkSSH(isLinux);
  totalScore += breakdown.ssh.score * (CHECKS.ssh.weight / 100);
  if (breakdown.ssh.recommendations) recommendations.push(...breakdown.ssh.recommendations);

  // 2. Firewall Status
  breakdown.firewall = await checkFirewall(isLinux);
  totalScore += breakdown.firewall.score * (CHECKS.firewall.weight / 100);
  if (breakdown.firewall.recommendations) recommendations.push(...breakdown.firewall.recommendations);

  // 3. Open Ports
  breakdown.ports = await checkOpenPorts(isLinux);
  totalScore += breakdown.ports.score * (CHECKS.ports.weight / 100);
  if (breakdown.ports.recommendations) recommendations.push(...breakdown.ports.recommendations);

  // 4. Auth Failures
  breakdown.authFailures = await checkAuthFailures(isLinux);
  totalScore += breakdown.authFailures.score * (CHECKS.authFailures.weight / 100);
  if (breakdown.authFailures.recommendations) recommendations.push(...breakdown.authFailures.recommendations);

  // 5. SSL Health
  breakdown.sslHealth = await checkSSLHealth();
  totalScore += breakdown.sslHealth.score * (CHECKS.sslHealth.weight / 100);
  if (breakdown.sslHealth.recommendations) recommendations.push(...breakdown.sslHealth.recommendations);

  // 6. Package Updates
  breakdown.updates = await checkUpdates(isLinux);
  totalScore += breakdown.updates.score * (CHECKS.updates.weight / 100);
  if (breakdown.updates.recommendations) recommendations.push(...breakdown.updates.recommendations);

  // 7. Running Services
  breakdown.services = await checkServices(isLinux);
  totalScore += breakdown.services.score * (CHECKS.services.weight / 100);
  if (breakdown.services.recommendations) recommendations.push(...breakdown.services.recommendations);

  // 8. File Permissions
  breakdown.filePerms = await checkFilePermissions(isLinux);
  totalScore += breakdown.filePerms.score * (CHECKS.filePerms.weight / 100);
  if (breakdown.filePerms.recommendations) recommendations.push(...breakdown.filePerms.recommendations);

  // 9. Docker Security
  breakdown.docker = await checkDocker();
  totalScore += breakdown.docker.score * (CHECKS.docker.weight / 100);
  if (breakdown.docker.recommendations) recommendations.push(...breakdown.docker.recommendations);

  const score = Math.round(totalScore);
  const grade = scoreToGrade(score);

  const result = {
    score,
    grade,
    breakdown: Object.keys(breakdown).map(key => ({
      check: CHECKS[key] ? CHECKS[key].name : key,
      key,
      score: breakdown[key].score,
      weight: CHECKS[key] ? CHECKS[key].weight : 0,
      status: breakdown[key].status,
      details: breakdown[key].details
    })),
    recommendations: recommendations.slice(0, 10),
    ts: new Date().toISOString()
  };

  neuralCache.set(CACHE_KEY, result, CACHE_TTL);
  return result;
}

function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// Individual check functions

async function checkSSH(isLinux) {
  if (!isLinux) {
    return { score: 50, status: 'unknown', details: 'Non-Linux platform — SSH check skipped', recommendations: [] };
  }

  try {
    const sshdConfig = '/etc/ssh/sshd_config';
    if (!fs.existsSync(sshdConfig)) {
      return { score: 50, status: 'unknown', details: 'sshd_config not found', recommendations: [] };
    }

    const config = fs.readFileSync(sshdConfig, 'utf8');
    let score = 100;
    const recommendations = [];

    // Check PermitRootLogin
    if (/^\s*PermitRootLogin\s+yes/m.test(config)) {
      score -= 30;
      recommendations.push('Disable root login: set PermitRootLogin no in /etc/ssh/sshd_config');
    }

    // Check PasswordAuthentication
    if (!/^\s*PasswordAuthentication\s+no/m.test(config)) {
      score -= 20;
      recommendations.push('Disable password auth: set PasswordAuthentication no (use key-based auth)');
    }

    // Check for non-standard port
    const portMatch = config.match(/^\s*Port\s+(\d+)/m);
    if (!portMatch || portMatch[1] === '22') {
      score -= 10;
      recommendations.push('Consider changing SSH port from default 22');
    }

    // Check MaxAuthTries
    const maxAuth = config.match(/^\s*MaxAuthTries\s+(\d+)/m);
    if (!maxAuth || parseInt(maxAuth[1]) > 5) {
      score -= 10;
      recommendations.push('Set MaxAuthTries to 3-5 in sshd_config');
    }

    return {
      score: Math.max(0, score),
      status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
      details: `SSH score: ${score}/100`,
      recommendations
    };
  } catch {
    return { score: 50, status: 'unknown', details: 'Could not read SSH config', recommendations: [] };
  }
}

async function checkFirewall(isLinux) {
  if (!isLinux) {
    return { score: 50, status: 'unknown', details: 'Non-Linux platform', recommendations: [] };
  }

  try {
    // Check ufw
    const ufw = await execCommand('ufw status 2>/dev/null', { timeout: 5000 });
    if (ufw.code === 0 && ufw.stdout.includes('Status: active')) {
      const rules = (ufw.stdout.match(/\n/g) || []).length - 2;
      return {
        score: Math.min(100, 80 + rules * 2),
        status: 'secure',
        details: `UFW active with ${rules} rules`,
        recommendations: []
      };
    }

    // Check iptables
    const ipt = await execCommand('iptables -L -n 2>/dev/null | wc -l', { timeout: 5000 });
    if (ipt.code === 0) {
      const lines = parseInt(ipt.stdout.trim()) || 0;
      if (lines > 10) {
        return { score: 75, status: 'warning', details: `iptables has ${lines} rule lines`, recommendations: [] };
      }
    }

    return {
      score: 20,
      status: 'critical',
      details: 'No active firewall detected',
      recommendations: ['Enable UFW: sudo ufw enable', 'Set default deny incoming: sudo ufw default deny incoming']
    };
  } catch {
    return { score: 30, status: 'unknown', details: 'Firewall check failed', recommendations: ['Install and enable UFW'] };
  }
}

async function checkOpenPorts(isLinux) {
  try {
    let result;
    if (isLinux) {
      result = await execCommand('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', { timeout: 5000 });
    } else {
      result = await execCommand('netstat -an 2>/dev/null', { timeout: 5000 });
    }

    if (result.code !== 0) {
      return { score: 50, status: 'unknown', details: 'Could not enumerate ports', recommendations: [] };
    }

    const lines = result.stdout.split('\n').filter(l => l.includes('LISTEN') || l.includes('ESTABLISHED'));
    const portCount = lines.length;

    let score;
    const recommendations = [];
    if (portCount <= 5) {
      score = 100;
    } else if (portCount <= 10) {
      score = 80;
    } else if (portCount <= 20) {
      score = 60;
      recommendations.push('Review open ports — ' + portCount + ' listening services detected');
    } else {
      score = 40;
      recommendations.push('Too many open ports (' + portCount + ') — close unnecessary services');
    }

    return {
      score,
      status: score >= 80 ? 'secure' : score >= 60 ? 'warning' : 'critical',
      details: portCount + ' listening ports',
      recommendations
    };
  } catch {
    return { score: 50, status: 'unknown', details: 'Port check failed', recommendations: [] };
  }
}

async function checkAuthFailures(isLinux) {
  if (!isLinux) {
    return { score: 70, status: 'unknown', details: 'Non-Linux platform', recommendations: [] };
  }

  try {
    const logFile = fs.existsSync('/var/log/auth.log') ? '/var/log/auth.log' : '/var/log/secure';
    if (!fs.existsSync(logFile)) {
      return { score: 60, status: 'unknown', details: 'Auth log not found', recommendations: [] };
    }

    const result = await execCommand(`grep -c "Failed password" ${logFile} 2>/dev/null || echo 0`, { timeout: 5000 });
    const failures = parseInt(result.stdout.trim()) || 0;

    let score;
    const recommendations = [];
    if (failures === 0) {
      score = 100;
    } else if (failures < 10) {
      score = 90;
    } else if (failures < 100) {
      score = 70;
      recommendations.push(failures + ' failed auth attempts — consider fail2ban');
    } else if (failures < 1000) {
      score = 40;
      recommendations.push(failures + ' failed auth attempts — install fail2ban immediately');
    } else {
      score = 10;
      recommendations.push(failures + ' failed auth attempts — active brute force detected, install fail2ban');
    }

    return {
      score,
      status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
      details: failures + ' failed login attempts',
      recommendations
    };
  } catch {
    return { score: 60, status: 'unknown', details: 'Auth failure check failed', recommendations: [] };
  }
}

async function checkSSLHealth() {
  // Check for any local SSL certificates
  try {
    const certDirs = ['/etc/letsencrypt/live', '/etc/ssl/certs'];
    let hasCerts = false;

    for (const dir of certDirs) {
      if (fs.existsSync(dir)) {
        hasCerts = true;
        break;
      }
    }

    if (!hasCerts) {
      return {
        score: 50,
        status: 'warning',
        details: 'No SSL certificates found',
        recommendations: ['Install SSL certificates via Let\'s Encrypt']
      };
    }

    return { score: 80, status: 'secure', details: 'SSL certificates present', recommendations: [] };
  } catch {
    return { score: 50, status: 'unknown', details: 'SSL check failed', recommendations: [] };
  }
}

async function checkUpdates(isLinux) {
  if (!isLinux) {
    return { score: 70, status: 'unknown', details: 'Non-Linux platform', recommendations: [] };
  }

  try {
    // Check for apt updates
    const result = await execCommand('apt list --upgradable 2>/dev/null | wc -l', { timeout: 10000 });
    if (result.code === 0) {
      const count = Math.max(0, (parseInt(result.stdout.trim()) || 1) - 1);
      let score;
      const recommendations = [];

      if (count === 0) {
        score = 100;
      } else if (count < 10) {
        score = 80;
        recommendations.push(count + ' packages need updating');
      } else if (count < 50) {
        score = 50;
        recommendations.push(count + ' packages need updating — run apt upgrade');
      } else {
        score = 20;
        recommendations.push(count + ' packages outdated — critical updates likely pending');
      }

      return {
        score,
        status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
        details: count + ' updates available',
        recommendations
      };
    }

    return { score: 60, status: 'unknown', details: 'Package manager check failed', recommendations: [] };
  } catch {
    return { score: 60, status: 'unknown', details: 'Update check failed', recommendations: [] };
  }
}

async function checkServices(isLinux) {
  if (!isLinux) {
    return { score: 70, status: 'unknown', details: 'Non-Linux platform', recommendations: [] };
  }

  try {
    const result = await execCommand('systemctl list-units --type=service --state=running --no-pager 2>/dev/null | wc -l', { timeout: 5000 });
    const count = parseInt(result.stdout.trim()) || 0;

    const recommendations = [];
    let score;
    if (count <= 20) {
      score = 100;
    } else if (count <= 40) {
      score = 80;
    } else if (count <= 60) {
      score = 60;
      recommendations.push('Review running services — ' + count + ' active');
    } else {
      score = 40;
      recommendations.push('Too many services running (' + count + ') — disable unnecessary ones');
    }

    return {
      score,
      status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
      details: count + ' running services',
      recommendations
    };
  } catch {
    return { score: 60, status: 'unknown', details: 'Service check failed', recommendations: [] };
  }
}

async function checkFilePermissions(isLinux) {
  if (!isLinux) {
    return { score: 70, status: 'unknown', details: 'Non-Linux platform', recommendations: [] };
  }

  try {
    let score = 100;
    const recommendations = [];

    // Check /etc/shadow permissions
    const shadow = await execCommand('stat -c "%a" /etc/shadow 2>/dev/null', { timeout: 3000 });
    if (shadow.code === 0) {
      const perms = shadow.stdout.trim();
      if (perms !== '640' && perms !== '600' && perms !== '0') {
        score -= 30;
        recommendations.push('/etc/shadow has unsafe permissions: ' + perms + ' (should be 640)');
      }
    }

    // Check /etc/passwd permissions
    const passwd = await execCommand('stat -c "%a" /etc/passwd 2>/dev/null', { timeout: 3000 });
    if (passwd.code === 0) {
      const perms = passwd.stdout.trim();
      if (perms !== '644') {
        score -= 20;
        recommendations.push('/etc/passwd has unusual permissions: ' + perms + ' (should be 644)');
      }
    }

    // Check for world-writable files in /etc
    const worldWritable = await execCommand('find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -5', { timeout: 5000 });
    if (worldWritable.code === 0 && worldWritable.stdout.trim()) {
      const count = worldWritable.stdout.trim().split('\n').length;
      score -= 20;
      recommendations.push(count + ' world-writable files found in /etc');
    }

    return {
      score: Math.max(0, score),
      status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
      details: 'File permission score: ' + score + '/100',
      recommendations
    };
  } catch {
    return { score: 60, status: 'unknown', details: 'File permission check failed', recommendations: [] };
  }
}

async function checkDocker() {
  try {
    const result = await execCommand('docker info 2>/dev/null', { timeout: 5000 });
    if (result.code !== 0) {
      return { score: 80, status: 'info', details: 'Docker not installed/running', recommendations: [] };
    }

    let score = 80;
    const recommendations = [];

    // Check if running as root
    const whoami = await execCommand('docker info --format "{{.SecurityOptions}}" 2>/dev/null', { timeout: 5000 });
    if (whoami.code === 0) {
      if (whoami.stdout.includes('rootless')) {
        score = 100;
      } else {
        recommendations.push('Consider running Docker in rootless mode');
      }

      if (!whoami.stdout.includes('seccomp')) {
        score -= 10;
        recommendations.push('Enable seccomp profiles for Docker containers');
      }
    }

    // Check for privileged containers
    const priv = await execCommand('docker ps --format "{{.Names}}" --filter "label=com.docker.compose.project" 2>/dev/null', { timeout: 5000 });
    if (priv.code === 0 && priv.stdout.trim()) {
      const containers = priv.stdout.trim().split('\n').length;
      if (containers > 20) {
        score -= 10;
        recommendations.push(containers + ' containers running — review for necessity');
      }
    }

    return {
      score: Math.max(0, score),
      status: score >= 80 ? 'secure' : score >= 50 ? 'warning' : 'critical',
      details: 'Docker security score: ' + score + '/100',
      recommendations
    };
  } catch {
    return { score: 80, status: 'info', details: 'Docker check skipped', recommendations: [] };
  }
}

module.exports = { calculatePosture, scoreToGrade };
