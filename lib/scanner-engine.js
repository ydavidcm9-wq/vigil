// Vigil — Scanner execution engine
// Wraps: nmap, nuclei, trivy, openssl
const { execCommand, binaryExists } = require('./exec');
const path = require('path');

const SCAN_TIMEOUT = 300000; // 5 minutes

/**
 * Standard finding format
 * @typedef {object} Finding
 * @property {string} severity - critical, high, medium, low, info
 * @property {string} title - Short title
 * @property {string} description - Detailed description
 * @property {string} target - What was scanned
 * @property {string|null} cve - CVE identifier if applicable
 * @property {string|null} remediation - Suggested fix
 * @property {string} scanner - Which scanner produced this
 * @property {string} timestamp - ISO timestamp
 */

/**
 * Run an Nmap scan
 * @param {string} target - IP, hostname, or CIDR
 * @param {object} options
 * @param {string} options.ports - Port specification (e.g., '1-1000', '22,80,443')
 * @param {boolean} options.serviceVersion - Enable service version detection (-sV)
 * @param {boolean} options.osDetection - Enable OS detection (-O, requires root)
 * @param {boolean} options.scriptScan - Enable default scripts (-sC)
 * @param {string} options.timing - Timing template T0-T5 (default: T3)
 * @returns {Promise<object>} - { available, findings[], raw, duration }
 */
async function runNmap(target, options = {}) {
  const available = await binaryExists('nmap');
  if (!available) {
    return { available: false, error: 'nmap is not installed', findings: [] };
  }

  if (!target) {
    return { available: true, error: 'No target specified', findings: [] };
  }

  // Build command
  const args = ['nmap'];

  if (options.ports) args.push('-p', options.ports);
  if (options.serviceVersion) args.push('-sV');
  if (options.osDetection) args.push('-O');
  if (options.scriptScan) args.push('-sC');

  const timing = options.timing || 'T3';
  args.push('-' + timing);

  // XML output for structured parsing
  args.push('-oX', '-');

  // Target last
  args.push(target);

  const startTime = Date.now();
  const result = await execCommand(args.join(' '), {
    timeout: SCAN_TIMEOUT,
    allowUnsafe: true
  });

  const duration = Date.now() - startTime;

  if (result.code !== 0 && !result.stdout) {
    return {
      available: true,
      error: result.stderr || 'Scan failed',
      findings: [],
      duration
    };
  }

  const findings = parseNmapXML(result.stdout, target);

  return {
    available: true,
    findings,
    raw: result.stdout,
    stderr: result.stderr,
    duration,
    target
  };
}

/**
 * Parse Nmap XML output into findings
 * @param {string} xml
 * @param {string} target
 * @returns {Finding[]}
 */
function parseNmapXML(xml, target) {
  const findings = [];
  if (!xml) return findings;

  // Extract open ports
  const portRegex = /<port protocol="([^"]*)" portid="(\d+)">[\s\S]*?<state state="([^"]*)"[^>]*\/>[\s\S]*?(?:<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?[^>]*\/>)?[\s\S]*?<\/port>/gi;
  let match;

  while ((match = portRegex.exec(xml)) !== null) {
    const protocol = match[1];
    const port = match[2];
    const state = match[3];
    const service = match[4] || 'unknown';
    const product = match[5] || '';
    const version = match[6] || '';

    if (state === 'open') {
      const serviceInfo = [service, product, version].filter(Boolean).join(' ');

      // Determine severity based on service
      let severity = 'info';
      const riskyPorts = ['21', '23', '25', '110', '143', '445', '3389', '5900'];
      const criticalPorts = ['23', '445', '3389'];

      if (criticalPorts.includes(port)) severity = 'high';
      else if (riskyPorts.includes(port)) severity = 'medium';

      findings.push({
        severity,
        title: `Open port ${port}/${protocol} (${service})`,
        description: `Port ${port}/${protocol} is open running ${serviceInfo}`,
        target,
        cve: null,
        remediation: severity !== 'info' ? `Review if port ${port} needs to be publicly accessible. Consider firewall rules or service disabling.` : null,
        scanner: 'nmap',
        timestamp: new Date().toISOString()
      });
    }
  }

  // Extract script output (vulns)
  const scriptRegex = /<script id="([^"]*)" output="([^"]*)"/gi;
  while ((match = scriptRegex.exec(xml)) !== null) {
    const scriptId = match[1];
    const output = match[2];

    if (output.toLowerCase().includes('vulnerable') || output.toLowerCase().includes('vuln')) {
      const cveMatch = output.match(/CVE-\d{4}-\d+/i);
      findings.push({
        severity: 'high',
        title: `Vulnerability detected: ${scriptId}`,
        description: output.substring(0, 500),
        target,
        cve: cveMatch ? cveMatch[0] : null,
        remediation: 'Apply vendor patches and updates',
        scanner: 'nmap',
        timestamp: new Date().toISOString()
      });
    }
  }

  // If no ports found, try plain text parsing
  if (findings.length === 0) {
    const plainRegex = /(\d+)\/(tcp|udp)\s+(open|filtered)\s+(\S+)/gm;
    while ((match = plainRegex.exec(xml)) !== null) {
      findings.push({
        severity: 'info',
        title: `Open port ${match[1]}/${match[2]} (${match[4]})`,
        description: `Port ${match[1]}/${match[2]} is ${match[3]} running ${match[4]}`,
        target,
        cve: null,
        remediation: null,
        scanner: 'nmap',
        timestamp: new Date().toISOString()
      });
    }
  }

  return findings;
}

/**
 * Run a Nuclei scan
 * @param {string} target - URL or IP
 * @param {object} options
 * @param {string[]} options.templates - Specific template names/paths
 * @param {string} options.severity - Filter by severity (critical,high,medium,low,info)
 * @param {string} options.tags - Filter by tags (e.g., 'cve,rce')
 * @returns {Promise<object>} - { available, findings[], raw, duration }
 */
async function runNuclei(target, options = {}) {
  const available = await binaryExists('nuclei');
  if (!available) {
    return { available: false, error: 'nuclei is not installed', findings: [] };
  }

  if (!target) {
    return { available: true, error: 'No target specified', findings: [] };
  }

  const args = ['nuclei', '-u', target, '-jsonl', '-silent'];

  if (options.templates && options.templates.length > 0) {
    options.templates.forEach(t => args.push('-t', t));
  }
  if (options.severity) {
    args.push('-severity', options.severity);
  }
  if (options.tags) {
    args.push('-tags', options.tags);
  }

  const startTime = Date.now();
  const result = await execCommand(args.join(' '), {
    timeout: SCAN_TIMEOUT,
    allowUnsafe: true
  });
  const duration = Date.now() - startTime;

  const findings = [];
  if (result.stdout) {
    result.stdout.split('\n').filter(Boolean).forEach(line => {
      try {
        const item = JSON.parse(line);
        findings.push({
          severity: (item.info && item.info.severity) || 'info',
          title: (item.info && item.info.name) || item['template-id'] || 'Unknown',
          description: (item.info && item.info.description) || item.matched || '',
          target: item.host || item.matched || target,
          cve: item.info && item.info.classification && item.info.classification['cve-id']
            ? item.info.classification['cve-id'][0]
            : null,
          remediation: item.info && item.info.remediation || null,
          scanner: 'nuclei',
          templateId: item['template-id'],
          timestamp: new Date().toISOString()
        });
      } catch {
        // Skip unparseable lines
      }
    });
  }

  return {
    available: true,
    findings,
    raw: result.stdout,
    stderr: result.stderr,
    duration,
    target
  };
}

/**
 * Run a Trivy scan
 * @param {string} target - Image name, directory, or repo URL
 * @param {string} type - 'image', 'fs', 'repo'
 * @param {object} options
 * @param {string} options.severity - Filter (CRITICAL,HIGH,MEDIUM,LOW)
 * @returns {Promise<object>} - { available, findings[], raw, duration }
 */
async function runTrivy(target, type = 'image', options = {}) {
  const available = await binaryExists('trivy');
  if (!available) {
    return { available: false, error: 'trivy is not installed', findings: [] };
  }

  if (!target) {
    return { available: true, error: 'No target specified', findings: [] };
  }

  const validTypes = ['image', 'fs', 'repo'];
  if (!validTypes.includes(type)) type = 'image';

  const args = ['trivy', type, '--format', 'json', '--quiet'];

  if (options.severity) {
    args.push('--severity', options.severity);
  }

  args.push(target);

  const startTime = Date.now();
  const result = await execCommand(args.join(' '), {
    timeout: SCAN_TIMEOUT,
    allowUnsafe: true
  });
  const duration = Date.now() - startTime;

  const findings = [];
  if (result.stdout) {
    try {
      const report = JSON.parse(result.stdout);
      const results = report.Results || [];
      results.forEach(r => {
        const vulns = r.Vulnerabilities || [];
        vulns.forEach(v => {
          findings.push({
            severity: (v.Severity || 'unknown').toLowerCase(),
            title: `${v.VulnerabilityID}: ${v.PkgName} ${v.InstalledVersion}`,
            description: v.Description || v.Title || '',
            target: `${target} (${r.Target || 'unknown'})`,
            cve: v.VulnerabilityID || null,
            remediation: v.FixedVersion ? `Update ${v.PkgName} to ${v.FixedVersion}` : 'No fix available yet',
            scanner: 'trivy',
            timestamp: new Date().toISOString()
          });
        });
      });
    } catch {
      // JSON parse failed
    }
  }

  return {
    available: true,
    findings,
    raw: result.stdout,
    stderr: result.stderr,
    duration,
    target
  };
}

/**
 * Check SSL certificate for a domain
 * @param {string} domain - Domain to check
 * @param {number} [port] - Port (default: 443)
 * @returns {Promise<object>} - { available, findings[], certInfo, raw }
 */
async function runSSLCheck(domain, port = 443) {
  const available = await binaryExists('openssl');
  if (!available) {
    return { available: false, error: 'openssl is not installed', findings: [] };
  }

  if (!domain) {
    return { available: true, error: 'No domain specified', findings: [] };
  }

  // Get certificate info
  const cmd = `echo | openssl s_client -connect ${domain}:${port} -servername ${domain} 2>/dev/null | openssl x509 -noout -text -dates -subject -issuer 2>/dev/null`;
  const result = await execCommand(cmd, { timeout: 15000, allowUnsafe: true });

  const findings = [];
  const certInfo = {};

  if (result.code !== 0 || !result.stdout) {
    findings.push({
      severity: 'critical',
      title: `SSL connection failed for ${domain}:${port}`,
      description: 'Could not establish SSL/TLS connection',
      target: `${domain}:${port}`,
      cve: null,
      remediation: 'Verify SSL certificate is installed and the service is running',
      scanner: 'openssl',
      timestamp: new Date().toISOString()
    });
    return { available: true, findings, certInfo, raw: result.stderr };
  }

  const output = result.stdout;

  // Parse dates
  const notBeforeMatch = output.match(/notBefore=(.+)/);
  const notAfterMatch = output.match(/notAfter=(.+)/);

  if (notAfterMatch) {
    const expiry = new Date(notAfterMatch[1].trim());
    certInfo.expires = expiry.toISOString();
    certInfo.daysRemaining = Math.ceil((expiry - new Date()) / 86400000);

    if (certInfo.daysRemaining < 0) {
      findings.push({
        severity: 'critical',
        title: `SSL certificate EXPIRED for ${domain}`,
        description: `Certificate expired ${Math.abs(certInfo.daysRemaining)} days ago`,
        target: `${domain}:${port}`,
        cve: null,
        remediation: 'Renew SSL certificate immediately',
        scanner: 'openssl',
        timestamp: new Date().toISOString()
      });
    } else if (certInfo.daysRemaining < 14) {
      findings.push({
        severity: 'high',
        title: `SSL certificate expiring soon for ${domain}`,
        description: `Certificate expires in ${certInfo.daysRemaining} days`,
        target: `${domain}:${port}`,
        cve: null,
        remediation: 'Renew SSL certificate before expiry',
        scanner: 'openssl',
        timestamp: new Date().toISOString()
      });
    } else if (certInfo.daysRemaining < 30) {
      findings.push({
        severity: 'medium',
        title: `SSL certificate renewal recommended for ${domain}`,
        description: `Certificate expires in ${certInfo.daysRemaining} days`,
        target: `${domain}:${port}`,
        cve: null,
        remediation: 'Schedule SSL certificate renewal',
        scanner: 'openssl',
        timestamp: new Date().toISOString()
      });
    } else {
      findings.push({
        severity: 'info',
        title: `SSL certificate valid for ${domain}`,
        description: `Certificate valid for ${certInfo.daysRemaining} days`,
        target: `${domain}:${port}`,
        cve: null,
        remediation: null,
        scanner: 'openssl',
        timestamp: new Date().toISOString()
      });
    }
  }

  // Parse subject
  const subjectMatch = output.match(/subject=(.+)/);
  if (subjectMatch) certInfo.subject = subjectMatch[1].trim();

  // Parse issuer
  const issuerMatch = output.match(/issuer=(.+)/);
  if (issuerMatch) certInfo.issuer = issuerMatch[1].trim();

  // Check for weak signature algorithm
  if (output.includes('sha1WithRSA') || output.includes('md5WithRSA')) {
    findings.push({
      severity: 'high',
      title: `Weak signature algorithm for ${domain}`,
      description: 'Certificate uses a deprecated/weak signature algorithm',
      target: `${domain}:${port}`,
      cve: null,
      remediation: 'Reissue certificate with SHA-256 or stronger',
      scanner: 'openssl',
      timestamp: new Date().toISOString()
    });
  }

  // Check key size
  const keyMatch = output.match(/Public-Key:\s*\((\d+)\s*bit\)/);
  if (keyMatch) {
    certInfo.keySize = parseInt(keyMatch[1]);
    if (certInfo.keySize < 2048) {
      findings.push({
        severity: 'high',
        title: `Weak key size (${certInfo.keySize}-bit) for ${domain}`,
        description: 'RSA key size should be at least 2048 bits',
        target: `${domain}:${port}`,
        cve: null,
        remediation: 'Reissue certificate with 2048-bit or 4096-bit key',
        scanner: 'openssl',
        timestamp: new Date().toISOString()
      });
    }
  }

  return {
    available: true,
    findings,
    certInfo,
    raw: output,
    target: `${domain}:${port}`
  };
}

/**
 * Check which scanners are available on the system
 * @returns {Promise<object>} - { nmap, nuclei, trivy, openssl }
 */
async function checkAvailability() {
  const [nmap, nuclei, trivy, openssl] = await Promise.all([
    binaryExists('nmap'),
    binaryExists('nuclei'),
    binaryExists('trivy'),
    binaryExists('openssl')
  ]);

  return { nmap, nuclei, trivy, openssl };
}

module.exports = {
  runNmap,
  runNuclei,
  runTrivy,
  runSSLCheck,
  parseNmapXML,
  checkAvailability
};
