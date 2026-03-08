// Vigil — Shell command execution wrapper
const { exec, execFile } = require('child_process');
const path = require('path');

// Characters that could enable command injection
const DANGEROUS_CHARS = /[;&|`$(){}[\]<>!\\]/g;

/**
 * Execute a shell command safely
 * @param {string} cmd - Command to execute
 * @param {object} options - Options
 * @param {number} options.timeout - Timeout in ms (default: 30000)
 * @param {string} options.cwd - Working directory
 * @param {object} options.env - Environment variables
 * @param {boolean} options.allowUnsafe - Skip sanitization (use with caution)
 * @param {number} options.maxBuffer - Max buffer size (default: 10MB)
 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
 */
function execCommand(cmd, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 30000;
    const maxBuffer = options.maxBuffer || 10 * 1024 * 1024;

    // Sanitization check — block commands with excessive dangerous characters
    if (!options.allowUnsafe && typeof cmd === 'string') {
      const dangerous = cmd.match(DANGEROUS_CHARS);
      if (dangerous && dangerous.length > 5) {
        console.warn('  exec: BLOCKED potentially dangerous command:', cmd.substring(0, 100));
        return resolve({ stdout: '', stderr: 'Command blocked by sanitization', code: 1 });
      }
    }

    const execOpts = {
      timeout,
      maxBuffer,
      cwd: options.cwd || process.cwd(),
      env: options.env || { ...process.env },
      windowsHide: true
    };

    const child = exec(cmd, execOpts, (error, stdout, stderr) => {
      resolve({
        stdout: stdout ? stdout.toString() : '',
        stderr: stderr ? stderr.toString() : '',
        code: error ? (error.code || 1) : 0
      });
    });
    // Close stdin so CLI tools (e.g. claude) don't hang waiting for input
    child.stdin.end();
  });
}

/**
 * Execute a file directly (safer than exec for known binaries)
 * @param {string} binary - Path to binary
 * @param {string[]} args - Arguments array
 * @param {object} options - Options
 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
 */
function execFileSafe(binary, args = [], options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 30000;
    const maxBuffer = options.maxBuffer || 10 * 1024 * 1024;

    const execOpts = {
      timeout,
      maxBuffer,
      cwd: options.cwd || process.cwd(),
      env: options.env || { ...process.env },
      windowsHide: true
    };

    execFile(binary, args, execOpts, (error, stdout, stderr) => {
      resolve({
        stdout: stdout ? stdout.toString() : '',
        stderr: stderr ? stderr.toString() : '',
        code: error ? (error.code || 1) : 0
      });
    });
  });
}

/**
 * Check if a binary exists on the system
 * @param {string} name - Binary name
 * @returns {Promise<boolean>}
 */
async function binaryExists(name) {
  const cmd = process.platform === 'win32' ? `where ${name} 2>nul` : `which ${name} 2>/dev/null`;
  const result = await execCommand(cmd, { timeout: 5000 });
  return result.code === 0 && result.stdout.trim().length > 0;
}

/**
 * Atomic JSON file write — write to temp file then rename (prevents corruption on crash)
 * @param {string} filePath - Path to JSON file
 * @param {*} data - Data to serialize
 */
function writeJSONAtomic(filePath, data) {
  const fs = require('fs');
  const pathMod = require('path');
  const dir = pathMod.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = filePath + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

module.exports = { execCommand, execFileSafe, binaryExists, writeJSONAtomic };
