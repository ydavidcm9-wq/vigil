// Vigil — BYOK AI provider wrapper
// Supported: claude-cli, claude-code, codex, none
const { execCommand, execFileSafe } = require('./exec');

const SECURITY_SYSTEM_PROMPT = 'You are Vigil, an AI security analyst. You analyze threats, vulnerabilities, and security configurations with precision. Be concise, actionable, and cite specific CVEs, MITRE ATT&CK techniques, or CWE IDs when relevant.';

const DEFAULT_TIMEOUT = 30000;

// Clean env for spawning AI CLIs — strip CLAUDECODE so claude doesn't refuse to start
function getCleanEnv() {
  const env = { ...process.env };
  delete env.CLAUDECODE;
  return env;
}

// Settings file for AI provider preference
const fs = require('fs');
const path = require('path');
const SETTINGS_FILE = path.join(__dirname, '..', 'data', 'settings.json');

/**
 * Get configured AI provider
 * @returns {string} - 'claude-cli', 'claude-code', 'codex', or 'none'
 */
function getProvider() {
  // Check env first
  if (process.env.AI_PROVIDER) return process.env.AI_PROVIDER;

  // Check settings file
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      if (settings.aiProvider) return settings.aiProvider;
    }
  } catch {}

  return 'none';
}

/**
 * Get the CLI command for the current provider
 * @returns {string|null}
 */
function getAICommand() {
  const provider = getProvider();
  switch (provider) {
    case 'claude-cli': return 'claude';
    case 'claude-code': return 'claude';
    case 'codex': return 'codex';
    default: return null;
  }
}

/**
 * Build the full CLI command for a prompt
 * @param {string} prompt
 * @param {object} options
 * @returns {string|null}
 */
function buildCommand(prompt, options = {}) {
  const provider = getProvider();
  // Escape the prompt for shell safety
  const escaped = prompt.replace(/'/g, "'\\''");

  switch (provider) {
    case 'claude-cli':
    case 'claude-code':
      return `claude --print -p '${escaped}'`;
    case 'codex':
      return `codex -q '${escaped}'`;
    default:
      return null;
  }
}

/**
 * Send a prompt to the configured AI provider
 * @param {string} prompt - The prompt to send
 * @param {object} options
 * @param {number} options.timeout - Timeout in ms
 * @param {boolean} options.includeSystemPrompt - Prepend security system prompt (default: true)
 * @returns {Promise<string|null>} - AI response or null
 */
async function askAI(prompt, options = {}) {
  const provider = getProvider();
  if (provider === 'none') return null;

  const { spawn } = require('child_process');
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const includeSystem = options.includeSystemPrompt !== false;

  const fullPrompt = includeSystem
    ? SECURITY_SYSTEM_PROMPT + '\n\n' + prompt
    : prompt;

  let bin, args;
  switch (provider) {
    case 'claude-cli':
    case 'claude-code':
      bin = 'claude'; args = ['--print', '-p', fullPrompt]; break;
    case 'codex':
      bin = 'codex'; args = ['-q', fullPrompt]; break;
    default:
      return null;
  }

  try {
    const result = await execCommand(
      bin + ' ' + args.map(a => JSON.stringify(a)).join(' '),
      { timeout, env: getCleanEnv(), allowUnsafe: true }
    );

    if (result.code !== 0) {
      console.warn('  AI: command failed (code ' + result.code + '):', result.stderr.substring(0, 200));
      return null;
    }

    return result.stdout.trim() || null;
  } catch (err) {
    console.error('  AI: error —', err.message);
    return null;
  }
}

/**
 * Send a prompt and parse JSON from the response
 * Falls back to regex extraction for ```json blocks
 * @param {string} prompt
 * @param {object} options
 * @returns {Promise<object|null>}
 */
async function askAIJSON(prompt, options = {}) {
  const jsonPrompt = prompt + '\n\nRespond with valid JSON only. No markdown, no explanation.';
  const response = await askAI(jsonPrompt, options);

  if (!response) return null;

  // Try direct JSON parse
  try {
    return JSON.parse(response);
  } catch {}

  // Try extracting from ```json blocks
  const jsonBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (jsonBlockMatch) {
    try {
      return JSON.parse(jsonBlockMatch[1].trim());
    } catch {}
  }

  // Try finding JSON object/array in response
  const objMatch = response.match(/\{[\s\S]*\}/);
  if (objMatch) {
    try {
      return JSON.parse(objMatch[0]);
    } catch {}
  }

  const arrMatch = response.match(/\[[\s\S]*\]/);
  if (arrMatch) {
    try {
      return JSON.parse(arrMatch[0]);
    } catch {}
  }

  console.warn('  AI: could not parse JSON from response');
  return null;
}

/**
 * Stream AI output via callback (for terminal/socket)
 * @param {string} prompt
 * @param {Function} onData - Callback for each chunk of output
 * @param {object} options
 * @returns {Promise<{success: boolean, output: string}>}
 */
async function streamAI(prompt, onData, options = {}) {
  const provider = getProvider();
  if (provider === 'none') {
    if (onData) onData('AI provider not configured\n');
    return { success: false, output: '' };
  }

  const { spawn } = require('child_process');
  const timeout = options.timeout || 60000;
  const includeSystem = options.includeSystemPrompt !== false;
  const fullPrompt = includeSystem
    ? SECURITY_SYSTEM_PROMPT + '\n\n' + prompt
    : prompt;

  return new Promise((resolve) => {
    let args;
    let bin;

    switch (provider) {
      case 'claude-cli':
      case 'claude-code':
        bin = 'claude';
        args = ['--print', '-p', fullPrompt];
        break;
      case 'codex':
        bin = 'codex';
        args = ['-q', fullPrompt];
        break;
      default:
        resolve({ success: false, output: '' });
        return;
    }

    let output = '';
    const proc = spawn(bin, args, {
      timeout,
      env: getCleanEnv(),
      windowsHide: true
    });

    proc.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      if (onData) onData(chunk);
    });

    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      if (onData) onData(chunk);
    });

    proc.on('close', (code) => {
      resolve({ success: code === 0, output });
    });

    proc.on('error', (err) => {
      if (onData) onData('Error: ' + err.message + '\n');
      resolve({ success: false, output });
    });

    // Timeout kill
    setTimeout(() => {
      try { proc.kill(); } catch {}
    }, timeout);
  });
}

module.exports = {
  askAI,
  askAIJSON,
  getAICommand,
  getProvider,
  streamAI,
  SECURITY_SYSTEM_PROMPT
};
