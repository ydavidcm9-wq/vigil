// Vigil — TOTP 2FA (RFC 6238)
// Simple HMAC-based implementation — no external dependencies
const crypto = require('crypto');

const TOTP_PERIOD = 30; // seconds
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // allow +/- 1 period for clock skew

/**
 * Generate a random TOTP secret (base32 encoded)
 * @returns {string} - Base32-encoded secret
 */
function generateSecret() {
  const buffer = crypto.randomBytes(20);
  return base32Encode(buffer);
}

/**
 * Generate otpauth:// URI for QR code scanning
 * @param {string} secret - Base32-encoded secret
 * @param {string} username - Account identifier
 * @param {string} [issuer] - Issuer name
 * @returns {string} - otpauth:// URI
 */
function generateQRData(secret, username, issuer = 'Vigil') {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedUser = encodeURIComponent(username);
  return `otpauth://totp/${encodedIssuer}:${encodedUser}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}

// Per-user 2FA rate limiting
const twoFAAttempts = new Map();
const MAX_2FA_ATTEMPTS = 5;
const TWO_FA_WINDOW = 5 * 60 * 1000; // 5 minutes

/**
 * Verify a TOTP token with rate limiting
 * @param {string} secret - Base32-encoded secret
 * @param {string} token - 6-digit token string
 * @param {string} [username] - Username for rate limiting
 * @returns {boolean|'rate_limited'}
 */
function verifyToken(secret, token, username) {
  if (!secret || !token) return false;

  // Rate limiting per user
  if (username) {
    const key = 'totp:' + username;
    const entry = twoFAAttempts.get(key);
    if (entry) {
      if (Date.now() - entry.firstAttempt > TWO_FA_WINDOW) {
        twoFAAttempts.delete(key);
      } else if (entry.count >= MAX_2FA_ATTEMPTS) {
        return 'rate_limited';
      }
    }
  }

  const normalizedToken = token.toString().replace(/\s/g, '');
  if (normalizedToken.length !== TOTP_DIGITS) return false;

  const now = Math.floor(Date.now() / 1000);

  // Check within window for clock skew tolerance, using constant-time comparison
  let valid = false;
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const timeStep = Math.floor(now / TOTP_PERIOD) + i;
    const generated = generateTOTP(secret, timeStep);
    // Constant-time comparison to prevent timing attacks
    if (generated.length === normalizedToken.length &&
        crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(normalizedToken))) {
      valid = true;
    }
  }

  // Record failed attempt
  if (!valid && username) {
    const key = 'totp:' + username;
    const entry = twoFAAttempts.get(key);
    if (!entry) twoFAAttempts.set(key, { count: 1, firstAttempt: Date.now() });
    else entry.count++;
  } else if (valid && username) {
    twoFAAttempts.delete('totp:' + username);
  }

  return valid;
}

/**
 * Generate a TOTP code for a given time step
 * @param {string} secret - Base32-encoded secret
 * @param {number} timeStep - Time counter value
 * @returns {string} - 6-digit code
 */
function generateTOTP(secret, timeStep) {
  // Decode base32 secret
  const key = base32Decode(secret);

  // Convert time step to 8-byte big-endian buffer
  const timeBuffer = Buffer.alloc(8);
  let t = timeStep;
  for (let i = 7; i >= 0; i--) {
    timeBuffer[i] = t & 0xff;
    t = Math.floor(t / 256);
  }

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuffer);
  const hash = hmac.digest();

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, TOTP_DIGITS);
  return otp.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * Get current TOTP code (for testing)
 * @param {string} secret - Base32-encoded secret
 * @returns {string}
 */
function getCurrentToken(secret) {
  const timeStep = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  return generateTOTP(secret, timeStep);
}

// Base32 encoding/decoding (RFC 4648)
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let result = '';
  let bits = 0;
  let value = 0;

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return result;
}

function base32Decode(str) {
  const cleaned = str.replace(/[=\s]/g, '').toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }

  return Buffer.from(bytes);
}

module.exports = {
  generateSecret,
  generateQRData,
  verifyToken,
  getCurrentToken
};
