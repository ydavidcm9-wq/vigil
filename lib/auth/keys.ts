const HEX_32_BYTE = /^[a-fA-F0-9]{64}$/;

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} environment variable is required`);
  }
  return value;
}

export function getTotpEncryptionKey(): Buffer {
  const key = requiredEnv("ENCRYPTION_KEY");
  if (!HEX_32_BYTE.test(key)) {
    throw new Error("ENCRYPTION_KEY must be a 32-byte hex string (64 chars)");
  }
  return Buffer.from(key, "hex");
}

export function getJwtSigningKey(): Uint8Array {
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    if (jwtSecret.length < 32) {
      throw new Error("JWT_SECRET must be at least 32 characters");
    }
    return new TextEncoder().encode(jwtSecret);
  }

  // Backward-compatible fallback: derive JWT key from the validated hex key.
  return new Uint8Array(getTotpEncryptionKey());
}
