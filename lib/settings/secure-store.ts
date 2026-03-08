import { decrypt, encrypt } from "@/lib/auth/totp";
import { getSetting, setSetting } from "@/lib/settings/store";

interface EncryptedEnvelope {
  encrypted: true;
  payload: string;
}

function isEncryptedEnvelope(input: unknown): input is EncryptedEnvelope {
  return Boolean(
    input &&
      typeof input === "object" &&
      (input as { encrypted?: unknown }).encrypted === true &&
      typeof (input as { payload?: unknown }).payload === "string"
  );
}

export async function getSecureSetting<T>(key: string, fallback: T): Promise<T> {
  const raw = await getSetting<unknown>(key, fallback);
  if (isEncryptedEnvelope(raw)) {
    try {
      const plaintext = decrypt(raw.payload);
      return JSON.parse(plaintext) as T;
    } catch {
      return fallback;
    }
  }
  return raw as T;
}

export async function setSecureSetting<T>(
  key: string,
  value: T,
  updatedBy: string | null = null
): Promise<void> {
  const plaintext = JSON.stringify(value);
  const envelope: EncryptedEnvelope = {
    encrypted: true,
    payload: encrypt(plaintext),
  };
  await setSetting(key, envelope, updatedBy);
}
