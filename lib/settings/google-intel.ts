import { z } from "zod";
import { getSecureSetting, setSecureSetting } from "@/lib/settings/secure-store";

const modeSchema = z.enum(["no_key", "custom_search_api"]);

export const googleIntelSettingsSchema = z.object({
  enabled: z.boolean().default(true),
  mode: modeSchema.default("no_key"),
  api_key: z.string().trim().min(20).max(5000).optional(),
  cse_cx: z.string().trim().min(5).max(500).optional(),
  country: z.string().trim().min(2).max(5).default("us"),
  language: z.string().trim().min(2).max(10).default("en"),
  max_results: z.number().int().min(1).max(20).default(10),
  allow_live_google_fetch: z.boolean().default(true),
});

export const googleIntelUpdateSchema = z.object({
  enabled: z.boolean().optional(),
  mode: modeSchema.optional(),
  api_key: z.string().trim().max(5000).nullable().optional(),
  cse_cx: z.string().trim().max(500).nullable().optional(),
  country: z.string().trim().min(2).max(5).optional(),
  language: z.string().trim().min(2).max(10).optional(),
  max_results: z.number().int().min(1).max(20).optional(),
  allow_live_google_fetch: z.boolean().optional(),
});

export type GoogleIntelSettings = z.infer<typeof googleIntelSettingsSchema>;
export type GoogleIntelUpdateInput = z.infer<typeof googleIntelUpdateSchema>;

function getDefaultSettings(): GoogleIntelSettings {
  const mode =
    process.env.GOOGLE_INTEL_MODE?.trim().toLowerCase() === "custom_search_api"
      ? "custom_search_api"
      : "no_key";

  return {
    enabled: process.env.GOOGLE_INTEL_ENABLED?.trim().toLowerCase() !== "false",
    mode,
    api_key: process.env.GOOGLE_API_KEY?.trim() || undefined,
    cse_cx: process.env.GOOGLE_CSE_CX?.trim() || undefined,
    country: process.env.GOOGLE_INTEL_COUNTRY?.trim().toLowerCase() || "us",
    language: process.env.GOOGLE_INTEL_LANGUAGE?.trim().toLowerCase() || "en",
    max_results: Math.min(
      20,
      Math.max(1, Number(process.env.GOOGLE_INTEL_MAX_RESULTS || "10") || 10)
    ),
    allow_live_google_fetch:
      process.env.GOOGLE_INTEL_ALLOW_LIVE_FETCH?.trim().toLowerCase() !== "false",
  };
}

function normalizeSettings(input: GoogleIntelSettings): GoogleIntelSettings {
  const country = input.country.trim().toLowerCase();
  const language = input.language.trim().toLowerCase();

  return {
    enabled: input.enabled,
    mode: input.mode,
    api_key: input.api_key?.trim() || undefined,
    cse_cx: input.cse_cx?.trim() || undefined,
    country: country || "us",
    language: language || "en",
    max_results: input.max_results,
    allow_live_google_fetch: input.allow_live_google_fetch,
  };
}

export async function getGoogleIntelSettings(): Promise<GoogleIntelSettings> {
  const raw = await getSecureSetting<unknown>("google_intel", getDefaultSettings());
  const parsed = googleIntelSettingsSchema.safeParse(raw);
  if (!parsed.success) return getDefaultSettings();
  return normalizeSettings(parsed.data);
}

export async function saveGoogleIntelSettings(
  updateInput: GoogleIntelUpdateInput,
  updatedBy: string | null = null
): Promise<GoogleIntelSettings> {
  const current = await getGoogleIntelSettings();
  const update = googleIntelUpdateSchema.parse(updateInput);

  const next: GoogleIntelSettings = {
    enabled: update.enabled ?? current.enabled,
    mode: update.mode ?? current.mode,
    api_key:
      update.api_key === null
        ? undefined
        : update.api_key?.trim() || current.api_key || undefined,
    cse_cx:
      update.cse_cx === null
        ? undefined
        : update.cse_cx?.trim() || current.cse_cx || undefined,
    country: update.country?.trim().toLowerCase() || current.country || "us",
    language: update.language?.trim().toLowerCase() || current.language || "en",
    max_results: update.max_results ?? current.max_results,
    allow_live_google_fetch:
      update.allow_live_google_fetch ?? current.allow_live_google_fetch,
  };

  const normalized = normalizeSettings(googleIntelSettingsSchema.parse(next));
  await setSecureSetting("google_intel", normalized, updatedBy);
  return normalized;
}

export function toGoogleIntelPublicSettings(settings: GoogleIntelSettings) {
  return {
    enabled: settings.enabled,
    mode: settings.mode,
    has_api_key: Boolean(settings.api_key),
    has_cse_cx: Boolean(settings.cse_cx),
    country: settings.country,
    language: settings.language,
    max_results: settings.max_results,
    allow_live_google_fetch: settings.allow_live_google_fetch,
  };
}
