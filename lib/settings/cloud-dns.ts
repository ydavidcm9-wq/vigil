import { z } from "zod";
import { getSecureSetting, setSecureSetting } from "@/lib/settings/secure-store";

const baseZoneAllowlistSchema = z.array(z.string().trim().min(1).max(253)).max(200);

const cloudflareSchema = z.object({
  enabled: z.boolean().default(false),
  api_token: z.string().trim().min(10).max(5000).optional(),
  zone_allowlist: baseZoneAllowlistSchema.default([]),
});

const gcpSchema = z.object({
  enabled: z.boolean().default(false),
  service_account_json: z.string().trim().min(10).max(200000).optional(),
  project_id: z.string().trim().min(1).max(200).optional(),
  zone_allowlist: baseZoneAllowlistSchema.default([]),
});

const awsSchema = z.object({
  enabled: z.boolean().default(false),
  access_key_id: z.string().trim().min(10).max(200).optional(),
  secret_access_key: z.string().trim().min(10).max(500).optional(),
  session_token: z.string().trim().max(5000).optional(),
  region: z.string().trim().min(2).max(60).default("us-east-1"),
  zone_allowlist: baseZoneAllowlistSchema.default([]),
});

const azureSchema = z.object({
  enabled: z.boolean().default(false),
  tenant_id: z.string().trim().min(10).max(200).optional(),
  client_id: z.string().trim().min(10).max(200).optional(),
  client_secret: z.string().trim().min(10).max(5000).optional(),
  subscription_id: z.string().trim().min(10).max(200).optional(),
  zone_allowlist: baseZoneAllowlistSchema.default([]),
});

const safetySchema = z.object({
  never_send_cloud_credentials_to_llm: z.boolean().default(true),
  redact_provider_identifiers: z.boolean().default(true),
});

export const cloudDnsSettingsSchema = z.object({
  cloudflare: cloudflareSchema.default({ enabled: false, zone_allowlist: [] }),
  gcp: gcpSchema.default({ enabled: false, zone_allowlist: [] }),
  aws: awsSchema.default({ enabled: false, region: "us-east-1", zone_allowlist: [] }),
  azure: azureSchema.default({ enabled: false, zone_allowlist: [] }),
  safety: safetySchema.default({
    never_send_cloud_credentials_to_llm: true,
    redact_provider_identifiers: true,
  }),
});

export const cloudDnsUpdateSchema = z.object({
  cloudflare: z
    .object({
      enabled: z.boolean().optional(),
      api_token: z.string().trim().max(5000).nullable().optional(),
      zone_allowlist: baseZoneAllowlistSchema.optional(),
    })
    .optional(),
  gcp: z
    .object({
      enabled: z.boolean().optional(),
      service_account_json: z.string().trim().max(200000).nullable().optional(),
      project_id: z.string().trim().max(200).nullable().optional(),
      zone_allowlist: baseZoneAllowlistSchema.optional(),
    })
    .optional(),
  aws: z
    .object({
      enabled: z.boolean().optional(),
      access_key_id: z.string().trim().max(200).nullable().optional(),
      secret_access_key: z.string().trim().max(500).nullable().optional(),
      session_token: z.string().trim().max(5000).nullable().optional(),
      region: z.string().trim().max(60).nullable().optional(),
      zone_allowlist: baseZoneAllowlistSchema.optional(),
    })
    .optional(),
  azure: z
    .object({
      enabled: z.boolean().optional(),
      tenant_id: z.string().trim().max(200).nullable().optional(),
      client_id: z.string().trim().max(200).nullable().optional(),
      client_secret: z.string().trim().max(5000).nullable().optional(),
      subscription_id: z.string().trim().max(200).nullable().optional(),
      zone_allowlist: baseZoneAllowlistSchema.optional(),
    })
    .optional(),
  safety: z
    .object({
      never_send_cloud_credentials_to_llm: z.boolean().optional(),
      redact_provider_identifiers: z.boolean().optional(),
    })
    .optional(),
});

export type CloudDnsSettings = z.infer<typeof cloudDnsSettingsSchema>;
export type CloudDnsUpdateInput = z.infer<typeof cloudDnsUpdateSchema>;

const DEFAULT_SETTINGS: CloudDnsSettings = {
  cloudflare: { enabled: false, zone_allowlist: [] },
  gcp: { enabled: false, zone_allowlist: [] },
  aws: { enabled: false, region: "us-east-1", zone_allowlist: [] },
  azure: { enabled: false, zone_allowlist: [] },
  safety: {
    never_send_cloud_credentials_to_llm: true,
    redact_provider_identifiers: true,
  },
};

function normalizeSettings(input: CloudDnsSettings): CloudDnsSettings {
  return {
    cloudflare: {
      enabled: input.cloudflare.enabled,
      api_token: input.cloudflare.api_token?.trim() || undefined,
      zone_allowlist: input.cloudflare.zone_allowlist || [],
    },
    gcp: {
      enabled: input.gcp.enabled,
      service_account_json: input.gcp.service_account_json?.trim() || undefined,
      project_id: input.gcp.project_id?.trim() || undefined,
      zone_allowlist: input.gcp.zone_allowlist || [],
    },
    aws: {
      enabled: input.aws.enabled,
      access_key_id: input.aws.access_key_id?.trim() || undefined,
      secret_access_key: input.aws.secret_access_key?.trim() || undefined,
      session_token: input.aws.session_token?.trim() || undefined,
      region: input.aws.region?.trim() || "us-east-1",
      zone_allowlist: input.aws.zone_allowlist || [],
    },
    azure: {
      enabled: input.azure.enabled,
      tenant_id: input.azure.tenant_id?.trim() || undefined,
      client_id: input.azure.client_id?.trim() || undefined,
      client_secret: input.azure.client_secret?.trim() || undefined,
      subscription_id: input.azure.subscription_id?.trim() || undefined,
      zone_allowlist: input.azure.zone_allowlist || [],
    },
    safety: {
      never_send_cloud_credentials_to_llm:
        input.safety.never_send_cloud_credentials_to_llm,
      redact_provider_identifiers: input.safety.redact_provider_identifiers,
    },
  };
}

export async function getCloudDnsSettings(): Promise<CloudDnsSettings> {
  const raw = await getSecureSetting<unknown>("cloud_dns_connectors", DEFAULT_SETTINGS);
  const parsed = cloudDnsSettingsSchema.safeParse(raw);
  if (!parsed.success) return DEFAULT_SETTINGS;
  return normalizeSettings(parsed.data);
}

export async function saveCloudDnsSettings(
  updateInput: CloudDnsUpdateInput,
  updatedBy: string | null = null
): Promise<CloudDnsSettings> {
  const current = await getCloudDnsSettings();
  const update = cloudDnsUpdateSchema.parse(updateInput);

  const next: CloudDnsSettings = {
    cloudflare: {
      enabled: update.cloudflare?.enabled ?? current.cloudflare.enabled,
      api_token:
        update.cloudflare?.api_token === null
          ? undefined
          : update.cloudflare?.api_token?.trim() ||
            current.cloudflare.api_token ||
            undefined,
      zone_allowlist:
        update.cloudflare?.zone_allowlist ?? current.cloudflare.zone_allowlist,
    },
    gcp: {
      enabled: update.gcp?.enabled ?? current.gcp.enabled,
      service_account_json:
        update.gcp?.service_account_json === null
          ? undefined
          : update.gcp?.service_account_json?.trim() ||
            current.gcp.service_account_json ||
            undefined,
      project_id:
        update.gcp?.project_id === null
          ? undefined
          : update.gcp?.project_id?.trim() || current.gcp.project_id || undefined,
      zone_allowlist: update.gcp?.zone_allowlist ?? current.gcp.zone_allowlist,
    },
    aws: {
      enabled: update.aws?.enabled ?? current.aws.enabled,
      access_key_id:
        update.aws?.access_key_id === null
          ? undefined
          : update.aws?.access_key_id?.trim() || current.aws.access_key_id || undefined,
      secret_access_key:
        update.aws?.secret_access_key === null
          ? undefined
          : update.aws?.secret_access_key?.trim() ||
            current.aws.secret_access_key ||
            undefined,
      session_token:
        update.aws?.session_token === null
          ? undefined
          : update.aws?.session_token?.trim() || current.aws.session_token || undefined,
      region:
        update.aws?.region === null
          ? "us-east-1"
          : update.aws?.region?.trim() || current.aws.region || "us-east-1",
      zone_allowlist: update.aws?.zone_allowlist ?? current.aws.zone_allowlist,
    },
    azure: {
      enabled: update.azure?.enabled ?? current.azure.enabled,
      tenant_id:
        update.azure?.tenant_id === null
          ? undefined
          : update.azure?.tenant_id?.trim() || current.azure.tenant_id || undefined,
      client_id:
        update.azure?.client_id === null
          ? undefined
          : update.azure?.client_id?.trim() || current.azure.client_id || undefined,
      client_secret:
        update.azure?.client_secret === null
          ? undefined
          : update.azure?.client_secret?.trim() || current.azure.client_secret || undefined,
      subscription_id:
        update.azure?.subscription_id === null
          ? undefined
          : update.azure?.subscription_id?.trim() ||
            current.azure.subscription_id ||
            undefined,
      zone_allowlist: update.azure?.zone_allowlist ?? current.azure.zone_allowlist,
    },
    safety: {
      never_send_cloud_credentials_to_llm:
        update.safety?.never_send_cloud_credentials_to_llm ??
        current.safety.never_send_cloud_credentials_to_llm,
      redact_provider_identifiers:
        update.safety?.redact_provider_identifiers ??
        current.safety.redact_provider_identifiers,
    },
  };

  const normalized = normalizeSettings(cloudDnsSettingsSchema.parse(next));
  await setSecureSetting("cloud_dns_connectors", normalized, updatedBy);
  return normalized;
}

export function toCloudDnsPublicSettings(settings: CloudDnsSettings) {
  return {
    cloudflare: {
      enabled: settings.cloudflare.enabled,
      has_api_token: Boolean(settings.cloudflare.api_token),
      zone_allowlist: settings.cloudflare.zone_allowlist,
    },
    gcp: {
      enabled: settings.gcp.enabled,
      has_service_account_json: Boolean(settings.gcp.service_account_json),
      project_id: settings.gcp.project_id || null,
      zone_allowlist: settings.gcp.zone_allowlist,
    },
    aws: {
      enabled: settings.aws.enabled,
      has_access_key_id: Boolean(settings.aws.access_key_id),
      has_secret_access_key: Boolean(settings.aws.secret_access_key),
      has_session_token: Boolean(settings.aws.session_token),
      region: settings.aws.region || "us-east-1",
      zone_allowlist: settings.aws.zone_allowlist,
    },
    azure: {
      enabled: settings.azure.enabled,
      has_tenant_id: Boolean(settings.azure.tenant_id),
      has_client_id: Boolean(settings.azure.client_id),
      has_client_secret: Boolean(settings.azure.client_secret),
      has_subscription_id: Boolean(settings.azure.subscription_id),
      zone_allowlist: settings.azure.zone_allowlist,
    },
    safety: settings.safety,
  };
}
