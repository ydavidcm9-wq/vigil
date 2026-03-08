/**
 * Model Cache Manager — Smart model lifecycle with weighted eviction,
 * auto-pull on first use, multi-model security scanning, and usage tracking.
 *
 * Innovation: Not just LRU — uses weighted scoring (recency 40%, frequency 30%,
 * priority 30%) for eviction. Security-critical models are pinned. Supports
 * both Ollama registry and HuggingFace GGUF models via hf.co/ prefix.
 */

import { query, queryOne, execute } from "@/lib/db/pool";
import { getOllamaClient, getModel } from "./ollama-client";
import { getLLMSettings } from "@/lib/settings/llm";

// ─── Types ──────────────────────────────────────────────────────────────

export interface CachedModel {
  id: string;
  model_name: string;
  model_family: string | null;
  purpose: string;
  size_bytes: number;
  digest: string | null;
  parameter_size: string | null;
  quantization: string | null;
  source: "ollama" | "huggingface";
  source_ref: string | null;
  is_pulled: boolean;
  auto_pull: boolean;
  priority: number;
  last_used_at: string | null;
  use_count: number;
  total_tokens_generated: number;
  avg_tokens_per_sec: number | null;
  pulled_at: string | null;
  evicted_at: string | null;
  created_at: string;
}

export interface OllamaModelInfo {
  name: string;
  model: string;
  modified_at: string;
  size: number;
  digest: string;
  details: {
    format: string;
    family: string;
    families: string[];
    parameter_size: string;
    quantization_level: string;
  };
}

export interface PullProgress {
  status: string;
  digest?: string;
  total?: number;
  completed?: number;
}

export interface CacheStats {
  total_models: number;
  pulled_models: number;
  total_disk_bytes: number;
  max_disk_bytes: number;
  utilization_pct: number;
  total_inferences: number;
  models_by_purpose: Record<string, number>;
}

export interface ModelRecommendation {
  model_name: string;
  purpose: string;
  reason: string;
  is_pulled: boolean;
  size_bytes: number;
}

// ─── Purpose → Model Mapping (multi-model security scanning) ─────────

const PURPOSE_MODEL_MAP: Record<string, string[]> = {
  "code-security":   ["qwen2.5-coder:7b", "qwen2.5-coder:32b"],
  "threat-analysis": ["ALIENTELLIGENCE/cybersecuritythreatanalysisv2", "llama3.1:8b"],
  "code-review":     ["alpernae/qwen2.5-auditor", "qwen2.5-coder:7b"],
  "deep-analysis":   ["qwen2.5-coder:32b", "deepseek-coder-v2:16b"],
  "general":         ["llama3.1:8b"],
  "fallback":        ["codellama:7b", "llama3.1:8b"],
};

// ─── Cache Manager ──────────────────────────────────────────────────────

const DEFAULT_MAX_DISK_GB = 50;

export class ModelCacheManager {
  private maxDiskBytes: number;

  constructor(maxDiskGB: number = DEFAULT_MAX_DISK_GB) {
    this.maxDiskBytes = maxDiskGB * 1024 * 1024 * 1024;
  }

  // ── Core: ensure model is available before inference ───────────────

  async ensureModel(modelName: string): Promise<boolean> {
    const ollama = await getOllamaClient();

    // Check if already pulled in Ollama
    try {
      const list = await ollama.list();
      const found = list.models.find(
        (m) => m.name === modelName || m.model === modelName
      );
      if (found) {
        await this.recordModelPulled(modelName, found.size, found.digest, found.details);
        return true;
      }
    } catch {
      return false; // Ollama not running
    }

    // Check if auto-pull is enabled for this model
    const entry = await queryOne<{ auto_pull: boolean }>(
      `SELECT auto_pull FROM model_cache WHERE model_name = $1`,
      [modelName]
    );
    if (entry && !entry.auto_pull) {
      return false; // Not allowed to auto-pull
    }

    // Check disk budget before pulling
    const estimatedSize = await this.estimateModelSize(modelName);
    const freed = await this.ensureDiskSpace(estimatedSize);
    if (freed === false) {
      return false; // Can't free enough space
    }

    // Pull the model
    try {
      await ollama.pull({ model: modelName });
      // Re-check after pull
      const list = await ollama.list();
      const pulled = list.models.find(
        (m) => m.name === modelName || m.model === modelName
      );
      if (pulled) {
        await this.recordModelPulled(modelName, pulled.size, pulled.digest, pulled.details);
      }
      return true;
    } catch (err) {
      console.error(`[model-cache] Failed to pull ${modelName}:`, err);
      return false;
    }
  }

  // ── Get best model for a security purpose ─────────────────────────

  async getModelForPurpose(purpose: string): Promise<string> {
    const candidates = PURPOSE_MODEL_MAP[purpose] || PURPOSE_MODEL_MAP["general"];

    for (const modelName of candidates) {
      const entry = await queryOne<{ is_pulled: boolean }>(
        `SELECT is_pulled FROM model_cache WHERE model_name = $1`,
        [modelName]
      );
      if (entry?.is_pulled) {
        return modelName;
      }
    }

    // Try to pull the first candidate
    const primary = candidates[0];
    const pulled = await this.ensureModel(primary);
    if (pulled) return primary;

    // Fall back to whatever is currently pulled
    const fallback = await queryOne<{ model_name: string }>(
      `SELECT model_name FROM model_cache WHERE is_pulled = true ORDER BY priority ASC LIMIT 1`,
      []
    );
    if (fallback?.model_name) return fallback.model_name;
    try {
      const llm = await getLLMSettings();
      if (llm.default_model) return llm.default_model;
    } catch {
      // ignore
    }
    return getModel();
  }

  // ── Recommend models for a scan type ──────────────────────────────

  async recommendModels(scanType: string): Promise<ModelRecommendation[]> {
    const purposeMap: Record<string, string[]> = {
      zap:     ["code-security", "threat-analysis"],
      nuclei:  ["code-security", "threat-analysis"],
      nmap:    ["threat-analysis"],
      trivy:   ["code-security"],
      nikto:   ["code-security"],
      sqlmap:  ["code-security"],
      osint:   ["threat-analysis"],
      pentest: ["deep-analysis", "threat-analysis"],
    };

    const purposes = purposeMap[scanType] || ["general"];
    const recommendations: ModelRecommendation[] = [];

    for (const purpose of purposes) {
      const models = await query<CachedModel>(
        `SELECT * FROM model_cache WHERE purpose = $1 ORDER BY priority ASC`,
        [purpose]
      );
      for (const m of models) {
        recommendations.push({
          model_name: m.model_name,
          purpose: m.purpose,
          reason: this.getRecommendationReason(m),
          is_pulled: m.is_pulled,
          size_bytes: m.size_bytes,
        });
      }
    }

    return recommendations;
  }

  // ── Sync Ollama state → DB ────────────────────────────────────────

  async syncFromOllama(): Promise<{ synced: number; new: number; evicted: number }> {
    let synced = 0, newModels = 0, evicted = 0;

    try {
      const ollama = await getOllamaClient();
      const list = await ollama.list();
      const ollamaNames = new Set(list.models.map((m) => m.name));

      // Update pulled models
      for (const m of list.models) {
        const existing = await queryOne<{ id: string }>(
          `SELECT id FROM model_cache WHERE model_name = $1`,
          [m.name]
        );
        if (existing) {
          await execute(
            `UPDATE model_cache SET
              is_pulled = true, size_bytes = $1, digest = $2,
              parameter_size = $3, quantization = $4,
              model_family = COALESCE(model_family, $5),
              pulled_at = COALESCE(pulled_at, NOW()),
              evicted_at = NULL, updated_at = NOW()
            WHERE model_name = $6`,
            [
              m.size, m.digest,
              m.details.parameter_size, m.details.quantization_level,
              m.details.family, m.name,
            ]
          );
          synced++;
        } else {
          // New model found in Ollama but not in registry
          await execute(
            `INSERT INTO model_cache (model_name, model_family, purpose, size_bytes, digest, parameter_size, quantization, is_pulled, pulled_at)
             VALUES ($1, $2, 'general', $3, $4, $5, $6, true, NOW())`,
            [m.name, m.details.family, m.size, m.digest, m.details.parameter_size, m.details.quantization_level]
          );
          newModels++;
        }
      }

      // Mark models in DB but not in Ollama as evicted
      const dbModels = await query<{ model_name: string }>(
        `SELECT model_name FROM model_cache WHERE is_pulled = true`,
        []
      );
      for (const dbm of dbModels) {
        if (!ollamaNames.has(dbm.model_name)) {
          await execute(
            `UPDATE model_cache SET is_pulled = false, evicted_at = NOW(), updated_at = NOW() WHERE model_name = $1`,
            [dbm.model_name]
          );
          evicted++;
        }
      }
    } catch {
      // Ollama not available
    }

    return { synced, new: newModels, evicted };
  }

  // ── Record model usage after inference ────────────────────────────

  async recordUsage(
    modelName: string,
    userId: string | null,
    scanId: string | null,
    purpose: string,
    inputTokens: number,
    outputTokens: number,
    durationMs: number
  ): Promise<void> {
    const tokensPerSec = durationMs > 0 ? (outputTokens / (durationMs / 1000)) : 0;

    await execute(
      `INSERT INTO model_usage_log (model_name, user_id, scan_id, purpose, input_tokens, output_tokens, duration_ms, tokens_per_sec)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [modelName, userId, scanId, purpose, inputTokens, outputTokens, durationMs, tokensPerSec]
    );

    await execute(
      `UPDATE model_cache SET
        use_count = use_count + 1,
        last_used_at = NOW(),
        total_tokens_generated = total_tokens_generated + $1,
        avg_tokens_per_sec = (
          SELECT AVG(tokens_per_sec) FROM model_usage_log WHERE model_name = $2 AND tokens_per_sec > 0
        ),
        updated_at = NOW()
      WHERE model_name = $2`,
      [outputTokens, modelName]
    );
  }

  // ── Pull a model with streaming progress ──────────────────────────

  async pullModelStream(
    modelName: string,
    onProgress: (p: PullProgress) => void
  ): Promise<boolean> {
    const estimatedSize = await this.estimateModelSize(modelName);
    await this.ensureDiskSpace(estimatedSize);

    let baseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    try {
      baseUrl = (await getLLMSettings()).base_url;
    } catch {
      // fallback to env
    }
    try {
      const res = await fetch(`${baseUrl}/api/pull`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: modelName, stream: true }),
      });

      if (!res.ok || !res.body) return false;

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.trim()) {
            try {
              onProgress(JSON.parse(line));
            } catch { /* skip malformed */ }
          }
        }
      }

      await this.syncFromOllama();
      return true;
    } catch (err) {
      console.error(`[model-cache] Stream pull failed for ${modelName}:`, err);
      return false;
    }
  }

  // ── Delete a model ────────────────────────────────────────────────

  async deleteModel(modelName: string): Promise<boolean> {
    try {
      const ollama = await getOllamaClient();
      await ollama.delete({ model: modelName });
      await execute(
        `UPDATE model_cache SET is_pulled = false, evicted_at = NOW(), updated_at = NOW() WHERE model_name = $1`,
        [modelName]
      );
      return true;
    } catch {
      return false;
    }
  }

  // ── Get cache statistics ──────────────────────────────────────────

  async getStats(): Promise<CacheStats> {
    const totals = await queryOne<{
      total_models: string;
      pulled_models: string;
      total_disk: string;
      total_inferences: string;
    }>(
      `SELECT
        COUNT(*) as total_models,
        COUNT(*) FILTER (WHERE is_pulled) as pulled_models,
        COALESCE(SUM(size_bytes) FILTER (WHERE is_pulled), 0) as total_disk,
        COALESCE(SUM(use_count), 0) as total_inferences
      FROM model_cache`,
      []
    );

    const byPurpose = await query<{ purpose: string; count: string }>(
      `SELECT purpose, COUNT(*) as count FROM model_cache GROUP BY purpose`,
      []
    );

    const totalDisk = Number(totals?.total_disk || 0);

    return {
      total_models: Number(totals?.total_models || 0),
      pulled_models: Number(totals?.pulled_models || 0),
      total_disk_bytes: totalDisk,
      max_disk_bytes: this.maxDiskBytes,
      utilization_pct: this.maxDiskBytes > 0 ? Math.round((totalDisk / this.maxDiskBytes) * 100) : 0,
      total_inferences: Number(totals?.total_inferences || 0),
      models_by_purpose: Object.fromEntries(byPurpose.map((r) => [r.purpose, Number(r.count)])),
    };
  }

  // ── List all models with their status ─────────────────────────────

  async listModels(): Promise<CachedModel[]> {
    return query<CachedModel>(
      `SELECT * FROM model_cache ORDER BY priority ASC, model_name ASC`,
      []
    );
  }

  // ── Add a new model to the registry ───────────────────────────────

  async addModel(model: {
    model_name: string;
    purpose: string;
    source?: "ollama" | "huggingface";
    source_ref?: string;
    auto_pull?: boolean;
    priority?: number;
  }): Promise<string> {
    const result = await queryOne<{ id: string }>(
      `INSERT INTO model_cache (model_name, purpose, source, source_ref, auto_pull, priority)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (model_name) DO UPDATE SET
         purpose = EXCLUDED.purpose,
         source = EXCLUDED.source,
         source_ref = EXCLUDED.source_ref,
         auto_pull = EXCLUDED.auto_pull,
         priority = EXCLUDED.priority,
         updated_at = NOW()
       RETURNING id`,
      [
        model.model_name,
        model.purpose,
        model.source || "ollama",
        model.source_ref || null,
        model.auto_pull ?? true,
        model.priority ?? 5,
      ]
    );
    return result!.id;
  }

  // ── Private: weighted eviction ────────────────────────────────────

  private async ensureDiskSpace(neededBytes: number): Promise<boolean | number> {
    const totalUsed = await this.getTotalDiskUsage();
    if (totalUsed + neededBytes <= this.maxDiskBytes) return 0;

    // Get eviction candidates scored by weighted formula
    const candidates = await query<CachedModel & { eviction_score: number }>(
      `SELECT *,
        (
          EXTRACT(EPOCH FROM (NOW() - COALESCE(last_used_at, created_at))) / 3600 * 0.4 +
          CASE WHEN use_count > 0 THEN (1.0 / use_count) * 100 ELSE 100 END * 0.3 +
          priority * 10 * 0.3
        ) as eviction_score
      FROM model_cache
      WHERE is_pulled = true AND priority > 2
      ORDER BY eviction_score DESC`,
      []
    );

    // Also check what's currently loaded in Ollama (don't evict running models)
    let runningNames: Set<string>;
    try {
      const ollama = await getOllamaClient();
      let baseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
      try {
        baseUrl = (await getLLMSettings()).base_url;
      } catch {
        // fallback to env
      }
      const psRes = await fetch(`${baseUrl}/api/ps`);
      const psData = await psRes.json() as { models: Array<{ name: string }> };
      runningNames = new Set((psData.models || []).map((m) => m.name));
    } catch {
      runningNames = new Set();
    }

    let freed = 0;
    for (const candidate of candidates) {
      if (totalUsed + neededBytes - freed <= this.maxDiskBytes) break;
      if (runningNames.has(candidate.model_name)) continue;

      const deleted = await this.deleteModel(candidate.model_name);
      if (deleted) {
        freed += candidate.size_bytes;
      }
    }

    return totalUsed + neededBytes - freed <= this.maxDiskBytes ? freed : false;
  }

  private async getTotalDiskUsage(): Promise<number> {
    const result = await queryOne<{ total: string }>(
      `SELECT COALESCE(SUM(size_bytes), 0) as total FROM model_cache WHERE is_pulled = true`,
      []
    );
    return Number(result?.total || 0);
  }

  private async estimateModelSize(modelName: string): Promise<number> {
    // Check DB first
    const cached = await queryOne<{ size_bytes: number }>(
      `SELECT size_bytes FROM model_cache WHERE model_name = $1 AND size_bytes > 0`,
      [modelName]
    );
    if (cached) return cached.size_bytes;

    // Rough estimate based on parameter count in name
    if (modelName.includes("32b")) return 19_000_000_000;
    if (modelName.includes("16b")) return 9_000_000_000;
    if (modelName.includes("14b")) return 8_500_000_000;
    if (modelName.includes("13b")) return 7_500_000_000;
    if (modelName.includes("8b") || modelName.includes("7b")) return 4_700_000_000;
    if (modelName.includes("3b")) return 2_000_000_000;
    if (modelName.includes("1b")) return 800_000_000;
    return 5_000_000_000; // default 5GB estimate
  }

  private async recordModelPulled(
    modelName: string,
    size: number,
    digest: string,
    details: { family: string; parameter_size: string; quantization_level: string }
  ): Promise<void> {
    const existing = await queryOne<{ id: string }>(
      `SELECT id FROM model_cache WHERE model_name = $1`,
      [modelName]
    );
    if (existing) {
      await execute(
        `UPDATE model_cache SET
          is_pulled = true, size_bytes = $1, digest = $2,
          parameter_size = $3, quantization = $4,
          model_family = COALESCE(model_family, $5),
          pulled_at = COALESCE(pulled_at, NOW()),
          evicted_at = NULL, updated_at = NOW()
        WHERE model_name = $6`,
        [size, digest, details.parameter_size, details.quantization_level, details.family, modelName]
      );
    } else {
      await execute(
        `INSERT INTO model_cache (model_name, model_family, purpose, size_bytes, digest, parameter_size, quantization, is_pulled, pulled_at)
         VALUES ($1, $2, 'general', $3, $4, $5, $6, true, NOW())`,
        [modelName, details.family, size, digest, details.parameter_size, details.quantization_level]
      );
    }
  }

  private getRecommendationReason(model: CachedModel): string {
    const reasons: Record<string, string> = {
      "code-security": "Best for finding vulnerabilities in source code",
      "threat-analysis": "Specialized in cybersecurity threat modeling",
      "code-review": "Focused on security code review and bug bounty patterns",
      "deep-analysis": "Large model for complex multi-file security analysis",
      "general": "General-purpose AI assistant",
      "multi-file": "Strong at analyzing cross-file dependencies",
      "fallback": "Reliable fallback when primary models unavailable",
    };
    return reasons[model.purpose] || `${model.purpose} model`;
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────

let _instance: ModelCacheManager | null = null;

export function getModelCache(): ModelCacheManager {
  if (!_instance) {
    const maxGB = Number(process.env.MODEL_CACHE_MAX_GB || DEFAULT_MAX_DISK_GB);
    _instance = new ModelCacheManager(maxGB);
  }
  return _instance;
}

