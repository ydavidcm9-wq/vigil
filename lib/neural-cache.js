// Vigil — Intelligent caching layer with semantic matching
const crypto = require('crypto');

class NeuralCache {
  constructor() {
    this.cache = new Map();
    this.semanticCache = new Map();
    this.stats = { hits: 0, misses: 0, semanticHits: 0 };
  }

  /**
   * Get a value from cache
   * @param {string} key
   * @returns {*} - Cached value or undefined
   */
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) {
      this.stats.misses++;
      return undefined;
    }

    // Check TTL
    if (entry.expires && Date.now() > entry.expires) {
      this.cache.delete(key);
      this.stats.misses++;
      return undefined;
    }

    this.stats.hits++;
    entry.accessCount = (entry.accessCount || 0) + 1;
    entry.lastAccess = Date.now();
    return entry.value;
  }

  /**
   * Set a value in cache with optional TTL
   * @param {string} key
   * @param {*} value
   * @param {number} [ttlMs] - Time to live in milliseconds
   */
  set(key, value, ttlMs = 0) {
    this.cache.set(key, {
      value,
      created: Date.now(),
      expires: ttlMs > 0 ? Date.now() + ttlMs : 0,
      accessCount: 0,
      lastAccess: Date.now()
    });
  }

  /**
   * Check if a key exists and is not expired
   * @param {string} key
   * @returns {boolean}
   */
  has(key) {
    const entry = this.cache.get(key);
    if (!entry) return false;
    if (entry.expires && Date.now() > entry.expires) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Invalidate a specific key
   * @param {string} key
   * @returns {boolean}
   */
  invalidate(key) {
    return this.cache.delete(key);
  }

  /**
   * Invalidate all keys matching a prefix
   * @param {string} prefix
   * @returns {number} - Number of keys invalidated
   */
  invalidatePrefix(prefix) {
    let count = 0;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }

  /**
   * Semantic get — fuzzy match for AI responses
   * Normalizes the prompt to create a content-addressed key
   * @param {string} prompt
   * @returns {*} - Cached response or undefined
   */
  semanticGet(prompt) {
    const key = this._normalizePrompt(prompt);
    const entry = this.semanticCache.get(key);

    if (!entry) {
      this.stats.misses++;
      return undefined;
    }

    if (entry.expires && Date.now() > entry.expires) {
      this.semanticCache.delete(key);
      this.stats.misses++;
      return undefined;
    }

    this.stats.semanticHits++;
    this.stats.hits++;
    return entry.value;
  }

  /**
   * Semantic set — store AI response with normalized key
   * @param {string} prompt
   * @param {*} response
   * @param {number} [ttlMs] - Default: 5 minutes
   */
  semanticSet(prompt, response, ttlMs = 300000) {
    const key = this._normalizePrompt(prompt);
    this.semanticCache.set(key, {
      value: response,
      prompt: prompt.substring(0, 200),
      created: Date.now(),
      expires: ttlMs > 0 ? Date.now() + ttlMs : 0
    });
  }

  /**
   * Normalize a prompt for content-addressed caching
   * Removes whitespace variations, lowercases, and hashes
   * @param {string} prompt
   * @returns {string}
   */
  _normalizePrompt(prompt) {
    const normalized = prompt
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
    return crypto.createHash('sha256').update(normalized).digest('hex').substring(0, 16);
  }

  /**
   * Get cache statistics
   * @returns {object}
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      size: this.cache.size,
      semanticSize: this.semanticCache.size,
      hitRate: total > 0 ? Math.round((this.stats.hits / total) * 100) : 0
    };
  }

  /**
   * Clear all caches
   */
  clear() {
    this.cache.clear();
    this.semanticCache.clear();
    this.stats = { hits: 0, misses: 0, semanticHits: 0 };
  }

  /**
   * Evict expired entries
   * @returns {number} - Number of entries evicted
   */
  evict() {
    const now = Date.now();
    let evicted = 0;

    for (const [key, entry] of this.cache) {
      if (entry.expires && now > entry.expires) {
        this.cache.delete(key);
        evicted++;
      }
    }

    for (const [key, entry] of this.semanticCache) {
      if (entry.expires && now > entry.expires) {
        this.semanticCache.delete(key);
        evicted++;
      }
    }

    return evicted;
  }
}

// Singleton instance
const cache = new NeuralCache();

// Auto-evict every 60 seconds
setInterval(() => cache.evict(), 60000);

module.exports = cache;
