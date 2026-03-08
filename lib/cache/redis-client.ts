import { createClient } from "redis";

type AppRedisClient = ReturnType<typeof createClient>;

let client: AppRedisClient | null = null;
let connectPromise: Promise<AppRedisClient | null> | null = null;
let retryAfter = 0;

const RETRY_BACKOFF_MS = 30_000;

function redisUrl(): string | null {
  const value = process.env.REDIS_URL?.trim();
  return value ? value : null;
}

export async function getRedisClient(): Promise<AppRedisClient | null> {
  const url = redisUrl();
  if (!url) return null;

  if (Date.now() < retryAfter) return null;
  if (client?.isOpen) return client;
  if (connectPromise) return connectPromise;

  const nextClient = createClient({
    url,
    socket: {
      connectTimeout: 3000,
      reconnectStrategy: (retries) => Math.min(50 * retries, 500),
    },
  });

  nextClient.on("error", (err) => {
    console.error("[redis] client error:", err.message);
  });

  connectPromise = (async () => {
    try {
      await nextClient.connect();
      client = nextClient;
      retryAfter = 0;
      return client;
    } catch (err) {
      console.error("[redis] connect warning:", (err as Error).message);
      retryAfter = Date.now() + RETRY_BACKOFF_MS;
      try {
        await nextClient.quit();
      } catch {
        // Ignore close errors.
      }
      return null;
    } finally {
      connectPromise = null;
    }
  })();

  return connectPromise;
}
