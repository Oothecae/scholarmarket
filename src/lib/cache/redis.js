let client = null;

export async function getRedisClient() {
  if (!process.env.REDIS_URL) return null;
  if (!client) {
    try {
      const { createClient } = await import('redis');
      client = createClient({ url: process.env.REDIS_URL });
      client.on('error', (err) => console.error('Redis error', err.message));
      await client.connect();
    } catch (err) {
      console.warn('Failed to initialize Redis client:', err.message);
      return null;
    }
  }
  return client;
}

export async function cacheGet(key) {
  const redis = await getRedisClient();
  if (!redis) return null;
  try {
    const val = await redis.get(key);
    return val ? JSON.parse(val) : null;
  } catch { return null; }
}

export async function cacheSet(key, value, ttlSeconds = 600) {
  const redis = await getRedisClient();
  if (!redis) return;
  try {
    await redis.set(key, JSON.stringify(value), { EX: ttlSeconds });
  } catch { /* no-op */ }
}

export async function cacheDel(key) {
  const redis = await getRedisClient();
  if (!redis) return;
  try { await redis.del(key); } catch { /* no-op */ }
}

export async function cacheDelPattern(pattern) {
  const redis = await getRedisClient();
  if (!redis) return;
  try {
    const keys = await redis.keys(pattern);
    if (keys && keys.length > 0) {
      await redis.del(keys);
    }
  } catch (err) {
    console.warn(`[Redis] Pattern deletion failed for ${pattern}:`, err.message);
  }
}

export async function invalidateMarketplaceCache() {
  await Promise.all([
    cacheDelPattern('market-materials:*'),
    cacheDelPattern('materials:*'),
    cacheDelPattern('materials-search:*'),
  ]);
}

