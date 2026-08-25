import test from "node:test";
import assert from "node:assert/strict";
import {
  cacheGet,
  cacheSet,
  cacheDel,
  cacheDelPattern,
  invalidateMarketplaceCache,
} from "../../src/lib/cache/redis.js";

test("Redis Caching Utilities — Fallback resilience when unconfigured/configured", async (t) => {
  await t.test("cacheGet returns null gracefully without Redis", async () => {
    const val = await cacheGet("nonexistent_test_key");
    assert.equal(val, null);
  });

  await t.test("cacheSet does not throw without Redis", async () => {
    await assert.doesNotReject(async () => {
      await cacheSet("test_key", { data: 123 }, 60);
    });
  });

  await t.test("cacheDel does not throw without Redis", async () => {
    await assert.doesNotReject(async () => {
      await cacheDel("test_key");
    });
  });

  await t.test("cacheDelPattern does not throw without Redis", async () => {
    await assert.doesNotReject(async () => {
      await cacheDelPattern("materials:*");
    });
  });

  await t.test("invalidateMarketplaceCache clears all marketplace namespaces", async () => {
    await assert.doesNotReject(async () => {
      await invalidateMarketplaceCache();
    });
  });
});
