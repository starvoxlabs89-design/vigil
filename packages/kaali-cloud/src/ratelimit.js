// In-memory sliding-window rate limiter. Fine for single-VPS deploy;
// swap to Redis if the API goes multi-node.
const store = new Map();

export function limit(key, max, windowMs) {
  const now = Date.now();
  const arr = store.get(key) || [];
  const fresh = arr.filter((t) => now - t < windowMs);
  fresh.push(now);
  store.set(key, fresh);
  return fresh.length <= max;
}

// Periodic sweep so idle keys don't leak forever.
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of store) {
    const fresh = arr.filter((t) => now - t < 24 * 60 * 60 * 1000);
    if (fresh.length === 0) store.delete(k);
    else store.set(k, fresh);
  }
}, 10 * 60 * 1000).unref();
