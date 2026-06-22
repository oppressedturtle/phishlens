import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("./redis", () => ({
  redis: { eval: vi.fn() },
}));

import { rateLimit } from "./rate-limit";
import { redis } from "./redis";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("rateLimit", () => {
  it("allows a request when under the limit", async () => {
    vi.mocked(redis.eval).mockResolvedValue([1, 4] as never);

    const result = await rateLimit("submit:abc", 5, 60_000);

    expect(result.success).toBe(true);
    expect(result.remaining).toBe(4);
  });

  it("blocks a request when the limit is reached", async () => {
    vi.mocked(redis.eval).mockResolvedValue([0, 0] as never);

    const result = await rateLimit("submit:abc", 5, 60_000);

    expect(result.success).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it("passes the bucket key, limit and window to the Lua script", async () => {
    vi.mocked(redis.eval).mockResolvedValue([1, 2] as never);

    await rateLimit("submit:abc", 3, 30_000);

    const args = vi.mocked(redis.eval).mock.calls[0]!;
    // args: script, numKeys, key, now, window, limit, member
    expect(args[2]).toBe("ratelimit:submit:abc");
    expect(args[4]).toBe(30_000);
    expect(args[5]).toBe(3);
  });

  it("fails open when Redis throws", async () => {
    vi.mocked(redis.eval).mockRejectedValue(new Error("redis down"));

    const result = await rateLimit("submit:abc", 5, 60_000);

    expect(result.success).toBe(true);
    expect(result.remaining).toBe(4);
  });
});
