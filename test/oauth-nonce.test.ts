import { deriveDpopNonce, isValidDpopNonce } from "../src/oauth/nonce";

describe("OAuth DPoP nonce", () => {
  const secret = "nonce-secret";
  const now = 300 * 10_000 + 42;

  it("derives the same nonce inside one window", async () => {
    await expect(deriveDpopNonce(secret, now + 1)).resolves.toBe(
      await deriveDpopNonce(secret, now + 100),
    );
  });

  it("accepts current and previous windows", async () => {
    const current = await deriveDpopNonce(secret, now);
    const previous = await deriveDpopNonce(secret, now - 300);

    await expect(isValidDpopNonce(secret, current, now)).resolves.toBe(true);
    await expect(isValidDpopNonce(secret, previous, now)).resolves.toBe(true);
  });

  it("rejects nonces two or more windows old", async () => {
    const current = await deriveDpopNonce(secret, now);
    const stale = await deriveDpopNonce(secret, now - 600);

    expect(stale).not.toBe(current);
    await expect(isValidDpopNonce(secret, stale, now)).resolves.toBe(false);
  });

  it("throws on an empty secret", async () => {
    await expect(deriveDpopNonce("", now)).rejects.toThrow("OAuth nonce secret is required");
    await expect(isValidDpopNonce("", "nonce", now)).rejects.toThrow(
      "OAuth nonce secret is required",
    );
  });
});
