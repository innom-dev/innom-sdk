import { afterEach, describe, expect, it, vi } from "vitest";
import { WalletChannel } from "../src/walletChannel.js";

/**
 * Credential-mint acknowledgement contract (VAL-REUSE-006).
 *
 * After an M1 pass the SDK asks the wallet to mint and store the Innom
 * credential, then proceeds to token minting. The acknowledgement is a
 * store-population gate, never a ceremony gate: it must be capped far inside
 * VAL-REUSE-006's 500ms ceremony-disturbance ceiling so a lost or stalled
 * wallet ack (an unresponsive iframe, a dropped message) can never delay the
 * unlock. These tests pin the cap with a fake window object — no browser
 * needed — and the `{ ok: false }` resolution every caller relies on.
 */

/** Minimal stand-in for the browser `window` the channel listens on. */
function createFakeWindow(): {
  addEventListener: (type: string, listener: (event: unknown) => void) => void;
  removeEventListener: (type: string, listener: (event: unknown) => void) => void;
  dispatch: (event: unknown) => void;
  messageListenerCount: () => number;
} {
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  return {
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    dispatch(event) {
      for (const listener of [...(listeners.get("message") ?? [])]) listener(event);
    },
    messageListenerCount() {
      return listeners.get("message")?.size ?? 0;
    },
  };
}

const REQUEST_ID = "req_0123456789abcdef";
const ATTESTATION = "testheader.testpayload.testsignature";

/** Installs the fake global window (the channel listens on `window`). */
function installFakeWindow(): ReturnType<typeof createFakeWindow> {
  const fakeWindow = createFakeWindow();
  (globalThis as { window?: unknown }).window = fakeWindow;
  return fakeWindow;
}

function channel(targetWindow: { postMessage: () => void }): WalletChannel {
  return new WalletChannel({
    walletUrl: "http://localhost:4002/",
    targetWindow: targetWindow as unknown as Window,
  });
}

const MUTED_TARGET: { postMessage: () => void } = { postMessage: () => undefined };

describe("WalletChannel.requestCredentialMint", () => {
  afterEach(() => {
    vi.useRealTimers();
    if ((globalThis as { window?: unknown }).window) {
      delete (globalThis as { window?: unknown }).window;
    }
  });

  it("resolves { ok: false } at the 400ms cap when the wallet never acknowledges", async () => {
    vi.useFakeTimers();
    installFakeWindow();
    const innom = channel(MUTED_TARGET);

    const outcome = innom.requestCredentialMint({
      requestId: REQUEST_ID,
      attestation: ATTESTATION,
    });
    let settled: unknown = "pending";
    void outcome.then((value) => {
      settled = value;
    });

    // At 399ms the wait is still alive: the cap has not fired.
    await vi.advanceTimersByTimeAsync(399);
    expect(settled).toBe("pending");

    // One millisecond later the wait resolves `{ ok: false }` — the ceremony
    // proceeds at 400ms no matter what the wallet does (VAL-REUSE-006).
    await vi.advanceTimersByTimeAsync(1);
    await Promise.resolve();
    expect(settled).toEqual({ ok: false });
  });

  it("resolves { ok: true } when the wallet acknowledges within the cap", async () => {
    const fakeWindow = installFakeWindow();
    const innom = channel(MUTED_TARGET);

    const outcome = innom.requestCredentialMint({
      requestId: REQUEST_ID,
      attestation: ATTESTATION,
    });
    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: { type: "innom.wallet.minted", version: 1, requestId: REQUEST_ID, ok: true },
    });

    await expect(outcome).resolves.toEqual({ ok: true });
  });

  it("resolves { ok: false } on a rejected acknowledgement", async () => {
    const fakeWindow = installFakeWindow();
    const innom = channel(MUTED_TARGET);

    const outcome = innom.requestCredentialMint({
      requestId: REQUEST_ID,
      attestation: ATTESTATION,
    });
    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: { type: "innom.wallet.minted", version: 1, requestId: REQUEST_ID, ok: false },
    });

    await expect(outcome).resolves.toEqual({ ok: false });
  });

  it("ignores a late acknowledgement that lands after the cap resolved", async () => {
    vi.useFakeTimers();
    const fakeWindow = installFakeWindow();
    const innom = channel(MUTED_TARGET);

    const outcome = innom.requestCredentialMint({
      requestId: REQUEST_ID,
      attestation: ATTESTATION,
    });
    await vi.advanceTimersByTimeAsync(400);
    await expect(outcome).resolves.toEqual({ ok: false });

    // The wait removed its listener when the cap fired, so a late ack from an
    // eventually-recovered wallet finds no listener and changes nothing.
    expect(fakeWindow.messageListenerCount()).toBe(0);
    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: { type: "innom.wallet.minted", version: 1, requestId: REQUEST_ID, ok: true },
    });
    await expect(outcome).resolves.toEqual({ ok: false });
  });

  it("does not give up before 30s when the wallet signals ready late (cold Turbopack first-compile)", async () => {
    vi.useFakeTimers();
    const fakeWindow = installFakeWindow();
    const innom = channel(MUTED_TARGET);

    let settled: unknown = "pending";
    const outcome = innom.waitForReady();
    void outcome.then(
      (value) => {
        settled = value;
      },
      (error) => {
        settled = error;
      },
    );

    // Turbopack's first-request compile for the wallet takes ~16s on a cold
    // dev server. The old 15s default rejected here; the 30s default must
    // still be waiting. At 20s the wait is alive and nothing has settled.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(settled).toBe("pending");

    // The wallet signals ready; the channel resolves instead of rejecting.
    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: { type: "innom.wallet.ready", version: 1 },
    });
    await expect(outcome).resolves.toBeUndefined();
  });

  it("filters acknowledgements by requestId, ignoring other ceremonies' acks", async () => {
    const fakeWindow = installFakeWindow();
    const innom = channel(MUTED_TARGET);

    const outcome = innom.requestCredentialMint({
      requestId: REQUEST_ID,
      attestation: ATTESTATION,
    });
    // A stale ack from an earlier ceremony carries a different requestId and
    // must not satisfy this wait.
    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: {
        type: "innom.wallet.minted",
        version: 1,
        requestId: "req_0000000000000000",
        ok: true,
      },
    });
    let settled: unknown = "pending";
    void outcome.then((value) => {
      settled = value;
    });
    await Promise.resolve();
    expect(settled).toBe("pending");

    fakeWindow.dispatch({
      origin: "http://localhost:4002",
      source: MUTED_TARGET,
      data: { type: "innom.wallet.minted", version: 1, requestId: REQUEST_ID, ok: true },
    });
    await expect(outcome).resolves.toEqual({ ok: true });
  });
});
