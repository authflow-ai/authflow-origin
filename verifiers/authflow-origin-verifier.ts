// SPDX-License-Identifier: Apache-2.0
// Copy this whole file. Origin Protocol v1 is NOT JWT; never use OAuth JWKS here.
// Create one verifier per issuer/resource per process (or Workers isolate), not per request.
// Node: collect every X-Authflow-Identity field from request.rawHeaders and pass the values.
// Fetch/Workers: pass request.headers; comma-joined duplicate values are rejected.
// Dispatch MCP only when result.ok; otherwise return result.response unchanged.
// replayStore.claim MUST atomically insert-if-absent across every serving replica.
// Redis SET NX with expiry or a Durable Object transaction works; Workers KV get/put does not.

export const PROTOCOL_VERSION = "v1";
export const VERIFIER_VERSION = "1.0.0";

export type OriginErrorCode =
  | "missing_identity" | "unsupported_version" | "malformed_identity"
  | "bad_signature" | "unknown_key" | "keys_unavailable" | "expired"
  | "not_yet_valid" | "replayed_nonce" | "iss_mismatch" | "resource_mismatch"
  | "forbidden_claim" | "replay_cache_unavailable";

export interface OriginIdentity {
  readonly sub: string;
  readonly resource: string;
  readonly tier: string;
  readonly nonce: string;
  readonly iat: number;
  readonly exp: number;
}

export interface ReplayStore {
  // true = atomically claimed; false = already present; throw = store unavailable.
  // Keep the key until at least retainUntil (UTC Unix seconds). Never evict live keys.
  claim(key: string, retainUntil: number): Promise<boolean>;
}

export interface OriginVerifierOptions {
  readonly issuer: string;
  readonly resource: string;
  readonly replayStore: ReplayStore;
  readonly fetch?: typeof fetch;
  readonly now?: () => number; // UTC Unix seconds; omit outside deterministic tests.
}

export type OriginVerification =
  | { readonly ok: true; readonly identity: OriginIdentity }
  | { readonly ok: false; readonly errorCode: OriginErrorCode; readonly response: Response };

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const forbidden = new Set(["credits", "credit_balance", "balance", "remaining",
  "remaining_credits", "quota", "units_remaining"]);
const kidPattern = /^[A-Za-z0-9._-]{1,64}$/;
const maxHeaderBytes = 16_384;
const maxDocumentBytes = 65_536;

// JavaScript's $ also matches before a final newline; compare the complete match.
function matches(pattern: RegExp, value: unknown): value is string {
  return typeof value === "string" && pattern.exec(value)?.[0] === value;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decodeBase64Url(value: unknown): Uint8Array<ArrayBuffer> {
  if (!matches(/^[A-Za-z0-9_-]+$/, value)) throw new Error("Invalid base64url");
  const decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== value) throw new Error("Noncanonical base64url");
  return Uint8Array.from(decoded, character => character.charCodeAt(0));
}

function validUrl(value: unknown, issuer: boolean): value is string {
  if (typeof value !== "string" || value !== value.trim() || /[?#\\\s]/u.test(value)) return false;
  try {
    const url = new URL(value);
    const loopback = url.hostname === "localhost" || url.hostname === "[::1]" ||
      /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname);
    return (url.protocol === "https:" || (url.protocol === "http:" && loopback)) &&
      !url.username && !url.password && (!issuer || url.pathname === "/") &&
      value === url.origin + url.pathname.replace(/\/+$/, "");
  } catch { return false; }
}

function validIssuerClaim(value: unknown): value is string {
  if (typeof value !== "string" || value !== value.trim() || /[?#\\\s]/u.test(value) || value.endsWith("/")) return false;
  try {
    const url = new URL(value);
    return !url.username && !url.password && url.pathname === "/" &&
      (url.protocol === "https:" || (url.protocol === "http:" &&
        (url.hostname === "localhost" || url.hostname === "[::1]" || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname))));
  } catch { return false; }
}

// JSON.parse supplies the grammar; this scan preserves NumericDate spelling and sees
// forbidden/duplicate members that JSON.parse would otherwise overwrite.
function parseJson(bytes: Uint8Array): {
  value: Record<string, unknown>; forbiddenMember: boolean; integerDates: Set<string>;
} {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error("BOM");
  const source = decoder.decode(bytes);
  const value: unknown = JSON.parse(source);
  if (!object(value)) throw new Error("Expected an object");
  const tokens = source.match(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)!;
  const stack: Array<Set<string> | null> = [];
  const integerDates = new Set<string>();
  let forbiddenMember = false;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === "{" || token === "[") {
      stack.push(token === "{" ? new Set() : null);
      if (stack.length > 64) throw new Error("Too deeply nested");
    } else if (token === "}" || token === "]") {
      stack.pop();
    } else if (token.startsWith('"') && tokens[i + 1] === ":") {
      const name: string = JSON.parse(token);
      const members = stack[stack.length - 1]!;
      if (members.has(name)) throw new Error("Duplicate member");
      members.add(name);
      forbiddenMember ||= forbidden.has(name);
      if (stack.length === 1 && (name === "iat" || name === "exp") && /^-?\d+$/.test(tokens[i + 2])) {
        integerDates.add(name);
      }
    }
  }
  return { value, forbiddenMember, integerDates };
}

function rejection(errorCode: OriginErrorCode): OriginVerification {
  return {
    ok: false, errorCode,
    response: new Response(JSON.stringify({
      error: "invalid_origin_identity", error_code: errorCode,
      error_description: "Request is missing a valid Authflow Origin Protocol identity header.",
    }), {
      status: 403,
      headers: {
        "Content-Type": "application/json", "Cache-Control": "no-store",
        "X-Authflow-Verifier": `typescript/${VERIFIER_VERSION}`,
      },
    }),
  };
}

export function createOriginVerifier(options: OriginVerifierOptions) {
  if (!validUrl(options.issuer, true) || !validUrl(options.resource, false)) {
    throw new Error("Copy the registration receipt's canonical issuer and resource exactly.");
  }
  if (typeof options.replayStore?.claim !== "function") {
    throw new Error("An atomic replayStore.claim implementation is required.");
  }
  const { issuer, resource, replayStore } = options;
  const fetchKeys = options.fetch ?? globalThis.fetch.bind(globalThis);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  let keys: Map<string, CryptoKey> | undefined;
  let freshUntil = -Infinity;
  let lastAttempt = -Infinity;
  let pending: Promise<void> | undefined;
  let forced: Array<{ kid: string; at: number }> = [];

  async function fetchDocument(): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await fetchKeys(`${issuer}/.well-known/authflow-origin-keys`, {
        redirect: "error", signal: controller.signal, headers: { Accept: "application/json" },
      });
      if (!response.ok) { await response.body?.cancel(); return; }
      if (!response.body) return;
      if (Number(response.headers.get("content-length")) > maxDocumentBytes) {
        await response.body.cancel();
        return;
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > maxDocumentBytes) { await reader.cancel(); return; }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const document = parseJson(bytes).value;
      if (document.issuer !== issuer || document.protocol_version !== PROTOCOL_VERSION ||
        !Array.isArray(document.keys) || document.keys.length === 0 || document.keys.length > 128) return;
      const parsed = new Map<string, CryptoKey>();
      const seen = new Set<string>();
      for (const entry of document.keys) {
        if (!object(entry)) continue;
        if (Object.hasOwn(entry, "d")) return;
        if (typeof entry.kid === "string") {
          if (seen.has(entry.kid)) return;
          seen.add(entry.kid);
        }
        if (entry.kty !== "OKP" || entry.crv !== "Ed25519" || entry.use !== "sig" ||
          entry.alg !== "EdDSA" || !matches(kidPattern, entry.kid)) continue;
        try {
          const raw = decodeBase64Url(entry.x);
          if (raw.length !== 32) continue;
          parsed.set(entry.kid, await crypto.subtle.importKey("raw", raw, "Ed25519", false, ["verify"]));
        } catch { /* Ignore unusable future or malformed key shapes. */ }
      }
      if (parsed.size === 0) return;
      const maxAge = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?(?:\s*,|\s*$)/i.exec(response.headers.get("cache-control") ?? "");
      const age = maxAge ? Math.min(Number(maxAge[1]), 3600) : 300;
      keys = parsed;
      freshUntil = now() + age;
    } catch { /* Failed fetches keep the last valid document; never skip verification. */ }
    finally { clearTimeout(timer); }
  }

  async function refresh(kid?: string): Promise<void> {
    if (pending) return pending;
    const time = now();
    forced = forced.filter(entry => time - entry.at < 30);
    if (kid !== undefined) {
      if (forced.length >= 3 || forced.some(entry => entry.kid === kid)) return;
      forced.push({ kid, at: time });
    } else if (time - lastAttempt < 30) return;
    lastAttempt = time;
    pending = fetchDocument();
    try { await pending; } finally { pending = undefined; }
  }

  async function verify(headers: Headers | readonly string[]): Promise<OriginVerification> {
    const values: readonly string[] = Array.isArray(headers)
      ? headers : [(headers as Headers).get("X-Authflow-Identity") ?? ""];
    if (values.length !== 1 || typeof values[0] !== "string" || !values[0].trim() || values[0].includes(",")) {
      return rejection("missing_identity");
    }
    const raw = values[0].trim();
    if (raw.length > maxHeaderBytes) return rejection("malformed_identity");
    const parts = raw.split(";");
    if (parts.length !== 3 || parts.some(part => !part)) return rejection("malformed_identity");
    if (parts[0] !== PROTOCOL_VERSION) return rejection("unsupported_version");
    let signature: Uint8Array<ArrayBuffer>;
    let parsed: ReturnType<typeof parseJson>;
    try {
      signature = decodeBase64Url(parts[2]);
      if (signature.length !== 64) return rejection("malformed_identity");
      parsed = parseJson(decodeBase64Url(parts[1]));
    } catch { return rejection("malformed_identity"); }
    const claims = parsed.value;
    if (!matches(kidPattern, claims.kid)) return rejection("malformed_identity");
    if (!keys || now() >= freshUntil) await refresh();
    if (!keys) return rejection("keys_unavailable");
    if (!keys.has(claims.kid)) await refresh(claims.kid);
    const key = keys.get(claims.kid);
    if (!key) return rejection("unknown_key");
    try {
      if (!await crypto.subtle.verify("Ed25519", key, signature, encoder.encode(`v1;${parts[1]}`))) {
        return rejection("bad_signature");
      }
    } catch { return rejection("bad_signature"); }
    if (parsed.forbiddenMember) return rejection("forbidden_claim");
    if (!validIssuerClaim(claims.iss) ||
      !matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, claims.sub) ||
      claims.sub === "00000000-0000-0000-0000-000000000000" ||
      typeof claims.resource !== "string" || !claims.resource ||
      !matches(/^[a-z][a-z0-9_]{0,63}$/, claims.tier) ||
      !matches(/^[A-Za-z0-9_-]{16,64}$/, claims.nonce) ||
      !parsed.integerDates.has("iat") || !parsed.integerDates.has("exp") ||
      typeof claims.iat !== "number" || !Number.isSafeInteger(claims.iat) ||
      typeof claims.exp !== "number" || !Number.isSafeInteger(claims.exp)) return rejection("malformed_identity");
    if (claims.iss !== issuer) return rejection("iss_mismatch");
    if (claims.resource !== resource) return rejection("resource_mismatch");
    if (claims.exp <= claims.iat || claims.exp - claims.iat > 300) return rejection("malformed_identity");
    const time = now();
    if (time > claims.exp + 60) return rejection("expired");
    if (claims.iat > time + 60) return rejection("not_yet_valid");
    let replayTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      const claimed = await Promise.race([
        replayStore.claim(JSON.stringify([issuer, resource, claims.nonce]),
          Math.max(time + 180, claims.exp + 61)),
        new Promise<never>((_, reject) => {
          replayTimer = setTimeout(() => reject(new Error("Replay store timed out")), 5_000);
        }),
      ]);
      if (claimed === false) return rejection("replayed_nonce");
      if (claimed !== true) return rejection("replay_cache_unavailable");
    } catch { return rejection("replay_cache_unavailable"); }
    finally { clearTimeout(replayTimer); }
    return { ok: true, identity: Object.freeze({
      sub: claims.sub, resource: claims.resource, tier: claims.tier,
      nonce: claims.nonce, iat: claims.iat, exp: claims.exp,
    }) };
  }

  return Object.freeze({ verify, warm: async () => { await refresh(); return keys !== undefined; } });
}
