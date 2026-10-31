// A fake Cloudflare Access team with real RSA keys, no network.
import { SignJWT, exportJWK, generateKeyPair } from "jose"

export const TEAM = "https://example-team.cloudflareaccess.com"
export const AUD = "aud-tag-for-this-app"
export const CERTS = `${TEAM}/cdn-cgi/access/certs`

export async function keypair(kid) {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true })
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" }
  return { privateKey, publicKey, jwk }
}

export const teamKey = await keypair("team-key-1")
export const attackerKey = await keypair("team-key-1") // same kid, different key: a forgery

/**
 * Replace global fetch (what jose uses) with a stub serving `state.keys`.
 * Returns the state; every requested URL lands in `state.calls`.
 */
export function stubFetch(t, { keys = [teamKey.jwk] } = {}) {
  const state = { calls: [], keys, fail: false, body: undefined, status: 200 }
  const original = globalThis.fetch
  globalThis.fetch = async (url) => {
    state.calls.push(String(url))
    if (state.fail) throw new TypeError("network down")
    const body = state.body ?? JSON.stringify({ keys: state.keys })
    return new Response(body, { status: state.status })
  }
  t.after(() => {
    globalThis.fetch = original
  })
  return state
}

/** A token as Cloudflare would issue it; override or drop (null) any claim. */
export async function makeToken({ key = teamKey.privateKey, kid = "team-key-1", header = {}, ...claims } = {}) {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    aud: [AUD],
    iss: TEAM,
    email: "someone@example.com",
    iat: now,
    nbf: now,
    exp: now + 3600,
    sub: "user-123",
    ...claims,
  }
  for (const k of Object.keys(payload)) if (payload[k] === null) delete payload[k]
  return new SignJWT(payload).setProtectedHeader({ alg: "RS256", kid, ...header }).sign(key)
}

export const b64url = (data) =>
  Buffer.from(typeof data === "string" ? data : JSON.stringify(data)).toString("base64url")
