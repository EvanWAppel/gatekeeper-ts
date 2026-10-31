// Verify Cloudflare Access tokens, so an app can tell a signed-in visitor from everyone else.
//
// Cloudflare Access puts a signed JWT in the Cf-Access-Jwt-Assertion header of every request
// it lets through. AccessVerifier.verify returns an Identity only for a token that is signed
// by your team's current keys, issued by your team, meant for this app, and in date. Every
// other case returns null, so an app that shows its full version only when it gets an
// Identity fails toward its public version, never toward the private one.
//
// Configuration (team domain, the app's AUD tag) is passed in by each app; none lives here.
// Port of gatekeeper (Python); same checks, same review findings.

import { createRemoteJWKSet, importJWK, jwtVerify } from "jose"

export const HEADER = "Cf-Access-Jwt-Assertion"

// https://<team>.cloudflareaccess.com — nothing before, nothing after.
const TEAM_DOMAIN = /^https:\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com$/

// Cloudflare signs Access tokens with RS256. Accepting anything else invites
// algorithm-confusion and "alg: none" forgeries.
const ALGORITHMS = ["RS256"]

// Access tokens are ~1 KB. Anything far larger is junk; reject it before any crypto or fetch.
const MAX_TOKEN_LENGTH = 16 * 1024

const isNumber = (x) => typeof x === "number" && Number.isFinite(x)

export class AccessVerifier {
  #issuer
  #audience
  #leeway
  #keys

  /**
   * Checks Access tokens for one app.
   *
   * teamDomain: https://<team>.cloudflareaccess.com (Zero Trust → Settings).
   * audience: the app's Application Audience (AUD) tag (Access → the app → Overview).
   *
   * Bad configuration throws here, at startup, so it is loud; bad tokens never throw
   * from verify — they resolve to null.
   */
  constructor({ teamDomain, audience, leewaySeconds = 60, keyCacheSeconds = 3600 } = {}) {
    const team = typeof teamDomain === "string" ? teamDomain.trim().replace(/\/+$/, "").toLowerCase() : ""
    if (!TEAM_DOMAIN.test(team)) {
      throw new TypeError(
        `teamDomain must look like https://<team>.cloudflareaccess.com (got ${JSON.stringify(teamDomain)})`,
      )
    }
    const aud = typeof audience === "string" ? audience.trim() : ""
    if (!aud) throw new TypeError("audience (the app's Access AUD tag) is required")
    if (!isNumber(leewaySeconds) || leewaySeconds < 0 || leewaySeconds > 300) {
      throw new RangeError(`leewaySeconds must be 0–300 (got ${String(leewaySeconds)})`)
    }
    if (!isNumber(keyCacheSeconds) || keyCacheSeconds <= 0) {
      throw new RangeError(`keyCacheSeconds must be a positive number (got ${String(keyCacheSeconds)})`)
    }

    this.#issuer = team
    this.#audience = aud
    this.#leeway = leewaySeconds
    // Keys come only from the configured team, never from anything the token says (jose
    // ignores jku / x5u). The whole set is cached and reloaded once stale, so a key
    // Cloudflare rotates out stops working on the next refresh. Unknown kids refetch at
    // most once per cooldown, redirects are not followed, and a slow Cloudflare can't hold
    // a request for long.
    this.#keys = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`), {
      cacheMaxAge: keyCacheSeconds * 1000,
      cooldownDuration: 30_000,
      timeoutDuration: 5_000,
    })
  }

  /**
   * Startup self-check: rejects if the team's signing keys can't be loaded, or none of them
   * imports as an RS256 public key.
   * Without this, a broken environment looks exactly like "nobody is signed in" — every
   * visitor quietly gets the public version. Await it once at startup and log the error.
   */
  async check() {
    let set
    try {
      await this.#keys.reload()
      set = this.#keys.jwks()
    } catch (err) {
      // Every failure becomes one error type; the original stays on `cause`.
      throw new Error(`cannot load Cloudflare Access signing keys: ${err?.name}: ${err?.message}`, {
        cause: err,
      })
    }
    const candidates = (set?.keys ?? []).filter(
      (k) =>
        k &&
        k.kty === "RSA" &&
        (k.alg === undefined || k.alg === "RS256") &&
        (k.use === undefined || k.use === "sig") &&
        (!Array.isArray(k.key_ops) || k.key_ops.includes("verify")),
    )
    // Labels aren't enough: a key only counts if it imports as an RS256 public key.
    let usable = 0
    for (const k of candidates) {
      try {
        if ((await importJWK(k, "RS256")).type === "public") usable++
      } catch {
        // not a usable key
      }
    }
    if (usable === 0) throw new Error("Cloudflare Access returned no usable signing keys")
  }

  /** The signed-in identity for a valid token, else null. Never throws. */
  async verify(token) {
    if (typeof token !== "string" || !token.trim() || token.length > MAX_TOKEN_LENGTH) return null
    let payload
    try {
      ;({ payload } = await jwtVerify(token, this.#keys, {
        algorithms: ALGORITHMS,
        issuer: this.#issuer,
        audience: this.#audience,
        clockTolerance: this.#leeway,
        requiredClaims: ["exp", "iss", "aud"],
      }))
    } catch {
      // Fail toward the public version. Never log the token itself.
      return null
    }
    // jose checks iat only with maxTokenAge; PyJWT rejects one issued in the future.
    if (payload.iat !== undefined && !(isNumber(payload.iat) && payload.iat <= Date.now() / 1000 + this.#leeway)) {
      return null
    }
    const email = payload.email
    if (typeof email !== "string" || !email) return null // service tokens are not people
    const subject = typeof payload.sub === "string" ? payload.sub : ""
    return Object.freeze({ email, subject })
  }

  /**
   * verify the Access header from a request's headers: a fetch / Next.js Headers object,
   * a Map, or a plain object (any letter case). A header sent more than once is ambiguous:
   * null. Never throws, whatever it is handed.
   */
  async fromHeaders(headers) {
    let token
    try {
      token = readHeader(headers)
    } catch {
      return null // an exotic headers object must not break the "never throws" promise
    }
    return this.verify(token)
  }
}

// The one Access header value, or null when it's missing or ambiguous (sent more than once,
// in any letter case, or as an array).
function readHeader(headers) {
  if (!headers || typeof headers !== "object") return null
  if (!(headers instanceof Map) && typeof headers.get === "function") {
    return headers.get(HEADER) // Headers joins repeats with ", ", which never verifies
  }
  const wanted = HEADER.toLowerCase()
  const entries = headers instanceof Map ? headers.entries() : Object.entries(headers)
  const found = []
  for (const [name, value] of entries) {
    if (typeof name === "string" && name.toLowerCase() === wanted) found.push(value)
  }
  return found.length === 1 && typeof found[0] === "string" ? found[0] : null
}
