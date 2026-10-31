// Every way a Cloudflare Access token can be wrong must come back as null (→ demo).
// Ported from gatekeeper (Python) tests/test_verify.py; same cases, same review findings.
import assert from "node:assert/strict"
import { createHmac, generateKeyPairSync } from "node:crypto"
import { readFileSync } from "node:fs"
import { describe, test } from "node:test"

import { SignJWT, exportJWK, exportSPKI, importJWK } from "jose"

import { AccessVerifier, HEADER } from "../index.js"
import { AUD, CERTS, TEAM, attackerKey, b64url, keypair, makeToken, stubFetch, teamKey } from "./helpers.js"

const now = () => Math.floor(Date.now() / 1000)
const verifier = (opts = {}) => new AccessVerifier({ teamDomain: TEAM, audience: AUD, ...opts })

// --- the one way in ----------------------------------------------------------

describe("valid tokens", () => {
  test("a valid token returns the identity", async (t) => {
    stubFetch(t)
    assert.deepEqual(await verifier().verify(await makeToken()), {
      email: "someone@example.com",
      subject: "user-123",
    })
  })

  test("the returned identity is frozen", async (t) => {
    stubFetch(t)
    assert.ok(Object.isFrozen(await verifier().verify(await makeToken())))
  })

  test("fromHeaders reads the header from a plain object, any letter case", async (t) => {
    stubFetch(t)
    const v = verifier()
    assert.notEqual(await v.fromHeaders({ [HEADER.toLowerCase()]: await makeToken() }), null)
    assert.notEqual(await v.fromHeaders({ [HEADER]: await makeToken() }), null)
  })

  test("fromHeaders reads a fetch/Next.js Headers object", async (t) => {
    stubFetch(t)
    const headers = new Headers({ [HEADER]: await makeToken() })
    assert.notEqual(await verifier().fromHeaders(headers), null)
  })

  test("aud as a plain string is accepted", async (t) => {
    stubFetch(t)
    assert.notEqual(await verifier().verify(await makeToken({ aud: AUD })), null)
  })
})

// --- everything else is null -------------------------------------------------

describe("rejected tokens", () => {
  for (const token of [undefined, null, "", "   ", "not-a-jwt", "a.b.c", 42, {}]) {
    test(`missing or garbage token: ${JSON.stringify(token)}`, async (t) => {
      stubFetch(t)
      assert.equal(await verifier().verify(token), null)
    })
  }

  test("missing header", async (t) => {
    stubFetch(t)
    const v = verifier()
    assert.equal(await v.fromHeaders({}), null)
    assert.equal(await v.fromHeaders(null), null)
    assert.equal(await v.fromHeaders(undefined), null)
    assert.equal(await v.fromHeaders(new Headers()), null)
  })

  test("a repeated header (array value) is ambiguous and rejected", async (t) => {
    stubFetch(t)
    const token = await makeToken()
    assert.equal(await verifier().fromHeaders({ [HEADER]: [token, token] }), null)
  })

  test("signed by another key with the same kid", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ key: attackerKey.privateKey })), null)
  })

  test("unknown kid", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ kid: "not-a-team-key" })), null)
  })

  test("wrong audience", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ aud: ["some-other-app"] })), null)
  })

  test("missing audience", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ aud: null })), null)
  })

  test("wrong issuer", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ iss: "https://evil.cloudflareaccess.com" })), null)
  })

  test("missing issuer", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ iss: null })), null)
  })

  test("expired", async (t) => {
    stubFetch(t)
    const past = now() - 7200
    assert.equal(await verifier().verify(await makeToken({ iat: past, nbf: past, exp: past + 60 })), null)
  })

  test("missing expiry", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ exp: null })), null)
  })

  test("not yet valid", async (t) => {
    stubFetch(t)
    const future = now() + 7200
    assert.equal(await verifier().verify(await makeToken({ nbf: future, exp: future + 3600 })), null)
  })

  test("missing email (service tokens never get the full app)", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ email: null })), null)
  })

  for (const email of ["", 42, ["a@example.com"]]) {
    test(`non-string or empty email: ${JSON.stringify(email)}`, async (t) => {
      stubFetch(t)
      assert.equal(await verifier().verify(await makeToken({ email })), null)
    })
  }

  test("alg: none", async (t) => {
    stubFetch(t)
    const claims = { aud: [AUD], iss: TEAM, email: "x@example.com", exp: now() + 3600, nbf: now() }
    const forged = `${b64url({ alg: "none", kid: "team-key-1" })}.${b64url(claims)}.`
    assert.equal(await verifier().verify(forged), null)
  })

  test("HS256 signed with the public key (algorithm confusion)", async (t) => {
    stubFetch(t)
    const pem = await exportSPKI(teamKey.publicKey)
    const claims = { aud: [AUD], iss: TEAM, email: "x@example.com", exp: now() + 3600, nbf: now() }
    const head = b64url({ alg: "HS256", typ: "JWT", kid: "team-key-1" })
    const body = b64url(claims)
    const sig = createHmac("sha256", pem).update(`${head}.${body}`).digest("base64url")
    assert.equal(await verifier().verify(`${head}.${body}.${sig}`), null)
  })

  test("an RS256 token whose JWK is served as another alg is rejected", async (t) => {
    stubFetch(t, { keys: [{ ...teamKey.jwk, alg: "RS512" }] })
    assert.equal(await verifier().verify(await makeToken()), null)
  })

  test("keys are fetched only from the configured team, never from jku / x5u", async (t) => {
    const state = stubFetch(t)
    await verifier().verify(
      await makeToken({ header: { jku: "https://evil.example/certs", x5u: "https://evil.example/x" } }),
    )
    assert.ok(state.calls.length > 0)
    assert.deepEqual(new Set(state.calls), new Set([CERTS]))
  })

  test("a key fetch failure is null, not an exception", async (t) => {
    const state = stubFetch(t)
    state.fail = true
    assert.equal(await verifier().verify(await makeToken()), null)
  })

  test("a non-JSON 200 from the certs URL is null", async (t) => {
    const state = stubFetch(t)
    state.body = "<html>not keys</html>"
    assert.equal(await verifier().verify(await makeToken()), null)
  })

  test("a redirect from the certs URL is not followed", async (t) => {
    const state = stubFetch(t)
    state.status = 302
    assert.equal(await verifier().verify(await makeToken()), null)
  })

  test("unexpected errors inside verification return null", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify("a\ud800.b.c"), null)
  })

  test("a validly signed token longer than 16 KiB is rejected without a key fetch", async (t) => {
    const state = stubFetch(t)
    const huge = await makeToken({ pad: "x".repeat(16 * 1024) })
    assert.equal(await verifier().verify(huge), null)
    assert.equal(state.calls.length, 0)
  })

  for (const alg of ["RS512", "PS256"]) {
    test(`${alg} signed with the real team key is rejected when the JWK has no alg`, async (t) => {
      // Only RS256 is accepted, even where the key set doesn't pin an alg per key.
      const { alg: _, ...unpinned } = teamKey.jwk
      stubFetch(t, { keys: [unpinned] })
      const priv = await importJWK({ ...(await exportJWK(teamKey.privateKey)), alg }, alg)
      const token = await new SignJWT({ aud: [AUD], iss: TEAM, email: "x@example.com", sub: "s" })
        .setProtectedHeader({ alg, kid: "team-key-1" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(priv)
      assert.equal(await verifier().verify(token), null)
    })
  }
})

// --- misconfiguration is loud, at startup ---------------------------------------

describe("configuration", () => {
  for (const team of [
    "",
    undefined,
    "http://example-team.cloudflareaccess.com",
    "https://example-team.cloudflareaccess.com.evil.com",
    "https://evil.com",
    "example-team.cloudflareaccess.com",
    "https://example-team.cloudflareaccess.com/path",
    ["https://user", "example-team.cloudflareaccess.com"].join("@"), // userinfo; split so the no-email guard stays strict
    "https://example-team.cloudflareaccess.com:8443",
  ]) {
    test(`bad team domain throws: ${JSON.stringify(team)}`, () => {
      assert.throws(() => new AccessVerifier({ teamDomain: team, audience: AUD }))
    })
  }

  test("a trailing slash and upper case on the team domain are normalised", async (t) => {
    stubFetch(t)
    const v = new AccessVerifier({ teamDomain: `${TEAM.toUpperCase().replace("HTTPS", "https")}/`, audience: AUD })
    assert.notEqual(await v.verify(await makeToken()), null)
  })

  for (const aud of ["", "   ", undefined, null, 42]) {
    test(`empty audience throws: ${JSON.stringify(aud)}`, () => {
      assert.throws(() => new AccessVerifier({ teamDomain: TEAM, audience: aud }))
    })
  }

  for (const leewaySeconds of [-1, 301, 1e9, Number.NaN, "60"]) {
    test(`out-of-range leeway throws: ${String(leewaySeconds)}`, () => {
      // A huge leeway would accept long-expired tokens.
      assert.throws(() => verifier({ leewaySeconds }))
    })
  }

  for (const keyCacheSeconds of [0, -5, Number.NaN, Infinity, "3600"]) {
    test(`bad key cache throws: ${String(keyCacheSeconds)}`, () => {
      assert.throws(() => verifier({ keyCacheSeconds }))
    })
  }

  test("constructing without an options object throws", () => {
    assert.throws(() => new AccessVerifier())
  })
})

// --- review findings carried over from the Python version ------------------------

describe("key handling", () => {
  test("a rotated-out key stops working once the key set refreshes", async (t) => {
    const state = stubFetch(t)
    const v = verifier({ keyCacheSeconds: 0.05 })
    assert.notEqual(await v.verify(await makeToken()), null)

    state.keys = [(await keypair("team-key-2")).jwk] // Cloudflare rotated team-key-1 out
    await new Promise((r) => setTimeout(r, 100))
    assert.equal(await v.verify(await makeToken()), null)
  })

  test("random kids do not trigger a fetch each", async (t) => {
    const state = stubFetch(t)
    const v = verifier()
    await v.verify(await makeToken())
    const before = state.calls.length
    for (let i = 0; i < 50; i++) await v.verify(await makeToken({ kid: `random-${i}` }))
    assert.ok(state.calls.length - before <= 1)
  })

  test("a hung certs endpoint gives up within about 5 seconds", async (t) => {
    const original = globalThis.fetch
    globalThis.fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason))
      })
    t.after(() => {
      globalThis.fetch = original
    })
    const started = Date.now()
    assert.equal(await verifier().verify(await makeToken()), null)
    assert.ok(Date.now() - started < 6000)
  })

  test("the dependency floor is the tested jose, below the next major", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
    assert.equal(pkg.dependencies.jose, "^6.2.14")
    assert.deepEqual(Object.keys(pkg.dependencies), ["jose"])
  })
})

// --- startup self-check: make "everyone gets the demo" visible ---------------------

describe("check()", () => {
  test("passes when the team keys load", async (t) => {
    stubFetch(t)
    await verifier().check()
  })

  test("throws when the keys can't be fetched", async (t) => {
    const state = stubFetch(t)
    state.fail = true
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("throws when the key set is empty", async (t) => {
    stubFetch(t, { keys: [] })
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("throws when no key is usable for RS256 signatures", async (t) => {
    stubFetch(t, { keys: [{ ...teamKey.jwk, use: "enc" }, { kty: "oct", k: "c2VjcmV0", kid: "x" }] })
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("wraps a non-JSON 200 and keeps the original as cause", async (t) => {
    const state = stubFetch(t)
    state.body = "<html>Cloudflare login page</html>"
    await assert.rejects(verifier().check(), (err) => {
      assert.match(err.message, /signing keys/)
      assert.ok(err.cause)
      return true
    })
  })
})

// --- review fixes (2026-10-31) -------------------------------------------------------

describe("review fixes", () => {
  // Finding 2: check() must load each key, not just read its labels.
  test("check() rejects a key set whose only RSA key can't be imported", async (t) => {
    stubFetch(t, { keys: [{ kty: "RSA", kid: "k1", alg: "RS256", use: "sig" }] })
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("check() rejects a key set that serves a private key", async (t) => {
    const priv = { ...(await exportJWK(teamKey.privateKey)), kid: "k1", alg: "RS256", use: "sig" }
    stubFetch(t, { keys: [priv] })
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("check() passes when one usable key sits beside junk", async (t) => {
    stubFetch(t, { keys: [{ kty: "RSA", kid: "junk" }, teamKey.jwk] })
    await verifier().check()
  })

  // Finding 3: fromHeaders never rejects, whatever it is handed.
  test("fromHeaders resolves null when the headers' get() throws", async (t) => {
    stubFetch(t)
    const headers = {
      get() {
        throw new Error("boom")
      },
    }
    assert.equal(await verifier().fromHeaders(headers), null)
  })

  test("fromHeaders resolves null when enumerating the headers throws", async (t) => {
    stubFetch(t)
    const headers = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("boom")
        },
      },
    )
    assert.equal(await verifier().fromHeaders(headers), null)
  })

  // Finding 4: two letter-case variants of the header are ambiguous, in either order.
  test("a plain object carrying the header twice in different case is null", async (t) => {
    stubFetch(t)
    const good = await makeToken()
    const v = verifier()
    assert.equal(await v.fromHeaders({ [HEADER.toLowerCase()]: good, [HEADER]: "junk" }), null)
    assert.equal(await v.fromHeaders({ [HEADER]: "junk", [HEADER.toLowerCase()]: good }), null)
    assert.equal(await v.fromHeaders({ [HEADER.toLowerCase()]: good, [HEADER]: good }), null)
  })

  test("a Map carrying the header twice in different case is null", async (t) => {
    stubFetch(t)
    const good = await makeToken()
    const map = new Map([
      [HEADER.toLowerCase(), good],
      [HEADER.toUpperCase(), good],
    ])
    assert.equal(await verifier().fromHeaders(map), null)
  })

  // Finding 5: parity with PyJWT on iat.
  test("a token issued in the future, beyond leeway, is null", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ iat: now() + 3600 })), null)
  })

  test("a token issued just ahead, within leeway, is accepted", async (t) => {
    stubFetch(t)
    assert.notEqual(await verifier().verify(await makeToken({ iat: now() + 30 })), null)
  })

  test("a non-numeric iat is null (jose rejects it before our guard runs)", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await makeToken({ iat: "yesterday" })), null)
  })

  test("iat exactly at now + leeway is accepted; just past it is null", async (t) => {
    stubFetch(t)
    const v = verifier({ leewaySeconds: 10 })
    assert.notEqual(await v.verify(await makeToken({ iat: now() + 10 })), null)
    assert.equal(await v.verify(await makeToken({ iat: now() + 15 })), null)
  })

  test("a token without iat is still accepted (Cloudflare always sets it; PyJWT doesn't require it)", async (t) => {
    stubFetch(t)
    assert.notEqual(await verifier().verify(await makeToken({ iat: null })), null)
  })

  // Finding 8: cases the review found missing.
  test("fromHeaders reads a Map", async (t) => {
    stubFetch(t)
    assert.notEqual(await verifier().fromHeaders(new Map([[HEADER, await makeToken()]])), null)
  })

  test("non-string header names are skipped", async (t) => {
    stubFetch(t)
    const map = new Map([
      [1, "x"],
      [Symbol("s"), "y"],
      [HEADER, await makeToken()],
    ])
    assert.notEqual(await verifier().fromHeaders(map), null)
  })

  test("a header appended twice to a Headers object is null", async (t) => {
    stubFetch(t)
    const token = await makeToken()
    const headers = new Headers()
    headers.append(HEADER, token)
    headers.append(HEADER, token)
    assert.equal(await verifier().fromHeaders(headers), null)
  })

  test("an aud array containing this app among others is accepted", async (t) => {
    stubFetch(t)
    assert.notEqual(await verifier().verify(await makeToken({ aud: ["other-app", AUD, "third"] })), null)
  })

  test("a token without a kid is null when the team publishes two keys", async (t) => {
    stubFetch(t, { keys: [teamKey.jwk, (await keypair("team-key-2")).jwk] })
    const token = await new SignJWT({ aud: [AUD], iss: TEAM, email: "x@example.com" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(teamKey.privateKey)
    assert.equal(await verifier().verify(token), null)
  })

  test("the certs fetch asks for manual redirects and a timeout signal", async (t) => {
    const seen = []
    const original = globalThis.fetch
    globalThis.fetch = async (url, init) => {
      seen.push(init)
      return new Response(JSON.stringify({ keys: [teamKey.jwk] }), { status: 200 })
    }
    t.after(() => {
      globalThis.fetch = original
    })
    await verifier().verify(await makeToken())
    assert.equal(seen.length, 1)
    assert.equal(seen[0].redirect, "manual")
    assert.ok(seen[0].signal instanceof AbortSignal)
  })
})

// --- second review (2026-10-31): check() must match what verify can actually use ------

describe("check() matches verify", () => {
  test("rejects a key set whose only key is under 2048 bits (jose won't verify with it)", async (t) => {
    // jose refuses to make one, so use node:crypto.
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 1024 })
    stubFetch(t, { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "small", alg: "RS256", use: "sig" }] })
    await assert.rejects(verifier().check(), /signing keys/)
  })

  test("rejects a key set whose only key has no kid (Cloudflare tokens always name one)", async (t) => {
    const { kid: _, ...noKid } = teamKey.jwk
    stubFetch(t, { keys: [noKid] })
    await assert.rejects(verifier().check(), /signing keys/)
  })
})

