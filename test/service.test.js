// Service tokens: a machine (not a person) let through by an Access "Service Auth" policy.
// verifyService runs the same signature, iss, exp and aud checks as verify, and returns only
// the token's common_name (the service token's client id). verify still refuses these tokens,
// and verifyService refuses people's tokens, so neither path can stand in for the other.
import assert from "node:assert/strict"
import { describe, test } from "node:test"

import { AccessVerifier, HEADER } from "../index.js"
import { AUD, TEAM, attackerKey, makeToken, stubFetch } from "./helpers.js"

const now = () => Math.floor(Date.now() / 1000)
const verifier = (opts = {}) => new AccessVerifier({ teamDomain: TEAM, audience: AUD, ...opts })
const CLIENT_ID = "0123456789abcdef.access"

// Cloudflare's service-token claims: no email, an empty sub, the client id as common_name.
const serviceToken = (claims = {}) =>
  makeToken({ email: null, sub: "", common_name: CLIENT_ID, type: "app", ...claims })

describe("verifyService: the one way in", () => {
  test("a valid service token returns its common_name and nothing else", async (t) => {
    stubFetch(t)
    assert.deepEqual(await verifier().verifyService(await serviceToken()), { commonName: CLIENT_ID })
  })

  test("the returned service identity is frozen", async (t) => {
    stubFetch(t)
    assert.ok(Object.isFrozen(await verifier().verifyService(await serviceToken())))
  })

  test("serviceFromHeaders reads a Headers object and a plain object, any letter case", async (t) => {
    stubFetch(t)
    const v = verifier()
    assert.notEqual(await v.serviceFromHeaders(new Headers({ [HEADER]: await serviceToken() })), null)
    assert.notEqual(await v.serviceFromHeaders({ [HEADER.toLowerCase()]: await serviceToken() }), null)
  })
})

describe("verifyService: everything else is null", () => {
  for (const token of [undefined, null, "", "   ", "not-a-jwt", "a.b.c", 42, {}]) {
    test(`missing or garbage token: ${JSON.stringify(token)}`, async (t) => {
      stubFetch(t)
      assert.equal(await verifier().verifyService(token), null)
    })
  }

  const cases = {
    "signed by another key with the same kid": { key: attackerKey.privateKey },
    "wrong audience (another Access app's token)": { aud: ["some-other-app"] },
    "missing audience": { aud: null },
    "wrong issuer": { iss: "https://evil.cloudflareaccess.com" },
    "missing issuer": { iss: null },
    "expired": { exp: now() - 3600, iat: now() - 7200, nbf: now() - 7200 },
    "missing expiry": { exp: null },
    "not yet valid": { nbf: now() + 3600 },
    "issued in the future, beyond leeway": { iat: now() + 3600 },
    "missing common_name": { common_name: null },
    "empty common_name": { common_name: "" },
    "non-string common_name": { common_name: 42 },
    "a person's token (has an email) is not a service token": { email: "someone@example.com" },
    "a person's token with a common_name is still not a service token": {
      email: "someone@example.com",
      sub: "user-123",
    },
  }
  for (const [name, claims] of Object.entries(cases)) {
    test(name, async (t) => {
      stubFetch(t)
      assert.equal(await verifier().verifyService(await serviceToken(claims)), null)
    })
  }

  test("an empty-string email still counts as a person's claim and is refused", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verifyService(await serviceToken({ email: "" })), null)
  })

  test("a key fetch failure is null, not an exception", async (t) => {
    stubFetch(t).fail = true
    assert.equal(await verifier().verifyService(await serviceToken()), null)
  })

  test("serviceFromHeaders: missing header, repeated header, throwing headers are null", async (t) => {
    stubFetch(t)
    const v = verifier()
    const token = await serviceToken()
    assert.equal(await v.serviceFromHeaders({}), null)
    assert.equal(await v.serviceFromHeaders({ [HEADER]: token, [HEADER.toLowerCase()]: token }), null)
    assert.equal(await v.serviceFromHeaders({ [HEADER]: [token, token] }), null)
    const throwing = {
      get() {
        throw new Error("boom")
      },
    }
    assert.equal(await v.serviceFromHeaders(throwing), null)
    assert.equal(await v.serviceFromHeaders(null), null)
  })
})

describe("the two paths stay apart", () => {
  test("verify still refuses a valid service token", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verify(await serviceToken()), null)
  })

  test("fromHeaders still refuses a valid service token", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().fromHeaders({ [HEADER]: await serviceToken() }), null)
  })

  test("verifyService refuses a valid person token", async (t) => {
    stubFetch(t)
    assert.equal(await verifier().verifyService(await makeToken()), null)
  })
})
