// Compile-only: the published types describe how apps actually call gatekeeper-ts.
import { AccessVerifier, HEADER, type Identity } from "../../index.js"

const verifier = new AccessVerifier({ teamDomain: "https://your-team.cloudflareaccess.com", audience: "aud" })
const fromNext: Promise<Identity | null> = verifier.fromHeaders(new Headers())
const fromNode: Promise<Identity | null> = verifier.fromHeaders({ "cf-access-jwt-assertion": "t", cookie: undefined })
const direct: Promise<Identity | null> = verifier.verify("token")
const started: Promise<void> = verifier.check()
const name: "Cf-Access-Jwt-Assertion" = HEADER

async function use() {
  const id = await verifier.verify(null)
  if (id) {
    const email: string = id.email
    // @ts-expect-error identities are read-only
    id.email = "x"
    void email
  }
}
// @ts-expect-error audience is required
new AccessVerifier({ teamDomain: "https://your-team.cloudflareaccess.com" })
void [fromNext, fromNode, direct, started, name, use]
