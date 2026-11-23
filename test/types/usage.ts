// Compile-only: the published types describe how apps actually call gatekeeper-ts.
import { AccessVerifier, HEADER, type Identity, type ServiceIdentity } from "../../index.js"

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
async function useService() {
  const fromHeaders: ServiceIdentity | null = await verifier.serviceFromHeaders(new Headers())
  const svc = await verifier.verifyService("token")
  if (svc) {
    const id: string = svc.commonName
    // @ts-expect-error service identities are read-only
    svc.commonName = "x"
    // @ts-expect-error a service identity carries no email
    void svc.email
    void id
  }
  void fromHeaders
}
// @ts-expect-error audience is required
new AccessVerifier({ teamDomain: "https://your-team.cloudflareaccess.com" })
void [fromNext, fromNode, direct, started, name, use, useService]
