# gatekeeper-ts

Verify Cloudflare Access tokens so an app can tell **a signed-in visitor** from **everyone
else**. The TypeScript/JavaScript port of
[gatekeeper](https://github.com/EvanWAppel/gatekeeper): same checks, same tests, same review bar.

Cloudflare Access adds a signed JWT (`Cf-Access-Jwt-Assertion`) to every request it lets
through. `AccessVerifier` resolves to an `Identity` only when that token is:

- signed with **RS256** by a key fetched from **your team's** certs endpoint (any `jku` / `x5u`
  in the token is ignored; `alg: none`, HMAC and other RSA algorithms are rejected; redirects
  from the certs URL are not followed; a key Cloudflare rotates out stops working on the next
  key-set refresh, hourly by default),
- issued by your team (`iss`), meant for this app (`aud`), and in date (`exp`, `nbf`),
- carrying an `email` (service tokens are not people),
- under 16 KiB.

Everything else (no header, a repeated header, a forged or expired token, Cloudflare
unreachable) resolves to `null`. Show the private version only on an `Identity`, and every
failure lands on the public side.

Bad configuration throws when the verifier is built, so it fails at startup, not quietly per
request.

Plain ESM JavaScript with hand-written types and no build step: the reviewed code is exactly
the code that runs. One runtime dependency, [`jose`](https://github.com/panva/jose).

## Use

Pin an exact commit, so an update can only arrive through a reviewed change in your app:

```sh
npm install github:EvanWAppel/gatekeeper-ts#<commit-sha>
pnpm add github:EvanWAppel/gatekeeper-ts#<commit-sha>
```

```ts
import { AccessVerifier } from "gatekeeper-ts"

const verifier = new AccessVerifier({
  teamDomain: process.env.CF_ACCESS_TEAM_DOMAIN!, // https://<team>.cloudflareaccess.com
  audience: process.env.CF_ACCESS_AUD!,           // the app's Application Audience tag
})
```

At startup, `await verifier.check()` and log the error it throws if the team's keys can't be
loaded. Otherwise a broken environment looks exactly like "nobody is signed in".

Next.js (16+, `proxy.ts`), guarding the same paths as the Access app:

```ts
import { NextResponse, type NextRequest } from "next/server"

export async function proxy(request: NextRequest) {
  const identity = await verifier.fromHeaders(request.headers)
  if (!identity) return new NextResponse("Forbidden", { status: 403 })
  return NextResponse.next()
}

export const config = { matcher: ["/settings/:path*", "/api/settings/:path*"] }
```

Keep the `matcher` and the Access app's paths in step: a path in one and not the other is
either unguarded by the app or unreachable through Cloudflare.

Any framework: pass the request's headers (a `Headers`, a `Map`, or a plain object such as
Node's `req.headers`) to `fromHeaders`, or the header value to `verify`.

## What this does not do

- **It is not the gate for apps without a public version.** Close the platform URL too
  (`*.vercel.app`, `*.up.railway.app`), or visitors can skip Cloudflare entirely.
- **It is not the allowlist.** Who may sign in lives in the Access policy. An app that wants a
  second check compares `identity.email` to its own owner setting.
- **It holds no configuration.** Team domain and AUD come from each app's environment. A test
  fails if a real team domain, AUD tag or email lands in this repo.

## Develop

```sh
npm ci
npm test
npm run typecheck
```
