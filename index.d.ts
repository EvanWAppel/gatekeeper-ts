/** The header Cloudflare Access adds to every request it lets through. */
export declare const HEADER: "Cf-Access-Jwt-Assertion"

/** A signed-in visitor, from a verified Access token. */
export interface Identity {
  readonly email: string
  readonly subject: string
}

export interface AccessVerifierOptions {
  /** https://<team>.cloudflareaccess.com (Zero Trust → Settings). */
  teamDomain: string
  /** The app's Application Audience (AUD) tag (Access → the app → Overview). */
  audience: string
  /** Clock skew allowed on exp, nbf and iat, 0–300 seconds. Default 60. */
  leewaySeconds?: number
  /** How long the team's key set is trusted before it is refetched. Default 3600. */
  keyCacheSeconds?: number
}

/** Anything a request's headers commonly come as. */
export type HeadersInput =
  | { get(name: string): string | null }
  | Map<string, string>
  | Record<string, string | string[] | undefined>

export declare class AccessVerifier {
  /** Throws on bad configuration, so it fails at startup, not quietly per request. */
  constructor(options: AccessVerifierOptions)
  /** Rejects unless a team signing key is a usable RS256 public key (≥2048 bits, has a kid). Await once at startup and log. */
  check(): Promise<void>
  /** The identity for a valid token, else null. Never rejects. */
  verify(token: unknown): Promise<Identity | null>
  /** verify the Access header from a request's headers (any letter case; sent twice → null). Never rejects. */
  fromHeaders(headers: HeadersInput | null | undefined): Promise<Identity | null>
}
