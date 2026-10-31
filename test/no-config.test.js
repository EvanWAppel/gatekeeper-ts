// This public repo carries no team name, app tag, or email of a real person.
// Ported from gatekeeper (Python) tests/test_no_config_in_repo.py.
import assert from "node:assert/strict"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

const ROOT = fileURLToPath(new URL("..", import.meta.url))
const SKIP_DIRS = new Set([".git", "node_modules"])
const SKIP_FILES = new Set(["no-config.test.js"])

const TEAM_DOMAIN = /([a-z0-9-]+)\.cloudflareaccess\.com/gi
const ALLOWED_TEAMS = new Set(["example-team", "your-team", "evil"])
const EMAIL = /[\w.+-]+@([\w-]+\.[\w.-]+)/g
const ALLOWED_EMAIL_DOMAINS = new Set(["example.com", "users.noreply.github.com"])
// Access AUD tags are 64 hex chars.
const AUD_TAG = /\b[0-9a-f]{64}\b/

function* files(dir = ROOT) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      if (!SKIP_DIRS.has(name)) yield* files(path)
    } else if (!SKIP_FILES.has(name)) {
      yield path
    }
  }
}

const text = (path) => readFileSync(path, "utf8")

test("no real team domain or email anywhere", () => {
  const leaks = []
  for (const p of files()) {
    for (const m of text(p).matchAll(TEAM_DOMAIN))
      if (!ALLOWED_TEAMS.has(m[1].toLowerCase())) leaks.push(`${relative(ROOT, p)}: ${m[0]}`)
    for (const m of text(p).matchAll(EMAIL)) {
      const domain = m[1].toLowerCase()
      if (!ALLOWED_EMAIL_DOMAINS.has(domain) && !domain.endsWith(".noreply.github.com"))
        leaks.push(`${relative(ROOT, p)}: ${m[0]}`)
    }
  }
  assert.deepEqual(leaks, [])
})

test("no AUD tag outside lockfile integrity hashes", () => {
  const leaks = []
  for (const p of files()) {
    text(p)
      .split("\n")
      .forEach((line, i) => {
        if (AUD_TAG.test(line) && !(p.endsWith("package-lock.json") && line.includes('"integrity"')))
          leaks.push(`${relative(ROOT, p)}:${i + 1}`)
      })
  }
  assert.deepEqual(leaks, [])
})

test("the lockfile only resolves from the public npm registry", () => {
  const lock = JSON.parse(text(join(ROOT, "package-lock.json")))
  const hosts = new Set()
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === "") continue
    assert.ok(entry.resolved, `${path} has no resolved URL`)
    assert.ok(entry.integrity, `${path} has no integrity hash`)
    hosts.add(new URL(entry.resolved).origin)
    assert.ok(!/\/\/[^/]*@/.test(entry.resolved), `${path} has credentials in its URL`)
  }
  assert.deepEqual(hosts, new Set(["https://registry.npmjs.org"]))
})

test("the repo has its own .gitignore", () => {
  const ignored = new Set(text(join(ROOT, ".gitignore")).split(/\s+/))
  assert.ok(ignored.has("node_modules/"))
})

test("the package ships only the reviewed files", () => {
  const pkg = JSON.parse(text(join(ROOT, "package.json")))
  assert.deepEqual(pkg.files, ["index.js", "index.d.ts"])
  assert.equal(pkg.scripts.prepare, undefined) // no install-time scripts in apps
  assert.equal(pkg.scripts.postinstall, undefined)
  assert.equal(pkg.scripts.install, undefined)
})
