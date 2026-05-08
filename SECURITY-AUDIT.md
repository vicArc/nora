# NORA Security Audit

**Version:** 0.8.3
**Audit date:** 2026-05-08
**Scope:** Static analysis of source code and supply chain

## Summary

Based on this static audit, **the project is safe to deploy on production
servers**. No signs of hidden malicious code, obfuscated payloads, covert
channels, or off-target network communication were found. The codebase is
fully consistent with its stated goal: a multi-protocol artifact registry.

## Audit scope

All files matching `*.rs`, `*.sh`, `*.toml`, `*.yml`, `*.yaml`, `*.json`,
`*.py`, `*.ts`, `*.js`, `Dockerfile*`, `Makefile`, `*.md` were scanned across
`nora-registry/`, `scripts/`, `fuzz/`, `tests/`, `.github/`, `deploy/`, and
`docs-ru/`. The `target/` and `node_modules/` directories were excluded.

The following vectors were inspected:

- hidden non-printable and BiDi Unicode characters;
- abnormally long single-line constructs (potential obfuscated payloads);
- use of `unsafe` Rust;
- subprocess execution and shell injection;
- hardcoded network endpoints;
- embedded binary or encoded blobs;
- dependency supply chain (`Cargo.lock`, git dependencies, submodules);
- build scripts (`build.rs`, `scripts/`, Dockerfile);
- GitHub Actions workflows.

## Vector-by-vector results

| Vector | Result |
|---|---|
| Hidden Unicode characters (ZWSP, ZWNJ, ZWJ, BOM, LRE/RLE/PDF, LRO/RLO, LRI/RLI/FSI/PDI, soft hyphen, MVS) | 0 hits |
| Suspiciously long lines (>1000 chars) | 7 hits, all in `nora-registry/src/ui/components.rs:117–694` — inline SVG `<path d="…">` data for registry icons (Docker, Maven, npm, Cargo, PyPI). Benign UI code. |
| `unsafe` Rust blocks | 0. `#![forbid(unsafe_code)]` is enforced in `lib.rs` and `main.rs`. |
| Subprocess execution (`Command::new`, `eval`, `exec`, `/bin/sh`) | None. Only `std::process::exit(N)` calls in CLI error paths and `env::set_var` inside `#[cfg(test)]` blocks. |
| Hardcoded external endpoints | All 50+ hosts are legitimate package-registry upstreams (auth.docker.io, crates.io, registry.npmjs.org, pypi.org, proxy.golang.org, repo1.maven.org, rubygems.org, registry.terraform.io, galaxy.ansible.com, api.nuget.org, pub.dev, center2.conan.io) or project-owned domains (getnora.dev, github.com). No paste sites, beacons, or personal domains. |
| `Cargo.lock` supply chain | 392 packages, **all** sourced from `registry+https://github.com/rust-lang/crates.io-index`. No `git+` dependencies, no patched sources, no git submodules. |
| Banned crates (`deny.toml`) | Active ban on `openssl`/`openssl-sys` (forces rustls). License allowlist is conservative. |
| Embedded binary assets | `logo.jpg` (6 KB, valid JPEG), `htmx.min.js` (47 KB, minified UMD — structure consistent with the genuine htmx library; recommend verifying SHA‑256 `b3bdcf5c741897a53648b1207fff0469a0d61901429ba1f6e88f98ebd84e669e` against the official release), `tailwind.css` (17 KB, plain CSS). |
| Build scripts | No `build.rs` in the workspace — compile-time code execution is excluded. |
| Dockerfile | Multi-stage build, drops to non-root `nora` user, no `curl \| sh` patterns, healthchecks loopback only. |
| `scripts/` directory | `coherence-check.sh`, `lock-audit.sh`, `pre-commit-check.sh`, `install-hooks.sh`, `verify-changelog.sh`, `diff-registry.sh`, `post-release-gate.sh` perform exactly the functions they claim (version sync, concurrency lock auditing, git hook installation). No outbound network calls. |

## Positive security signals

- CI runs **gitleaks** (secret scanning), **cargo-audit** (RustSec CVEs),
  **cargo-deny** (licenses + banned crates), **Trivy** (filesystem CVE scan),
  **CodeQL**, and **OpenSSF Scorecard**.
- Most third-party GitHub Actions are pinned by SHA rather than tag.
- `#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used)]` apply at the
  crate root.
- Path traversal trust boundary `validation::validate_storage_key()` is
  invoked by every registry handler before any storage operation.
- Curation is fail-closed: if the curation engine errors, the request is
  blocked rather than allowed through.

## Hygiene observations (not threats)

1. `obi1kenobi/cargo-semver-checks-action@v2` in `.github/workflows/ci.yml`
   is pinned by tag, not SHA — inconsistent with the rest of the file.
   Recommend replacing with a SHA pin.
2. `tests/e2e/package-lock.json` is in `.gitignore`. Playwright e2e resolves
   `@playwright/test ^1.50.0` afresh on each CI run. Minor reproducibility
   risk for the test harness; the shipped binary is unaffected.
3. `htmx.min.js` is committed directly. Recommend verifying SHA‑256 against
   the official htmx release, or switching to a fetch step protected by an
   SRI hash.

## Conclusion

Nothing in this static review contradicts the project's stated functionality:
no obfuscated payloads, no covert channels, no unexpected compile-time
execution, no suspicious network destinations, no hidden Unicode tricks.
**Production deployment is safe** subject to standard operational hygiene:
authentication enabled, TLS termination at a reverse proxy, and an egress
network policy in place.
