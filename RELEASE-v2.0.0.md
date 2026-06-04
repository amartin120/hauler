# Hauler v2.0.0 — Release Overview

**Comparison base:** `v1.4.3` → `main`

v2.0.0 is a **major** release. It replaces Hauler's entire OCI plumbing — the ORAS v1
dependency and the in-house cosign fork — with a native containerd-based implementation,
drops the deprecated `v1alpha1` API, and layers on a meaningful set of new capabilities
and reliability fixes on top of that new foundation.

---

## 🏗️ The Big Overhaul — #515

> *"over-haul: replace ORAS v1 and the cosign fork with a native containerd-based implementation"*

On the surface this is a "no new features" refactor — but it's the cornerstone of the
release and the primary justification for the major version bump. It touched 28 files
(~2,300 insertions).

### What changed

- **Removed the ORAS v1 dependency** — push/pull is now driven directly by containerd's
  docker resolver and `google/go-containerregistry`. A new `pkg/content/registry.go`
  (`RegistryTarget`) and `pkg/content/types.go` (`Target` interface, `IoContentWriter`)
  replace what ORAS used to own.
- **Removed the hauler-maintained cosign fork** — `pkg/cosign` is now a thin verify-only
  wrapper around upstream `sigstore/cosign/v3`. Images are added through a native
  `s.AddImage()` path in `pkg/store`.
- **Added OCI 1.1 Referrers support** — signatures, attestations, and SBOMs are discovered
  both via the classic cosign tag convention (`sha256-<hex>.sig` / `.att` / `.sbom`) and
  the modern Referrers API, then round-tripped correctly through the OCI layout.

### Why it matters

- **We own the copy path now.** Because `store copy registry://` is no longer black-boxed
  inside cosign, this release was able to add **per-artifact retry logic** (`pkg/retry`,
  `--retries` / `--ignore-errors`) and **per-blob progress logging** (`pushed blob` /
  `existing blob`, plus a completion line per artifact). That control simply wasn't
  possible while cosign owned the transfer loop.
- **No more fork maintenance burden.** Tracking upstream cosign no longer means maintaining
  a divergent fork — we consume `sigstore/cosign/v3` directly and stay current on security
  fixes without the extra effort.
- **Standards-forward signature handling.** Supporting both legacy cosign tags and OCI 1.1
  referrers means hauls produced today remain compatible with both older Hauler versions
  and modern registries that wire up referrers natively.
- **A cleaner internal contract.** The new `Target` interface and containerd resolver give
  every command (`add`, `sync`, `copy`, `save`, `serve`) a single, consistent transfer
  abstraction — which is exactly what made the smaller features below cheap to build.

---

## ✨ New Features

| PR | Feature | What it does |
|----|---------|--------------|
| **#551** | **Add images from a local Docker daemon** | `hauler store add image` can now pull straight from the local Docker daemon using the `--local` flag, not just remote registries — handy for air-gapping locally-built images. |
| **#519** | **Chunked hauls** | If there are size constraints on what can be brought into the airgap, Hauler can now chunk the haul into specified sizes during `hauler store save` and rejoin them on `hauler store load` . The `--chunk-size` flag accepts inputs as byte sizes, such as `1TB`, `500MB`, etc and will save multiple files not exceeding the specified size. When loaded, Hauler will automatically detect the files and join them back to one store. This is not compatible with the `--containerd` flag.|
| **#538** | **Native `images.txt` sync** | `hauler store sync` now has the option to sync artifacts from an images.txt file directly. The flag `--image-txt` allows you to pass an image list as a local or remote file, and Hauler will iterate over the list and add everything to your store. This is convenient for products that provide an images.txt file as a release artifact, but may not have a Hauler manifest available. |
| **#541** | **Exclude extra artifacts on pull** | A flag `--exclude-extras` (for both images and charts) to skip pulling associated sigs/atts/SBOMs/referrers when you only want the artifact itself — smaller, faster hauls. |
| **#547** | **`--dry-run` for `sync --products`** | Preview exactly what a product sync would fetch before committing to the transfer. |
| **#532** | **Multiple prefix references** | Allows specifying more than one prefix reference (with de-duplication), improving flexibility when remapping repositories. |

*Dev tooling: #577 added a `make` target for vulnerability scanning.*

---

## 🐛 Bug Fixes

| PR | Fix |
|----|-----|
| **#604** | **Adjust regex for image detection within charts** — to allow hyphen in image property |
| **#618 / #411** | **Special-characters fix** — adds regex filtering in `store copy` to skip invalid filenames that previously broke `hauler store serve`. |
| **#529** | **Fix `extract` for OCI files** — plus a guard against path-traversal during extraction. |
| **#531** | **`extract` now handles image indexes** correctly (multi-arch), not just single manifests. |
| **#537** | **Fix `--keep-registry` logic** — including correctly trimming the implicit `library/` prefix. |
| **#534** | **Fix Docker Hub default-host bug** — correct default registry resolution. |
| **#535** | **`kind` annotation no longer hard-codes cosign** — descriptor `kind` values are now neutral/correct. |
| **#514** | **File-referenced chart dependencies without a `repository` field** are now handled correctly. |
| **#575** | **Cleaner logging** when extracting OCI artifacts that carry cosign bits. |
| **#572** | **Removed an unnecessary `rewrite` flag** from `sync`. |
| **#553** | **Handle large diffs** passed to the `gh api` (CI tooling). |

---

## ⚠️ Breaking Changes

- **#528 — Removed deprecated code and dropped all `v1alpha1` API support.** Manifests using
  `apiVersion: hauler.cattle.io/v1alpha1` will no longer be accepted; users must migrate to
  `hauler.cattle.io/v1`.
- The **ORAS v1** and **cosign-fork** removals (#515) are internal, but any downstream tooling
  that depended on Hauler's forked cosign behavior should be re-validated.

---

## 🔧 Maintenance & Dependencies

- **Quality / CI:** improved test coverage (#530), verified/signed commits + better messages
  (#550), Dependabot config (#585), Mergify replacing the cherry-pick bot (#581, #533),
  workflow fixes (#574), a `dev.md` contributor guide (#521).
- **Notable dependency bumps:** Go → **1.26.0**; `sigstore/cosign/v3` → 3.1.1;
  `containerd` → 1.7.33; `go-containerregistry` → 0.21.7; `helm/v3` → 3.21.2;
  `in-toto-golang` → 0.11.0; plus grpc, otel, docker/cli, go-jose, and zerolog.


## 📒 Full Changelog:
- https://github.com/hauler-dev/hauler/compare/v1.4.3...v2.0.0