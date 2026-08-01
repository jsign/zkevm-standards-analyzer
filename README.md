# zkEVM Standards Analyzer

Evidence dashboard for the published guest-program ELFs in
[`eth-act/ere-guests`](https://github.com/eth-act/ere-guests), evaluated against
the standards merged into
[`eth-act/zkevm-standards/main`](https://github.com/eth-act/zkevm-standards).

The published dashboard is expected at
<https://jsign.github.io/zkevm-standards-analyzer/>.

This project reports atomic evidence—passes, failures, warnings, unknowns, and
non-applicable requirements. It does not calculate a compliance score and does
not certify an ELF or zkVM.

## What v1 analyzes

- Release-asset identity and SHA-256, including comparison with GitHub's asset
  digest when one is published.
- ELF class, endianness, machine, type, static linkage, load ranges, segment
  layout and permissions, entry point, visible `_start`/`main` symbols, section
  separation, and RISC-V attributes.
- File/load sizes, executable/read-only/writable bytes, BSS zero fill, header
  and symbol counts, stripping/debug state, and an instruction census.
- Linked `zkvm_*` and configured zkVM-specific accelerator symbol evidence.
- Matching VK, ELF/VK `.minisig`, public-key, successful public CI, and
  MIT/Apache-2.0 publication evidence.
- Byte-for-byte equality and source-repository licenses for republished ELFs.
- Every currently cataloged standards requirement, including explicit unknowns
  for evidence that static inspection cannot establish.

Minisign files are checked for presence only. The dashboard labels this
“published, cryptographic verification not performed.” Workflow links are
public CI evidence, not artifact attestations.

## Architecture

```text
GitHub APIs + release assets
           |
           v
Rust CLI (ingestion -> ELF metrics -> atomic rules)
           |
       ReportV1 JSON + checked-in JSON Schema
           |
           v
React/Vite static dashboard -> GitHub Pages
```

- [`crates/analyzer`](crates/analyzer) contains the Rust 2024 CLI and versioned
  report model. The MSRV is Rust 1.97.
- [`rules/standards.yml`](rules/standards.yml) maps stable rule IDs to a
  standards path, heading, reviewed blob SHA, subject, method, and evaluator.
- [`web`](web) contains the React, TypeScript, and Vite dashboard. It validates
  the generated report against the bundled JSON Schema before rendering.
- [`.github/workflows`](.github/workflows) contains deterministic PR checks,
  daily live generation/Pages deployment, and the pinned `v0.14.1` smoke test.

The analyzer resolves standards `main` to a commit and compares every
rule-referenced blob to the reviewed SHA. If a document moved or changed,
affected findings become `unknown`, raw ELF metrics remain available, and the
dashboard shows a stale-rules banner.

## Local analyzer

Prerequisites are Rust 1.97 and, for the dashboard, Node.js 22.

```console
cargo run -p zkevm-analyzer -- analyze \
  --release latest \
  --standards-ref main \
  --rules rules/standards.yml \
  --output report.json
```

An explicit release tag is accepted:

```console
cargo run -p zkevm-analyzer -- analyze \
  --release v0.14.1 \
  --standards-ref main \
  --rules rules/standards.yml \
  --output report.json
```

Set `GITHUB_TOKEN` to avoid anonymous API rate limits. A finding with status
`fail` does not make the command fail; non-zero exit codes are reserved for
fatal operational failures such as an unresolved release or standards ref.
Individual asset errors are retained in the report.

Generate the versioned schema with:

```console
cargo run -p zkevm-analyzer -- schema --output web/src/report.schema.json
```

## Local dashboard

```console
mkdir -p web/public/data
cargo run -p zkevm-analyzer -- analyze \
  --release v0.14.1 \
  --standards-ref main \
  --rules rules/standards.yml \
  --output web/public/data/report.json
cd web
npm ci
npm run dev
```

The generated `web/public/data/report.json` is ignored. Production reports and
downloaded ELF/VK files are never committed; CI publishes the report only in
the Pages bundle and as a workflow artifact.

## Status semantics

| Status | Meaning |
| --- | --- |
| Pass | The observed evidence satisfies one atomic check. |
| Fail | The observed evidence contradicts an explicit check. |
| Warning | Evidence exceeds or complicates a minimal target without proving incompatibility. |
| Unknown | Static/provenance evidence is insufficient, an operational check failed, or a rule is stale. |
| N/A | The requirement does not apply to this artifact or origin. |

Examples of deliberate unknowns include IO behavior, loader rejection,
termination, guard regions, instruction-misalignment behavior, `Zicclsm`
runtime support, unaligned-access telemetry, proving behavior, EEST,
sustainability, formal-verification policy, and benchmarks.

## Development checks

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run --quiet -p zkevm-analyzer -- schema --output /tmp/report.schema.json
cmp web/src/report.schema.json /tmp/report.schema.json
cd web
npm ci
npm audit --omit=dev
npm test
npm run build
```

The daily deployment runs at 06:00 UTC. A fatal upstream-resolution failure
stops the deployment, leaving the preceding Pages deployment live.
For the first publication, configure the repository's Pages source as
**GitHub Actions** in the repository settings; subsequent deployments are
fully workflow-driven.

## Deferred work

Historical and contemporaneous-standard views, signature verification and key
pinning, zkVM execution, malformed-loader conformance tests, EEST execution,
accelerator call tracing, proof generation, release comparisons, and trends are
outside v1.
