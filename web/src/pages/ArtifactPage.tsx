import { Link } from "../router";
import {
  EvidenceCounts,
  FindingList,
  PageHeader,
  artifactCounts,
  formatBytes,
} from "../components";
import type { ReportV1 } from "../types";

export function ArtifactPage({
  report,
  artifactId,
}: {
  report: ReportV1;
  artifactId: string;
}) {
  const artifact = report.artifacts.find(
    (item) => item.id === artifactId,
  );
  if (!artifact) {
    return (
      <div className="fatal-state">
        <h1>Artifact not found</h1>
        <Link to="/">Return to the release overview</Link>
      </div>
    );
  }
  const counts = artifactCounts(artifact);
  const analysis = artifact.analysis;
  const provenance = artifact.provenance;

  return (
    <>
      <div className="breadcrumbs">
        <Link to="/">Overview</Link>
        <span>/</span>
        <span>{artifact.guest}</span>
        <span>/</span>
        <span>{artifact.zkvm}</span>
      </div>
      <PageHeader
        eyebrow={`${artifact.origin} · ${artifact.variant} artifact`}
        title={`${artifact.guest} on ${artifact.zkvm}`}
        description={`${artifact.guest_version ?? "Unknown guest version"} · ${artifact.zkvm_version} · ${artifact.release_target_label ?? "target label unavailable"}`}
        aside={
          <a className="download-link" href={provenance.elf.url}>
            Download ELF <span aria-hidden="true">↓</span>
          </a>
        }
      />
      <EvidenceCounts counts={counts} />

      {artifact.operational_error && (
        <div className="error-banner" role="alert">
          <strong>Analysis incomplete</strong>
          <span>{artifact.operational_error}</span>
        </div>
      )}
      {artifact.ingestion_warnings.map((warning) => (
        <div className="warning-banner" role="status" key={warning}>
          <strong>Release metadata warning</strong>
          <span>{warning}</span>
        </div>
      ))}

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Publication chain</p>
            <h2>Provenance</h2>
          </div>
          <span className="quiet-label">Signature presence only</span>
        </div>
        <div className="provenance-grid">
          <Info label="ELF SHA-256" value={provenance.elf.computed_sha256 ?? "Unavailable"} mono />
          <Info
            label="GitHub digest"
            value={
              provenance.elf.digest_matches === true
                ? "Matches"
                : provenance.elf.digest_matches === false
                  ? "Mismatch"
                  : "Unavailable"
            }
          />
          <Info
            label="ELF signature"
            value={provenance.elf.signature_published ? "Published" : "Missing"}
          />
          <Info
            label="Verification key"
            value={provenance.verification_key ? "Published" : "Missing"}
          />
          <Info
            label="Source repository"
            value={provenance.licenses.repository}
          />
          <Info
            label="Dual license"
            value={
              provenance.licenses.mit && provenance.licenses.apache_2
                ? "MIT + Apache-2.0"
                : "Incomplete evidence"
            }
          />
        </div>
        {provenance.source && (
          <div className="source-chain">
            <span>Ere hub</span>
            <span aria-hidden="true">→</span>
            <a href={provenance.source.release_url}>
              {provenance.source.repository} / {provenance.source.release_tag}
            </a>
            <a href={provenance.source.asset_url}>source asset ↗</a>
            <strong>
              {provenance.source.matches_hub_asset
                ? "Byte-identical"
                : "Equality unconfirmed"}
            </strong>
          </div>
        )}
      </section>

      {analysis && (
        <>
          <section className="section-block">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Binary anatomy</p>
                <h2>ELF metrics</h2>
              </div>
              <span className="mono">{analysis.header.riscv_arch ?? "No Tag_arch"}</span>
            </div>
            <div className="metric-grid">
              <Metric label="Asset size" value={formatBytes(analysis.metrics.asset_bytes)} />
              <Metric
                label="Load file bytes"
                value={formatBytes(analysis.metrics.load_file_bytes)}
              />
              <Metric
                label="Load image"
                value={formatBytes(analysis.metrics.load_memory_bytes)}
              />
              <Metric
                label="Executable"
                value={formatBytes(analysis.metrics.executable_bytes)}
              />
              <Metric
                label="Read-only data"
                value={formatBytes(analysis.metrics.read_only_bytes)}
              />
              <Metric
                label="Writable"
                value={formatBytes(analysis.metrics.writable_bytes)}
              />
              <Metric
                label="Zero fill"
                value={formatBytes(analysis.metrics.bss_zero_fill_bytes)}
              />
              <Metric label="Entry" value={analysis.header.entry_hex} />
              <Metric label="Class" value={analysis.header.class} />
              <Metric
                label="Program headers"
                value={String(analysis.metrics.program_header_count)}
              />
              <Metric
                label="Sections"
                value={String(analysis.metrics.section_count)}
              />
              <Metric
                label="Symbols"
                value={analysis.metrics.symbol_count.toLocaleString()}
              />
              <Metric
                label="Symbol state"
                value={analysis.metrics.stripped ? "Stripped" : "Present"}
              />
              <Metric
                label="Debug sections"
                value={analysis.metrics.has_debug_sections ? "Present" : "Absent"}
              />
            </div>
            <div className="header-facts">
              <Info label="Machine" value={analysis.header.machine} />
              <Info label="ELF type" value={analysis.header.elf_type} />
              <Info
                label="Encoding"
                value={analysis.header.little_endian ? "Little-endian" : "Big-endian"}
              />
              <Info
                label="ELF flags"
                value={`0x${analysis.header.flags.toString(16)}`}
                mono
              />
              <Info
                label="_start"
                value={
                  analysis.symbols.start === null
                    ? "Not visible"
                    : `0x${analysis.symbols.start.toString(16)}`
                }
                mono
              />
              <Info
                label="main"
                value={
                  analysis.symbols.main === null
                    ? "Not visible"
                    : `0x${analysis.symbols.main.toString(16)}`
                }
                mono
              />
            </div>
          </section>

          <div className="detail-grid">
            <section className="section-block">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Decoded code</p>
                  <h2>Instruction census</h2>
                </div>
                <span className="quiet-label">
                  {analysis.instructions.confidence} confidence
                </span>
              </div>
              <div className="instruction-stats">
                <Metric
                  label="Decoded"
                  value={analysis.instructions.decoded_instructions.toLocaleString()}
                />
                <Metric
                  label="Compressed"
                  value={analysis.instructions.compressed.toLocaleString()}
                />
                <Metric
                  label="Atomic"
                  value={analysis.instructions.atomic.toLocaleString()}
                />
                <Metric
                  label="Floating point"
                  value={analysis.instructions.floating_point.toLocaleString()}
                />
                <Metric
                  label="System"
                  value={analysis.instructions.privileged_or_syscall.toLocaleString()}
                />
                <Metric
                  label="Undecodable"
                  value={formatBytes(analysis.instructions.undecodable_bytes)}
                />
              </div>
              <p className="table-note">
                Decoded from {analysis.instructions.source.replaceAll("_", " ")};{" "}
                {formatBytes(analysis.instructions.decoded_bytes)} covered.
              </p>
              <div className="mnemonics">
                {analysis.instructions.top_mnemonics.slice(0, 12).map((item) => (
                  <span key={item.mnemonic}>
                    <code>{item.mnemonic}</code>
                    {item.count.toLocaleString()}
                  </span>
                ))}
              </div>
            </section>

            <section className="section-block">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Linked evidence</p>
                  <h2>Accelerators</h2>
                </div>
              </div>
              <p className="section-copy">{analysis.accelerators.note}</p>
              <div className="symbol-list">
                {analysis.accelerators.standard_symbols.length ? (
                  analysis.accelerators.standard_symbols.map((symbol) => (
                    <code key={symbol}>{symbol}</code>
                  ))
                ) : (
                  <span>No standard zkvm_* symbols visible.</span>
                )}
              </div>
              {analysis.accelerators.platform_symbols.length > 0 && (
                <details className="raw-symbols">
                  <summary>
                    {analysis.accelerators.platform_symbols.length} platform-specific
                    symbols
                  </summary>
                  <pre>{analysis.accelerators.platform_symbols.join("\n")}</pre>
                </details>
              )}
            </section>
          </div>

          <section className="section-block">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Loader view</p>
                <h2>Program headers</h2>
              </div>
            </div>
            <div className="table-scroll">
              <table className="data-table">
                <caption className="visually-hidden">
                  ELF program headers for {artifact.guest} on {artifact.zkvm}
                </caption>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Flags</th>
                    <th>Offset</th>
                    <th>Virtual address</th>
                    <th>Physical address</th>
                    <th>File size</th>
                    <th>Memory size</th>
                    <th>Align</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.program_headers.map((header, index) => (
                    <tr key={`${header.kind}-${index}`}>
                      <td>{header.kind}</td>
                      <td><code>{header.flags || "—"}</code></td>
                      <td><code>0x{header.offset.toString(16)}</code></td>
                      <td><code>0x{header.virtual_address.toString(16)}</code></td>
                      <td><code>0x{header.physical_address.toString(16)}</code></td>
                      <td>{formatBytes(header.file_size)}</td>
                      <td>{formatBytes(header.memory_size)}</td>
                      <td><code>0x{header.alignment.toString(16)}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Atomic requirements</p>
            <h2>All findings</h2>
          </div>
        </div>
        <FindingList findings={artifact.findings} />
      </section>
    </>
  );
}

function Info({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="info-row">
      <span>{label}</span>
      <strong className={mono ? "mono hash-value" : ""}>{value}</strong>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
