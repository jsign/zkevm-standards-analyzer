import { Link } from "../router";
import {
  EvidenceCounts,
  FindingList,
  PageHeader,
  artifactCounts,
  formatBytes,
} from "../components";
import {
  decodeRiscvArchitecture,
  RISCV_ARCH_ATTRIBUTE_REFERENCE,
} from "../riscv";
import type { ElfAnalysis, ReportV1 } from "../types";

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
          <ElfStructure
            analysis={analysis}
            caption={`${artifact.guest} on ${artifact.zkvm}`}
          />

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

function ElfStructure({
  analysis,
  caption,
}: {
  analysis: ElfAnalysis;
  caption: string;
}) {
  const loadSegmentCount = analysis.program_headers.filter(
    (header) => header.kind === "LOAD" || header.kind === "PT_LOAD",
  ).length;

  return (
    <section className="section-block elf-structure">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Binary anatomy</p>
          <h2>ELF structure</h2>
        </div>
        <a href={RISCV_ARCH_ATTRIBUTE_REFERENCE}>
          Tag_RISCV_arch reference <span aria-hidden="true">↗</span>
        </a>
      </div>

      <RiscvArchitecture architecture={analysis.header.riscv_arch} />

      <div className="elf-root">
        <span className="elf-root-mark" aria-hidden="true">ELF</span>
        <div>
          <span>Executable file</span>
          <strong>{formatBytes(analysis.metrics.asset_bytes)}</strong>
          <small>
            One header points to the loader’s segments and the linker’s sections.
          </small>
        </div>
      </div>

      <div className="elf-tree">
        <div className="elf-node">
          <ElfNodeHeading
            index="01"
            eyebrow="File identity"
            title="ELF header"
            description="Describes the binary and locates the two header tables below."
            meta={
              analysis.header.header_size
                ? `${analysis.header.header_size} bytes`
                : "Size not reported"
            }
          />
          <div className="elf-fact-grid elf-header-grid">
            <Info label="Class" value={analysis.header.class} />
            <Info label="Machine" value={analysis.header.machine} />
            <Info label="ELF type" value={analysis.header.elf_type} />
            <Info
              label="Encoding"
              value={analysis.header.little_endian ? "Little-endian" : "Big-endian"}
            />
            <Info label="Entry point" value={analysis.header.entry_hex} mono />
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
                  : toHex(analysis.symbols.start)
              }
              mono
            />
            <Info
              label="main"
              value={
                analysis.symbols.main === null
                  ? "Not visible"
                  : toHex(analysis.symbols.main)
              }
              mono
            />
          </div>
        </div>

        <div className="elf-node">
          <ElfNodeHeading
            index="02"
            eyebrow="Loader view"
            title="Program header table"
            description="Tells the runtime which parts of the file become memory segments."
            meta={`${analysis.metrics.program_header_count} entries`}
          />
          <div className="elf-table-facts">
            <Info
              label="Table offset"
              value={optionalHex(analysis.header.program_header_offset)}
              mono
            />
            <Info
              label="Entry size"
              value={optionalBytes(analysis.header.program_header_entry_size)}
            />
            <Info label="Load segments" value={String(loadSegmentCount)} />
            <Info
              label="File bytes mapped"
              value={formatBytes(analysis.metrics.load_file_bytes)}
            />
            <Info
              label="Memory image"
              value={formatBytes(analysis.metrics.load_memory_bytes)}
            />
          </div>
          <div className="section-memory-summary" aria-label="Load segment memory summary">
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
          </div>

          <div className="elf-branch">
            <div className="elf-branch-heading">
              <div>
                <span className="elf-branch-kicker">Entries in the table</span>
                <h4>Program segments</h4>
              </div>
              <p>
                Segments are the loader-facing view of the ELF. They are not the
                same thing as sections.
              </p>
            </div>
            <div className="table-scroll">
              <table className="data-table segment-table">
                <caption className="visually-hidden">
                  ELF program segments for {caption}
                </caption>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Permissions</th>
                    <th>File offset</th>
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
                      <td className="segment-index">
                        {String(index).padStart(2, "0")}
                      </td>
                      <td>
                        <strong>{header.kind}</strong>
                      </td>
                      <td>
                        <code className="permission-badge">
                          {header.flags || "—"}
                        </code>
                      </td>
                      <td><code>{toHex(header.offset)}</code></td>
                      <td><code>{toHex(header.virtual_address)}</code></td>
                      <td><code>{toHex(header.physical_address)}</code></td>
                      <td>{formatBytes(header.file_size)}</td>
                      <td>{formatBytes(header.memory_size)}</td>
                      <td><code>{toHex(header.alignment)}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="elf-node">
          <ElfNodeHeading
            index="03"
            eyebrow="Linker view"
            title="Section header table"
            description="Catalogs logical regions used for code, data, symbols, and metadata."
            meta={`${analysis.metrics.section_count} sections`}
          />
          <div className="elf-table-facts elf-section-facts">
            <Info
              label="Table offset"
              value={optionalHex(analysis.header.section_header_offset)}
              mono
            />
            <Info
              label="Entry size"
              value={optionalBytes(analysis.header.section_header_entry_size)}
            />
            <Info
              label="Symbols"
              value={analysis.metrics.symbol_count.toLocaleString()}
            />
            <Info
              label="Symbol table"
              value={analysis.metrics.stripped ? "Stripped" : "Present"}
            />
            <Info
              label="Debug sections"
              value={analysis.metrics.has_debug_sections ? "Present" : "Absent"}
            />
          </div>
          {analysis.section_headers?.length ? (
            <div className="elf-branch">
              <div className="elf-branch-heading">
                <div>
                  <span className="elf-branch-kicker">Entries in the table</span>
                  <h4>Sections</h4>
                </div>
                <p>
                  The count includes the reserved null entry at index 0. The
                  remaining rows organize code, data, symbols, strings, and
                  architecture metadata.
                </p>
              </div>
              <div className="table-scroll">
                <table className="data-table segment-table section-table">
                  <caption className="visually-hidden">
                    ELF sections for {caption}
                  </caption>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Name</th>
                      <th>Purpose</th>
                      <th>Type</th>
                      <th>Flags</th>
                      <th>Address</th>
                      <th>File offset</th>
                      <th>Size</th>
                      <th>Entry size</th>
                      <th>Align</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.section_headers.map((section, index) => (
                      <tr key={`${section.name}-${index}`}>
                        <td className="segment-index">
                          {String(index).padStart(2, "0")}
                        </td>
                        <td>
                          <code className="section-name">
                            {section.name || "—"}
                          </code>
                        </td>
                        <td className="section-purpose">
                          {sectionPurpose(section.name, section.kind)}
                        </td>
                        <td><strong>{section.kind}</strong></td>
                        <td>
                          <code className="permission-badge">
                            {section.flags || "—"}
                          </code>
                        </td>
                        <td><code>{toHex(section.address)}</code></td>
                        <td><code>{toHex(section.offset)}</code></td>
                        <td>{formatBytes(section.size)}</td>
                        <td>
                          {section.entry_size
                            ? formatBytes(section.entry_size)
                            : "—"}
                        </td>
                        <td><code>{toHex(section.alignment)}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="section-flags-key">
                Flags: <code>W</code> writable · <code>A</code> allocated in
                memory · <code>X</code> executable · <code>M</code> mergeable ·{" "}
                <code>S</code> strings · <code>I</code> info link ·{" "}
                <code>L</code> link order · <code>O</code> OS processing ·{" "}
                <code>G</code> group · <code>T</code> TLS ·{" "}
                <code>C</code> compressed · <code>E</code> excluded
              </p>
            </div>
          ) : (
            <p className="elf-unreported">
              Individual section entries were not captured in this report.
              Regenerate it with the current analyzer to list them here.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

function RiscvArchitecture({
  architecture,
}: {
  architecture: string | null;
}) {
  if (!architecture) {
    return (
      <div className="isa-declaration isa-declaration-empty">
        <span className="quiet-label">Declared RISC-V ISA</span>
        <strong>No Tag_RISCV_arch attribute reported</strong>
      </div>
    );
  }

  const components = decodeRiscvArchitecture(architecture);

  return (
    <div className="isa-declaration">
      <div className="isa-declaration-heading">
        <div>
          <span className="quiet-label">Declared RISC-V ISA</span>
          <code>{architecture}</code>
        </div>
        <span>
          {components.length} {components.length === 1 ? "component" : "components"}
        </span>
      </div>

      {components.length > 0 && (
        <div className="isa-component-grid">
          {components.map((component) => (
            <a
              className="isa-component"
              href={component.referenceUrl}
              key={component.id}
            >
              <span className="isa-component-name">
                <code>{component.label}</code>
                {component.version && <small>v{component.version}</small>}
              </span>
              <span>{component.description}</span>
              <small>
                {component.referenceLabel} <span aria-hidden="true">↗</span>
              </small>
            </a>
          ))}
        </div>
      )}

      <p className="isa-declaration-note">
        Versions use <code>p</code> as the decimal point: <code>2p1</code> means{" "}
        <code>2.1</code>. This is the target ISA declared by the ELF, not a census
        of instructions observed in its code.
      </p>
    </div>
  );
}

function ElfNodeHeading({
  index,
  eyebrow,
  title,
  description,
  meta,
}: {
  index: string;
  eyebrow: string;
  title: string;
  description: string;
  meta: string;
}) {
  return (
    <div className="elf-node-heading">
      <span className="elf-node-index" aria-hidden="true">{index}</span>
      <div>
        <span className="elf-node-eyebrow">{eyebrow}</span>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      <code>{meta}</code>
    </div>
  );
}

function toHex(value: number) {
  return `0x${value.toString(16)}`;
}

function optionalHex(value: number | undefined) {
  return value === undefined ? "Not reported" : toHex(value);
}

function optionalBytes(value: number | undefined) {
  return value === undefined ? "Not reported" : `${value} bytes`;
}

function sectionPurpose(name: string, kind: string) {
  const knownSections: Record<string, string> = {
    ".text": "Executable code",
    ".rodata": "Read-only constants",
    ".data": "Initialized writable data",
    ".bss": "Zero-initialized data",
    ".comment": "Toolchain metadata",
    ".riscv.attributes": "RISC-V architecture attributes",
    ".symtab": "Symbol definitions",
    ".dynsym": "Dynamic symbol definitions",
    ".shstrtab": "Section-name strings",
    ".strtab": "Symbol-name strings",
  };
  if (name in knownSections) {
    return knownSections[name];
  }

  const knownTypes: Record<string, string> = {
    SHT_NULL: "Reserved entry",
    SHT_NOBITS: "Zero-fill data",
    SHT_NOTE: "Auxiliary metadata",
    SHT_PROGBITS: "Program-defined data",
    SHT_RELA: "Relocations with addends",
    SHT_REL: "Relocations",
    SHT_STRTAB: "String data",
    SHT_SYMTAB: "Symbol definitions",
  };
  return knownTypes[kind] ?? "Specialized metadata";
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
