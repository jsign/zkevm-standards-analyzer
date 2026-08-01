export type FindingStatus =
  | "pass"
  | "fail"
  | "warning"
  | "unknown"
  | "not_applicable";

export interface EvidenceCounts {
  pass: number;
  fail: number;
  warning: number;
  unknown: number;
  not_applicable: number;
}

export interface ReportV1 {
  schema_version: "1";
  generated_at: string;
  analyzer: { version: string; commit: string | null };
  standards: {
    repository: string;
    requested_ref: string;
    commit: string;
    tree: string;
    reviewed_snapshot: string;
    blobs: Record<string, string>;
    stale_paths: string[];
  };
  release: {
    repository: string;
    tag: string;
    commit: string;
    published_at: string;
    url: string;
    name: string | null;
    compiler: string | null;
    workflow_url: string | null;
  };
  summary: EvidenceCounts;
  artifacts: ArtifactReport[];
  platforms: PlatformReport[];
  readiness: Finding[];
}

export interface ArtifactReport {
  id: string;
  family_id: string;
  guest: string;
  guest_version: string | null;
  zkvm: string;
  zkvm_version: string;
  variant: "primary" | "profiling";
  origin: "compiled" | "republished";
  release_target_label: string | null;
  analysis: ElfAnalysis | null;
  provenance: ProvenanceEvidence;
  findings: Finding[];
  ingestion_warnings: string[];
  operational_error: string | null;
}

export interface ElfAnalysis {
  metrics: {
    asset_bytes: number;
    load_file_bytes: number;
    load_memory_bytes: number;
    executable_bytes: number;
    read_only_bytes: number;
    writable_bytes: number;
    bss_zero_fill_bytes: number;
    program_header_count: number;
    section_count: number;
    symbol_count: number;
    stripped: boolean;
    has_debug_sections: boolean;
  };
  header: {
    class: string;
    little_endian: boolean;
    elf_type: string;
    machine: string;
    entry: number;
    entry_hex: string;
    flags: number;
    riscv_arch: string | null;
    header_size?: number;
    program_header_offset?: number;
    program_header_entry_size?: number;
    section_header_offset?: number;
    section_header_entry_size?: number;
  };
  program_headers: ProgramHeader[];
  section_headers?: SectionHeader[];
  symbols: {
    start: number | null;
    main: number | null;
    heap_start: number | null;
    heap_end: number | null;
    read_input: boolean;
    write_output: boolean;
  };
  instructions: {
    source: string;
    confidence: "high" | "medium" | "low" | "not_applicable";
    decoded_instructions: number;
    decoded_bytes: number;
    undecodable_bytes: number;
    compressed: number;
    atomic: number;
    floating_point: number;
    privileged_or_syscall: number;
    top_mnemonics: { mnemonic: string; count: number }[];
  };
  accelerators: {
    standard_symbols: string[];
    platform_symbols: string[];
    note: string;
  };
  checks: Record<string, boolean | null>;
}

export interface ProgramHeader {
  kind: string;
  offset: number;
  virtual_address: number;
  physical_address: number;
  file_size: number;
  memory_size: number;
  flags: string;
  alignment: number;
}

export interface SectionHeader {
  name: string;
  kind: string;
  flags: string;
  address: number;
  offset: number;
  size: number;
  alignment: number;
  entry_size: number;
}

export interface ProvenanceEvidence {
  elf: AssetEvidence;
  verification_key: AssetEvidence | null;
  public_key_url: string | null;
  signature_policy: string;
  source: {
    repository: string;
    release_tag: string;
    release_url: string;
    asset_url: string;
    computed_sha256: string | null;
    matches_hub_asset: boolean | null;
    signature_url: string | null;
    signature_published: boolean;
    error: string | null;
  } | null;
  workflow_url: string | null;
  licenses: {
    repository: string;
    reference: string;
    mit: boolean;
    apache_2: boolean;
    inspected_paths: string[];
    error: string | null;
  };
}

export interface AssetEvidence {
  name: string;
  url: string;
  size: number;
  github_digest: string | null;
  computed_sha256: string | null;
  digest_matches: boolean | null;
  signature_url: string | null;
  signature_published: boolean;
  error: string | null;
}

export interface PlatformReport {
  zkvm: string;
  findings: Finding[];
}

export interface Finding {
  rule_id: string;
  title: string;
  subject:
    | "artifact"
    | "release"
    | "toolchain"
    | "guest_project"
    | "zkvm_runtime";
  status: FindingStatus;
  method: "static" | "provenance" | "dynamic" | "manual";
  confidence: "high" | "medium" | "low" | "not_applicable";
  explanation: string;
  standard_path: string;
  standard_anchor: string;
  source_url: string;
  evidence: Record<string, unknown>;
}
