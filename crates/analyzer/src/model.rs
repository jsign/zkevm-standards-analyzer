use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportV1 {
    pub schema_version: ReportSchemaVersion,
    pub generated_at: String,
    pub analyzer: AnalyzerIdentity,
    pub standards: StandardsSource,
    pub release: ReleaseIdentity,
    pub summary: EvidenceCounts,
    pub artifacts: Vec<ArtifactReport>,
    pub platforms: Vec<PlatformReport>,
    pub readiness: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub enum ReportSchemaVersion {
    #[serde(rename = "1")]
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzerIdentity {
    pub version: String,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StandardsSource {
    pub repository: String,
    pub requested_ref: String,
    pub commit: String,
    pub tree: String,
    pub reviewed_snapshot: String,
    pub blobs: BTreeMap<String, String>,
    pub stale_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseIdentity {
    pub repository: String,
    pub tag: String,
    pub commit: String,
    pub published_at: String,
    pub url: String,
    pub name: Option<String>,
    pub compiler: Option<String>,
    pub workflow_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceCounts {
    pub pass: u64,
    pub fail: u64,
    pub warning: u64,
    pub unknown: u64,
    pub not_applicable: u64,
}

impl EvidenceCounts {
    pub fn add(&mut self, status: FindingStatus) {
        match status {
            FindingStatus::Pass => self.pass += 1,
            FindingStatus::Fail => self.fail += 1,
            FindingStatus::Warning => self.warning += 1,
            FindingStatus::Unknown => self.unknown += 1,
            FindingStatus::NotApplicable => self.not_applicable += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactReport {
    pub id: String,
    pub family_id: String,
    pub guest: String,
    pub guest_version: Option<String>,
    pub zkvm: String,
    pub zkvm_version: String,
    pub variant: ArtifactVariant,
    pub origin: ArtifactOrigin,
    pub release_target_label: Option<String>,
    pub analysis: Option<ElfAnalysis>,
    pub provenance: ProvenanceEvidence,
    pub findings: Vec<Finding>,
    pub ingestion_warnings: Vec<String>,
    pub operational_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVariant {
    Primary,
    Profiling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactOrigin {
    Compiled,
    Republished,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceEvidence {
    pub elf: AssetEvidence,
    pub verification_key: Option<AssetEvidence>,
    pub public_key_url: Option<String>,
    pub signature_policy: String,
    pub source: Option<SourceEvidence>,
    pub workflow_url: Option<String>,
    pub licenses: LicenseEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssetEvidence {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub github_digest: Option<String>,
    pub computed_sha256: Option<String>,
    pub digest_matches: Option<bool>,
    pub signature_url: Option<String>,
    pub signature_published: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SourceEvidence {
    pub repository: String,
    pub release_tag: String,
    pub release_url: String,
    pub asset_url: String,
    pub computed_sha256: Option<String>,
    pub matches_hub_asset: Option<bool>,
    pub signature_url: Option<String>,
    pub signature_published: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct LicenseEvidence {
    pub repository: String,
    pub reference: String,
    pub mit: bool,
    pub apache_2: bool,
    pub inspected_paths: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ElfAnalysis {
    pub metrics: ElfMetrics,
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    #[serde(default)]
    pub section_headers: Vec<SectionHeader>,
    pub symbols: SymbolEvidence,
    pub instructions: InstructionCensus,
    pub accelerators: AcceleratorEvidence,
    pub checks: ElfChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ElfMetrics {
    pub asset_bytes: u64,
    pub load_file_bytes: u64,
    pub load_memory_bytes: u64,
    pub executable_bytes: u64,
    pub read_only_bytes: u64,
    pub writable_bytes: u64,
    pub bss_zero_fill_bytes: u64,
    pub program_header_count: u64,
    pub section_count: u64,
    pub symbol_count: u64,
    pub stripped: bool,
    pub has_debug_sections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ElfHeader {
    pub class: String,
    pub little_endian: bool,
    pub elf_type: String,
    pub machine: String,
    pub entry: u64,
    pub entry_hex: String,
    pub flags: u32,
    pub riscv_arch: Option<String>,
    #[serde(default)]
    pub header_size: u16,
    #[serde(default)]
    pub program_header_offset: u64,
    #[serde(default)]
    pub program_header_entry_size: u16,
    #[serde(default)]
    pub section_header_offset: u64,
    #[serde(default)]
    pub section_header_entry_size: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProgramHeader {
    pub kind: String,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: String,
    pub alignment: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SectionHeader {
    pub name: String,
    pub kind: String,
    pub flags: String,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub alignment: u64,
    pub entry_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolEvidence {
    pub start: Option<u64>,
    pub main: Option<u64>,
    pub heap_start: Option<u64>,
    pub heap_end: Option<u64>,
    pub read_input: bool,
    pub write_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstructionCensus {
    pub source: String,
    pub confidence: Confidence,
    pub decoded_instructions: u64,
    pub decoded_bytes: u64,
    pub undecodable_bytes: u64,
    pub compressed: u64,
    pub atomic: u64,
    pub floating_point: u64,
    pub privileged_or_syscall: u64,
    pub top_mnemonics: Vec<MnemonicCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MnemonicCount {
    pub mnemonic: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AcceleratorEvidence {
    pub standard_symbols: Vec<String>,
    pub platform_symbols: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ElfChecks {
    pub magic: bool,
    pub elf64: bool,
    pub little_endian: bool,
    pub riscv_machine: bool,
    pub executable_type: bool,
    pub statically_linked: bool,
    pub load_ranges_in_file: bool,
    pub file_size_within_memory_size: bool,
    pub vma_equals_lma: bool,
    pub alignment_valid: bool,
    pub load_segments_do_not_overlap: bool,
    pub write_xor_execute: bool,
    pub executable_permissions_valid: bool,
    pub entry_aligned: bool,
    pub entry_in_executable_segment: bool,
    pub code_data_separated: Option<bool>,
    pub entry_matches_start: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlatformReport {
    pub zkvm: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub subject: FindingSubject,
    pub status: FindingStatus,
    pub method: VerificationMethod,
    pub confidence: Confidence,
    pub explanation: String,
    pub standard_path: String,
    pub standard_anchor: String,
    pub source_url: String,
    pub evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Pass,
    Fail,
    Warning,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingSubject {
    Artifact,
    Release,
    Toolchain,
    GuestProject,
    ZkvmRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    Static,
    Provenance,
    Dynamic,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
    NotApplicable,
}
