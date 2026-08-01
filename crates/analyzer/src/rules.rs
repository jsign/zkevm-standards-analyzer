use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::Context;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{
    ArtifactOrigin, ArtifactReport, Confidence, Finding, FindingStatus, FindingSubject,
    LicenseEvidence, VerificationMethod,
};

#[derive(Debug, Clone, Deserialize)]
pub struct RuleCatalog {
    pub reviewed_snapshot: String,
    pub zkvm_identifiers: Vec<String>,
    pub accelerator_symbol_patterns: BTreeMap<String, Vec<String>>,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub title: String,
    pub scope: RuleScope,
    pub subject: FindingSubject,
    pub method: VerificationMethod,
    pub standard_path: String,
    pub standard_anchor: String,
    pub reviewed_blob_sha: String,
    pub evaluator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    Artifact,
    Platform,
    Release,
}

#[derive(Debug, Clone)]
pub struct ReleaseRuleContext<'a> {
    pub compiler: Option<&'a str>,
    pub license: &'a LicenseEvidence,
    pub workflow_url: Option<&'a str>,
}

pub fn load_catalog(path: &Path) -> anyhow::Result<RuleCatalog> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let catalog: RuleCatalog = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("invalid rule catalog {}", path.display()))?;
    if catalog.zkvm_identifiers.is_empty() {
        anyhow::bail!("rule catalog must configure at least one zkVM identifier");
    }
    for zkvm in &catalog.zkvm_identifiers {
        if !catalog.accelerator_symbol_patterns.contains_key(zkvm) {
            anyhow::bail!("missing accelerator symbol patterns for {zkvm}");
        }
    }
    let mut ids = BTreeSet::new();
    for rule in &catalog.rules {
        if !ids.insert(&rule.id) {
            anyhow::bail!("duplicate rule id {}", rule.id);
        }
    }
    Ok(catalog)
}

pub fn stale_paths(catalog: &RuleCatalog, current_blobs: &BTreeMap<String, String>) -> Vec<String> {
    let mut stale = catalog
        .rules
        .iter()
        .filter(|rule| {
            current_blobs
                .get(&rule.standard_path)
                .is_none_or(|sha| sha != &rule.reviewed_blob_sha)
        })
        .map(|rule| rule.standard_path.clone())
        .collect::<Vec<_>>();
    stale.sort();
    stale.dedup();
    stale
}

pub fn artifact_findings(
    catalog: &RuleCatalog,
    artifact: &ArtifactReport,
    standards_commit: &str,
    current_blobs: &BTreeMap<String, String>,
) -> Vec<Finding> {
    catalog
        .rules
        .iter()
        .filter(|rule| rule.scope == RuleScope::Artifact)
        .map(|rule| {
            let outcome = evaluate_artifact(rule, artifact);
            build_finding(
                rule,
                outcome,
                standards_commit,
                current_blobs.get(&rule.standard_path),
            )
        })
        .collect()
}

pub fn platform_findings(
    catalog: &RuleCatalog,
    zkvm: &str,
    standards_commit: &str,
    current_blobs: &BTreeMap<String, String>,
) -> Vec<Finding> {
    catalog
        .rules
        .iter()
        .filter(|rule| rule.scope == RuleScope::Platform)
        .map(|rule| {
            let mut evidence = BTreeMap::new();
            evidence.insert("zkvm".into(), json!(zkvm));
            build_finding(
                rule,
                Outcome {
                    status: FindingStatus::Unknown,
                    confidence: Confidence::Low,
                    explanation: runtime_explanation(&rule.evaluator),
                    evidence,
                },
                standards_commit,
                current_blobs.get(&rule.standard_path),
            )
        })
        .collect()
}

pub fn release_findings(
    catalog: &RuleCatalog,
    context: ReleaseRuleContext<'_>,
    standards_commit: &str,
    current_blobs: &BTreeMap<String, String>,
) -> Vec<Finding> {
    catalog
        .rules
        .iter()
        .filter(|rule| rule.scope == RuleScope::Release)
        .map(|rule| {
            let outcome = match rule.evaluator.as_str() {
                "readiness.license" => {
                    let mut evidence = BTreeMap::new();
                    evidence.insert("repository".into(), json!(context.license.repository));
                    evidence.insert("reference".into(), json!(context.license.reference));
                    evidence.insert("mit".into(), json!(context.license.mit));
                    evidence.insert("apache_2".into(), json!(context.license.apache_2));
                    if context.license.error.is_some() {
                        unknown("Repository licenses could not be inspected.", evidence)
                    } else if context.license.mit && context.license.apache_2 {
                        pass(
                            "Both MIT and Apache-2.0 license files are published.",
                            evidence,
                        )
                    } else {
                        fail(
                            "The inspected repository does not publish both expected license files.",
                            evidence,
                        )
                    }
                }
                "readiness.public_ci" => {
                    let mut evidence = BTreeMap::new();
                    evidence.insert("workflow_url".into(), json!(context.workflow_url));
                    if context.workflow_url.is_some() {
                        pass(
                            "A successful public workflow was found for the release commit. This is workflow evidence, not an artifact attestation.",
                            evidence,
                        )
                    } else {
                        unknown(
                            "No successful public workflow could be tied to the release commit.",
                            evidence,
                        )
                    }
                }
                "readiness.formal_verification" => {
                    let mut evidence = BTreeMap::new();
                    evidence.insert("compiler".into(), json!(context.compiler));
                    unknown(
                        "The handbook says formal-verification requirements for modified/custom compilers are still TBD.",
                        evidence,
                    )
                }
                "readiness.eest" => unknown(
                    "EEST execution is outside v1; no runtime test result was collected.",
                    BTreeMap::new(),
                ),
                "readiness.sustainability" => unknown(
                    "Maintainer sustainability requires a documented manual assessment.",
                    BTreeMap::new(),
                ),
                "readiness.benchmarks" => unknown(
                    "The handbook benchmark requirement is explicitly TBD.",
                    BTreeMap::new(),
                ),
                _ => unknown("No release evaluator is implemented.", BTreeMap::new()),
            };
            build_finding(
                rule,
                outcome,
                standards_commit,
                current_blobs.get(&rule.standard_path),
            )
        })
        .collect()
}

fn evaluate_artifact(rule: &RuleDefinition, artifact: &ArtifactReport) -> Outcome {
    let Some(analysis) = artifact.analysis.as_ref() else {
        if rule.evaluator == "elf.magic" {
            let mut evidence = BTreeMap::new();
            evidence.insert("error".into(), json!(artifact.operational_error.as_deref()));
            return fail("The asset could not be parsed as an ELF.", evidence);
        }
        return unknown(
            "The ELF could not be analyzed, so this requirement is not observable.",
            BTreeMap::new(),
        );
    };

    let checks = &analysis.checks;
    match rule.evaluator.as_str() {
        "elf.magic" => bool_outcome(
            checks.magic,
            "The ELF magic is valid.",
            "The ELF magic is invalid.",
            "magic",
        ),
        "elf.class64" => bool_outcome(
            checks.elf64,
            "The artifact is ELF64.",
            "The artifact is not ELF64.",
            "elf64",
        ),
        "elf.little_endian" => bool_outcome(
            checks.little_endian,
            "The artifact is little-endian.",
            "The artifact is not little-endian.",
            "little_endian",
        ),
        "elf.riscv_machine" => bool_outcome(
            checks.riscv_machine,
            "The ELF machine is RISC-V.",
            "The ELF machine is not RISC-V.",
            "riscv_machine",
        ),
        "elf.executable_type" => bool_outcome(
            checks.executable_type,
            "The ELF type is ET_EXEC.",
            "The ELF type is not ET_EXEC.",
            "executable_type",
        ),
        "elf.static" => bool_outcome(
            checks.statically_linked,
            "No dynamic interpreter or PT_DYNAMIC segment is present.",
            "A dynamic interpreter or PT_DYNAMIC segment is present.",
            "statically_linked",
        ),
        "elf.load_ranges" => bool_outcome(
            checks.load_ranges_in_file,
            "Every PT_LOAD file range lies within the asset.",
            "At least one PT_LOAD file range lies outside the asset or overflows.",
            "load_ranges_in_file",
        ),
        "elf.mem_size" => bool_outcome(
            checks.file_size_within_memory_size,
            "Every PT_LOAD has p_filesz <= p_memsz.",
            "At least one PT_LOAD has p_filesz > p_memsz.",
            "file_size_within_memory_size",
        ),
        "elf.vma_lma" => bool_outcome(
            checks.vma_equals_lma,
            "Load virtual and physical addresses agree.",
            "At least one PT_LOAD has a differing virtual and physical address.",
            "vma_equals_lma",
        ),
        "elf.alignment" => bool_outcome(
            checks.alignment_valid,
            "PT_LOAD address and file-offset alignment is congruent.",
            "At least one PT_LOAD has invalid address/file alignment.",
            "alignment_valid",
        ),
        "elf.no_overlap" => bool_outcome(
            checks.load_segments_do_not_overlap,
            "PT_LOAD virtual address ranges do not overlap.",
            "PT_LOAD virtual address ranges overlap or overflow.",
            "load_segments_do_not_overlap",
        ),
        "elf.wx" => bool_outcome(
            checks.write_xor_execute,
            "No PT_LOAD segment is both writable and executable.",
            "At least one PT_LOAD segment is writable and executable.",
            "write_xor_execute",
        ),
        "elf.exec_permissions" => bool_outcome(
            checks.executable_permissions_valid,
            "Executable segments use X or RX permissions.",
            "At least one executable segment has an unsupported permission combination.",
            "executable_permissions_valid",
        ),
        "elf.entry_aligned" => bool_outcome(
            checks.entry_aligned,
            "The entry point is four-byte aligned.",
            "The entry point is not four-byte aligned.",
            "entry_aligned",
        ),
        "elf.entry_executable" => bool_outcome(
            checks.entry_in_executable_segment,
            "The entry point lies in an executable PT_LOAD segment.",
            "The entry point does not lie in an executable PT_LOAD segment.",
            "entry_in_executable_segment",
        ),
        "elf.code_data" => optional_bool_outcome(
            checks.code_data_separated,
            "Allocated read-only data sections are separate from executable segments.",
            "An allocated read-only data section overlaps an executable segment.",
            "Section headers are unavailable, so code/data separation cannot be established.",
            "code_data_separated",
        ),
        "linker.start" => symbol_outcome(
            analysis.symbols.start,
            "_start",
            "The _start symbol is visible.",
        ),
        "linker.main" => {
            symbol_outcome(analysis.symbols.main, "main", "The main symbol is visible.")
        }
        "linker.entry_start" => optional_bool_outcome(
            checks.entry_matches_start,
            "The ELF entry point equals _start.",
            "The ELF entry point does not equal _start.",
            "_start is not visible, so the equality cannot be checked.",
            "entry_matches_start",
        ),
        "target.compressed" => {
            let count = analysis.instructions.compressed;
            let rvc_flag = analysis.header.flags & 0x1 != 0;
            let mut evidence = BTreeMap::new();
            evidence.insert("compressed_instruction_count".into(), json!(count));
            evidence.insert("rvc_elf_flag".into(), json!(rvc_flag));
            if count == 0 && !rvc_flag {
                pass(
                    "No compressed instructions or RVC ELF flag were observed.",
                    evidence,
                )
            } else {
                fail(
                    "Compressed instructions or the RVC ELF flag were observed, while the proposed target excludes C.",
                    evidence,
                )
            }
        }
        "target.floating_point" => {
            let count = analysis.instructions.floating_point;
            let float_abi = analysis.header.flags & 0x6;
            let mut evidence = BTreeMap::new();
            evidence.insert("floating_point_instruction_count".into(), json!(count));
            evidence.insert("float_abi_flag".into(), json!(float_abi));
            if count == 0 && float_abi == 0 {
                pass(
                    "No floating-point instructions or floating ABI flag were observed.",
                    evidence,
                )
            } else {
                fail("Floating-point evidence was observed.", evidence)
            }
        }
        "target.privileged" => {
            let count = analysis.instructions.privileged_or_syscall;
            let mut evidence = BTreeMap::new();
            evidence.insert("instruction_count".into(), json!(count));
            if count == 0 {
                pass(
                    "No privileged or syscall instruction was observed.",
                    evidence,
                )
            } else {
                fail(
                    "Privileged or syscall instructions were observed.",
                    evidence,
                )
            }
        }
        "target.atomic" => {
            let count = analysis.instructions.atomic;
            let declared = analysis
                .header
                .riscv_arch
                .as_deref()
                .is_some_and(declares_atomic_extension);
            let mut evidence = BTreeMap::new();
            evidence.insert("atomic_instruction_count".into(), json!(count));
            evidence.insert("atomic_extension_declared".into(), json!(declared));
            if count == 0 && !declared {
                pass("No atomic extension evidence was observed.", evidence)
            } else {
                warning(
                    "Atomic-extension evidence exceeds the proposed minimal profile; the loader standard permits capable zkVMs to exceed the minimum.",
                    evidence,
                )
            }
        }
        "interface.symbols" => {
            let mut evidence = BTreeMap::new();
            evidence.insert("read_input".into(), json!(analysis.symbols.read_input));
            evidence.insert("write_output".into(), json!(analysis.symbols.write_output));
            evidence.insert("heap_start".into(), json!(analysis.symbols.heap_start));
            evidence.insert("heap_end".into(), json!(analysis.symbols.heap_end));
            unknown(
                "Visible symbols are recorded, but missing final-ELF symbols do not prove the vendor static library is nonconforming.",
                evidence,
            )
        }
        "accelerator.inventory" => {
            let mut evidence = BTreeMap::new();
            evidence.insert(
                "standard_symbols".into(),
                json!(analysis.accelerators.standard_symbols),
            );
            evidence.insert(
                "platform_symbol_count".into(),
                json!(analysis.accelerators.platform_symbols.len()),
            );
            pass(
                "Linked accelerator symbol evidence was inventoried; runtime use is not claimed.",
                evidence,
            )
        }
        "provenance.digest" => match artifact.provenance.elf.digest_matches {
            Some(value) => bool_outcome(
                value,
                "The computed ELF SHA-256 matches GitHub's published digest.",
                "The computed ELF SHA-256 does not match GitHub's published digest.",
                "digest_matches",
            ),
            None => unknown(
                "GitHub did not publish a comparable SHA-256 digest or the download failed.",
                BTreeMap::new(),
            ),
        },
        "provenance.elf_signature" => presence_outcome(
            artifact.provenance.elf.signature_published,
            "A matching ELF .minisig asset is published. Its cryptographic validity is not checked in v1.",
            "No matching ELF .minisig asset is published.",
            artifact.provenance.elf.signature_url.as_deref(),
        ),
        "provenance.vk" => presence_outcome(
            artifact.provenance.verification_key.is_some(),
            "A matching verification-key asset is published.",
            "No matching verification-key asset is published.",
            artifact
                .provenance
                .verification_key
                .as_ref()
                .map(|asset| asset.url.as_str()),
        ),
        "provenance.vk_signature" => {
            let published = artifact
                .provenance
                .verification_key
                .as_ref()
                .is_some_and(|asset| asset.signature_published);
            presence_outcome(
                published,
                "A matching VK .minisig asset is published. Its cryptographic validity is not checked in v1.",
                "No matching VK .minisig asset is published.",
                artifact
                    .provenance
                    .verification_key
                    .as_ref()
                    .and_then(|asset| asset.signature_url.as_deref()),
            )
        }
        "provenance.public_key" => presence_outcome(
            artifact.provenance.public_key_url.is_some(),
            "A Minisign public-key asset is published with the release.",
            "No Minisign public-key asset is published with the release.",
            artifact.provenance.public_key_url.as_deref(),
        ),
        "provenance.upstream" => {
            if artifact.origin == ArtifactOrigin::Compiled {
                not_applicable(
                    "The artifact was compiled by ere-guests rather than republished.",
                    BTreeMap::new(),
                )
            } else if let Some(source) = &artifact.provenance.source {
                let mut evidence = BTreeMap::new();
                evidence.insert("source_url".into(), json!(source.asset_url));
                evidence.insert("sha256_matches".into(), json!(source.matches_hub_asset));
                match source.matches_hub_asset {
                    Some(true) => pass(
                        "The Ere hub artifact is byte-identical to the declared upstream source asset.",
                        evidence,
                    ),
                    Some(false) => fail(
                        "The Ere hub artifact differs from the declared upstream source asset.",
                        evidence,
                    ),
                    None => unknown("Upstream byte equality could not be checked.", evidence),
                }
            } else {
                unknown(
                    "The release identifies this as republished but no source URL was parsed.",
                    BTreeMap::new(),
                )
            }
        }
        "provenance.license" => {
            let licenses = &artifact.provenance.licenses;
            let mut evidence = BTreeMap::new();
            evidence.insert("repository".into(), json!(licenses.repository));
            evidence.insert("mit".into(), json!(licenses.mit));
            evidence.insert("apache_2".into(), json!(licenses.apache_2));
            if licenses.error.is_some() {
                unknown(
                    "Source repository licenses could not be inspected.",
                    evidence,
                )
            } else if licenses.mit && licenses.apache_2 {
                pass(
                    "The source repository publishes MIT and Apache-2.0 license files.",
                    evidence,
                )
            } else {
                fail(
                    "The source repository does not publish both expected license files.",
                    evidence,
                )
            }
        }
        _ => unknown("No artifact evaluator is implemented.", BTreeMap::new()),
    }
}

fn build_finding(
    rule: &RuleDefinition,
    mut outcome: Outcome,
    standards_commit: &str,
    current_blob: Option<&String>,
) -> Finding {
    if current_blob.is_none_or(|sha| sha != &rule.reviewed_blob_sha) {
        outcome.status = FindingStatus::Unknown;
        outcome.confidence = Confidence::Low;
        outcome.explanation = "The referenced standard changed after this rule was reviewed; rule review is required before evaluating it.".to_string();
        outcome
            .evidence
            .insert("reviewed_blob_sha".into(), json!(rule.reviewed_blob_sha));
        outcome
            .evidence
            .insert("current_blob_sha".into(), json!(current_blob));
    }
    Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        subject: rule.subject,
        status: outcome.status,
        method: rule.method,
        confidence: outcome.confidence,
        explanation: outcome.explanation,
        standard_path: rule.standard_path.clone(),
        standard_anchor: rule.standard_anchor.clone(),
        source_url: format!(
            "https://github.com/eth-act/zkevm-standards/blob/{standards_commit}/{}#{}",
            rule.standard_path, rule.standard_anchor
        ),
        evidence: outcome.evidence,
    }
}

struct Outcome {
    status: FindingStatus,
    confidence: Confidence,
    explanation: String,
    evidence: BTreeMap<String, serde_json::Value>,
}

fn bool_outcome(value: bool, pass_text: &str, fail_text: &str, evidence_key: &str) -> Outcome {
    let mut evidence = BTreeMap::new();
    evidence.insert(evidence_key.to_string(), json!(value));
    if value {
        pass(pass_text, evidence)
    } else {
        fail(fail_text, evidence)
    }
}

fn optional_bool_outcome(
    value: Option<bool>,
    pass_text: &str,
    fail_text: &str,
    unknown_text: &str,
    evidence_key: &str,
) -> Outcome {
    let mut evidence = BTreeMap::new();
    evidence.insert(evidence_key.to_string(), json!(value));
    match value {
        Some(true) => pass(pass_text, evidence),
        Some(false) => fail(fail_text, evidence),
        None => unknown(unknown_text, evidence),
    }
}

fn symbol_outcome(value: Option<u64>, name: &str, pass_text: &str) -> Outcome {
    let mut evidence = BTreeMap::new();
    evidence.insert(
        name.to_string(),
        json!(value.map(|address| format!("0x{address:X}"))),
    );
    if value.is_some() {
        pass(pass_text, evidence)
    } else {
        unknown(
            &format!(
                "The {name} symbol is not visible; stripping or garbage collection prevents a conclusive failure."
            ),
            evidence,
        )
    }
}

fn presence_outcome(value: bool, pass_text: &str, fail_text: &str, url: Option<&str>) -> Outcome {
    let mut evidence = BTreeMap::new();
    evidence.insert("published".into(), json!(value));
    evidence.insert("url".into(), json!(url));
    if value {
        pass(pass_text, evidence)
    } else {
        fail(fail_text, evidence)
    }
}

fn declares_atomic_extension(arch: &str) -> bool {
    arch.split('_')
        .any(|part| part.starts_with('a') && part[1..].starts_with(|c: char| c.is_ascii_digit()))
}

fn runtime_explanation(evaluator: &str) -> String {
    match evaluator {
        "runtime.zicclsm" => "Zicclsm support is a zkVM runtime capability and cannot be established from a guest ELF.".into(),
        "runtime.unaligned_metrics" => "Per-proof unaligned-access observability requires zkVM execution telemetry.".into(),
        "runtime.loader" => "Loader validation and deterministic initialization require negative and behavioral runtime tests.".into(),
        "runtime.io" => "IO idempotence, zero-copy behavior, and output concatenation require execution tests.".into(),
        "runtime.static_library" => "Startup initialization, ABI calls, and constructor behavior require vendor-library/runtime tests.".into(),
        "runtime.accelerators" => "C interface behavior and actual accelerator use require linking and execution tests.".into(),
        "runtime.termination" => "Successful, non-zero, panic, and verifier behavior require execution and proof tests.".into(),
        "runtime.memory_layout" => "The standard leaves addresses vendor-defined; a platform manifest and linker/runtime test are required.".into(),
        "runtime.guard_regions" => "Null and stack guard behavior requires deliberate faulting guest programs.".into(),
        "runtime.misaligned_instruction" => "Instruction-address-misaligned termination requires a deliberate runtime test.".into(),
        _ => "Runtime evidence is outside v1 static analysis.".into(),
    }
}

fn pass(text: &str, evidence: BTreeMap<String, serde_json::Value>) -> Outcome {
    Outcome {
        status: FindingStatus::Pass,
        confidence: Confidence::High,
        explanation: text.to_string(),
        evidence,
    }
}

fn fail(text: &str, evidence: BTreeMap<String, serde_json::Value>) -> Outcome {
    Outcome {
        status: FindingStatus::Fail,
        confidence: Confidence::High,
        explanation: text.to_string(),
        evidence,
    }
}

fn warning(text: &str, evidence: BTreeMap<String, serde_json::Value>) -> Outcome {
    Outcome {
        status: FindingStatus::Warning,
        confidence: Confidence::Medium,
        explanation: text.to_string(),
        evidence,
    }
}

fn unknown(text: &str, evidence: BTreeMap<String, serde_json::Value>) -> Outcome {
    Outcome {
        status: FindingStatus::Unknown,
        confidence: Confidence::Low,
        explanation: text.to_string(),
        evidence,
    }
}

fn not_applicable(text: &str, evidence: BTreeMap<String, serde_json::Value>) -> Outcome {
    Outcome {
        status: FindingStatus::NotApplicable,
        confidence: Confidence::NotApplicable,
        explanation: text.to_string(),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::model::{Confidence, FindingStatus, FindingSubject, VerificationMethod};

    use super::{RuleDefinition, RuleScope, build_finding, declares_atomic_extension, pass};

    #[test]
    fn detects_atomic_extension_token() {
        assert!(declares_atomic_extension("rv64i2p1_m2p0_a2p1_zmmul1p0"));
        assert!(!declares_atomic_extension("rv64i2p1_m2p0_zmmul1p0"));
    }

    #[test]
    fn stale_rule_becomes_unknown_without_dropping_observed_evidence() {
        let rule = RuleDefinition {
            id: "test.rule".into(),
            title: "Test".into(),
            scope: RuleScope::Artifact,
            subject: FindingSubject::Artifact,
            method: VerificationMethod::Static,
            standard_path: "standards/test.md".into(),
            standard_anchor: "test".into(),
            reviewed_blob_sha: "reviewed".into(),
            evaluator: "test".into(),
        };
        let mut evidence = BTreeMap::new();
        evidence.insert("raw_metric".into(), json!(42));
        let finding = build_finding(
            &rule,
            pass("would pass before drift", evidence),
            "commit",
            Some(&"changed".to_string()),
        );
        assert_eq!(finding.status, FindingStatus::Unknown);
        assert_eq!(finding.confidence, Confidence::Low);
        assert_eq!(finding.evidence["raw_metric"], json!(42));
        assert_eq!(finding.evidence["current_blob_sha"], json!("changed"));
    }
}
