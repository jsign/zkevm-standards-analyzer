use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use anyhow::{Context, bail};
use chrono::Utc;
use tempfile::TempDir;

use crate::{
    cache::AssetCache,
    elf::analyze_elf,
    github::{DownloadResult, GithubAsset, GithubClient, GithubRelease},
    model::{
        AnalyzerIdentity, ArtifactOrigin, ArtifactReport, AssetEvidence, EvidenceCounts,
        LicenseEvidence, PlatformReport, ProvenanceEvidence, ReleaseIdentity, ReportSchemaVersion,
        ReportV1, SourceEvidence, StandardsSource,
    },
    release::{compiler_version, discover_elves, parse_source_asset_url},
    rules::{
        ReleaseRuleContext, artifact_findings, load_catalog, platform_findings, release_findings,
        stale_paths,
    },
};

const ERE_OWNER: &str = "eth-act";
const ERE_REPO: &str = "ere-guests";
const STANDARDS_OWNER: &str = "eth-act";
const STANDARDS_REPO: &str = "zkevm-standards";

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub release: String,
    pub standards_ref: String,
    pub rules_path: PathBuf,
    pub cache_dir: PathBuf,
}

pub async fn analyze(options: AnalyzeOptions) -> anyhow::Result<ReportV1> {
    let catalog = load_catalog(&options.rules_path)?;
    let github = GithubClient::new()?;

    let (release, standards) = tokio::try_join!(
        github.release(ERE_OWNER, ERE_REPO, &options.release),
        github.resolve_ref(STANDARDS_OWNER, STANDARDS_REPO, &options.standards_ref)
    )?;
    let release_ref = github
        .resolve_ref(ERE_OWNER, ERE_REPO, &release.tag_name)
        .await
        .context("failed to resolve the release tag to a commit")?;
    let discovered = discover_elves(&release, &catalog.zkvm_identifiers);
    if !discovered
        .iter()
        .any(|artifact| artifact.variant == crate::model::ArtifactVariant::Primary)
    {
        bail!(
            "release {} contains no recognized primary ELF",
            release.tag_name
        );
    }

    let stale = stale_paths(&catalog, &standards.blobs);
    let referenced_paths = catalog
        .rules
        .iter()
        .map(|rule| rule.standard_path.as_str())
        .collect::<BTreeSet<_>>();
    let referenced_blobs = standards
        .blobs
        .iter()
        .filter(|(path, _)| referenced_paths.contains(path.as_str()))
        .map(|(path, sha)| (path.clone(), sha.clone()))
        .collect();
    let workflow_url = github
        .successful_workflow_url(
            ERE_OWNER,
            ERE_REPO,
            &release_ref.commit,
            "Compile and Release Compiled Guests",
        )
        .await
        .ok()
        .flatten();
    let ere_license = github
        .license_evidence(ERE_OWNER, ERE_REPO, &release_ref.commit)
        .await;
    let public_key_url = release
        .assets
        .iter()
        .find(|asset| asset.name == "minisign.pub")
        .map(|asset| asset.browser_download_url.clone());

    let tempdir = tempfile::tempdir().context("failed to create analysis workspace")?;
    let mut cache = DownloadCache::new(&github, tempdir, &options.cache_dir);
    let assets_by_name = release
        .assets
        .iter()
        .map(|asset| (asset.name.clone(), asset.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut source_releases = HashMap::<String, GithubRelease>::new();
    let mut source_licenses = HashMap::<String, LicenseEvidence>::new();
    let mut artifacts = Vec::new();

    for discovered_elf in discovered {
        let (elf_evidence, elf_path) = asset_evidence(
            &mut cache,
            &discovered_elf.asset,
            signature_for(&assets_by_name, &discovered_elf.asset.name),
        )
        .await;
        let operational_error = elf_evidence.error.clone();
        let analysis = elf_path
            .as_deref()
            .map(|path| {
                let patterns = catalog
                    .accelerator_symbol_patterns
                    .get(&discovered_elf.zkvm)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                analyze_elf(path, patterns)
            })
            .transpose()
            .map_err(|error| error.to_string());
        let (analysis, operational_error) = match analysis {
            Ok(analysis) => (analysis, operational_error),
            Err(error) => (None, Some(error)),
        };

        let vk_name = format!("{}.vk", discovered_elf.family_id);
        let verification_key = if let Some(vk_asset) = assets_by_name.get(&vk_name) {
            let (evidence, _) = asset_evidence(
                &mut cache,
                vk_asset,
                signature_for(&assets_by_name, &vk_asset.name),
            )
            .await;
            Some(evidence)
        } else {
            None
        };

        let metadata = discovered_elf.metadata.as_ref();
        let mut ingestion_warnings = Vec::new();
        match metadata {
            None => ingestion_warnings.push(
                "No matching release-note metadata row was parsed; identity was retained from the asset filename."
                    .into(),
            ),
            Some(row) => {
                if row.guest != discovered_elf.guest || row.zkvm != discovered_elf.zkvm {
                    ingestion_warnings.push(
                        "Release-note guest/zkVM identity differs from the authoritative asset filename."
                            .into(),
                    );
                }
                if row.guest_version.is_empty()
                    || row.zkvm_version.is_empty()
                    || row.target.is_empty()
                {
                    ingestion_warnings.push(
                        "The matching release-note row has incomplete version or target metadata."
                            .into(),
                    );
                }
            }
        }
        let origin = metadata
            .map(|row| row.origin)
            .unwrap_or(ArtifactOrigin::Compiled);
        let source = if let Some(raw_source) = metadata.and_then(|row| row.source_url.as_deref()) {
            analyze_source(
                &github,
                &mut cache,
                &mut source_releases,
                raw_source,
                elf_evidence.computed_sha256.as_deref(),
            )
            .await
        } else {
            None
        };
        let licenses = if let Some(raw_source) = metadata.and_then(|row| row.source_url.as_deref())
        {
            source_license(
                &github,
                &mut source_releases,
                &mut source_licenses,
                raw_source,
            )
            .await
            .unwrap_or_else(|| LicenseEvidence {
                repository: "unknown".into(),
                reference: "unknown".into(),
                error: Some("source release URL could not be resolved".into()),
                ..LicenseEvidence::default()
            })
        } else {
            ere_license.clone()
        };

        let provenance = ProvenanceEvidence {
            elf: elf_evidence,
            verification_key,
            public_key_url: public_key_url.clone(),
            signature_policy:
                "presence_only: signature files are not cryptographically verified in v1".into(),
            source,
            workflow_url: workflow_url.clone(),
            licenses,
        };
        let guest_version = metadata
            .map(|row| row.guest_version.clone())
            .filter(|value| !value.is_empty());
        let zkvm_version = metadata
            .map(|row| row.zkvm_version.clone())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| discovered_elf.zkvm_version.clone());
        let release_target_label = metadata
            .map(|row| row.target.clone())
            .filter(|value| !value.is_empty());
        let mut artifact = ArtifactReport {
            id: discovered_elf.id,
            family_id: discovered_elf.family_id,
            guest: discovered_elf.guest,
            guest_version,
            zkvm: discovered_elf.zkvm,
            zkvm_version,
            variant: discovered_elf.variant,
            origin,
            release_target_label,
            analysis,
            provenance,
            findings: Vec::new(),
            ingestion_warnings,
            operational_error,
        };
        artifact.findings =
            artifact_findings(&catalog, &artifact, &standards.commit, &standards.blobs);
        artifacts.push(artifact);
    }

    let zkvm_names = artifacts
        .iter()
        .map(|artifact| artifact.zkvm.clone())
        .collect::<BTreeSet<_>>();
    let platforms = zkvm_names
        .into_iter()
        .map(|zkvm| PlatformReport {
            findings: platform_findings(&catalog, &zkvm, &standards.commit, &standards.blobs),
            zkvm,
        })
        .collect::<Vec<_>>();

    let compiler = compiler_version(&release.body);
    let readiness = release_findings(
        &catalog,
        ReleaseRuleContext {
            compiler: compiler.as_deref(),
            license: &ere_license,
            workflow_url: workflow_url.as_deref(),
        },
        &standards.commit,
        &standards.blobs,
    );

    let mut summary = EvidenceCounts::default();
    for finding in artifacts
        .iter()
        .flat_map(|artifact| artifact.findings.iter())
        .chain(
            platforms
                .iter()
                .flat_map(|platform| platform.findings.iter()),
        )
        .chain(readiness.iter())
    {
        summary.add(finding.status);
    }

    Ok(ReportV1 {
        schema_version: ReportSchemaVersion::V1,
        generated_at: Utc::now().to_rfc3339(),
        analyzer: AnalyzerIdentity {
            version: env!("CARGO_PKG_VERSION").into(),
            commit: option_env!("GIT_COMMIT_SHA")
                .map(str::to_string)
                .or_else(|| std::env::var("GITHUB_SHA").ok()),
        },
        standards: StandardsSource {
            repository: format!("{STANDARDS_OWNER}/{STANDARDS_REPO}"),
            requested_ref: options.standards_ref,
            commit: standards.commit,
            tree: standards.tree,
            reviewed_snapshot: catalog.reviewed_snapshot,
            blobs: referenced_blobs,
            stale_paths: stale,
        },
        release: ReleaseIdentity {
            repository: format!("{ERE_OWNER}/{ERE_REPO}"),
            tag: release.tag_name,
            commit: release_ref.commit,
            published_at: release.published_at,
            url: release.html_url,
            name: release.name,
            compiler,
            workflow_url,
        },
        summary,
        artifacts,
        platforms,
        readiness,
    })
}

async fn analyze_source(
    github: &GithubClient,
    cache: &mut DownloadCache<'_>,
    releases: &mut HashMap<String, GithubRelease>,
    raw_source: &str,
    hub_sha: Option<&str>,
) -> Option<SourceEvidence> {
    let parsed = parse_source_asset_url(raw_source)?;
    let key = format!("{}/{}@{}", parsed.owner, parsed.repo, parsed.tag);
    let release = if let Some(release) = releases.get(&key) {
        release.clone()
    } else {
        match github
            .release(&parsed.owner, &parsed.repo, &parsed.tag)
            .await
        {
            Ok(release) => {
                releases.insert(key.clone(), release.clone());
                release
            }
            Err(error) => {
                return Some(SourceEvidence {
                    repository: format!("{}/{}", parsed.owner, parsed.repo),
                    release_tag: parsed.tag,
                    release_url: format!(
                        "https://github.com/{}/{}/releases",
                        parsed.owner, parsed.repo
                    ),
                    asset_url: raw_source.into(),
                    computed_sha256: None,
                    matches_hub_asset: None,
                    signature_url: None,
                    signature_published: false,
                    error: Some(error.to_string()),
                });
            }
        }
    };
    let source_asset = release
        .assets
        .iter()
        .find(|asset| asset.name == parsed.asset_name);
    let source_signature = release
        .assets
        .iter()
        .find(|asset| asset.name == format!("{}.minisig", parsed.asset_name));
    let Some(source_asset) = source_asset else {
        return Some(SourceEvidence {
            repository: format!("{}/{}", parsed.owner, parsed.repo),
            release_tag: parsed.tag,
            release_url: release.html_url,
            asset_url: raw_source.into(),
            computed_sha256: None,
            matches_hub_asset: None,
            signature_url: source_signature.map(|asset| asset.browser_download_url.clone()),
            signature_published: source_signature.is_some(),
            error: Some("source release does not contain the declared asset".into()),
        });
    };
    match cache.get(source_asset).await {
        Ok(download) => Some(SourceEvidence {
            repository: format!("{}/{}", parsed.owner, parsed.repo),
            release_tag: parsed.tag,
            release_url: release.html_url,
            asset_url: source_asset.browser_download_url.clone(),
            computed_sha256: Some(download.result.sha256.clone()),
            matches_hub_asset: hub_sha.map(|sha| sha == download.result.sha256),
            signature_url: source_signature.map(|asset| asset.browser_download_url.clone()),
            signature_published: source_signature.is_some(),
            error: None,
        }),
        Err(error) => Some(SourceEvidence {
            repository: format!("{}/{}", parsed.owner, parsed.repo),
            release_tag: parsed.tag,
            release_url: release.html_url,
            asset_url: source_asset.browser_download_url.clone(),
            computed_sha256: None,
            matches_hub_asset: None,
            signature_url: source_signature.map(|asset| asset.browser_download_url.clone()),
            signature_published: source_signature.is_some(),
            error: Some(error.to_string()),
        }),
    }
}

async fn source_license(
    github: &GithubClient,
    releases: &mut HashMap<String, GithubRelease>,
    licenses: &mut HashMap<String, LicenseEvidence>,
    raw_source: &str,
) -> Option<LicenseEvidence> {
    let parsed = parse_source_asset_url(raw_source)?;
    let key = format!("{}/{}@{}", parsed.owner, parsed.repo, parsed.tag);
    if let Some(license) = licenses.get(&key) {
        return Some(license.clone());
    }
    if !releases.contains_key(&key) {
        let release = github
            .release(&parsed.owner, &parsed.repo, &parsed.tag)
            .await
            .ok()?;
        releases.insert(key.clone(), release);
    }
    let license = github
        .license_evidence(&parsed.owner, &parsed.repo, &parsed.tag)
        .await;
    licenses.insert(key, license.clone());
    Some(license)
}

fn signature_for<'a>(
    assets: &'a BTreeMap<String, GithubAsset>,
    asset_name: &str,
) -> Option<&'a GithubAsset> {
    assets.get(&format!("{asset_name}.minisig"))
}

async fn asset_evidence(
    cache: &mut DownloadCache<'_>,
    asset: &GithubAsset,
    signature: Option<&GithubAsset>,
) -> (AssetEvidence, Option<PathBuf>) {
    match cache.get(asset).await {
        Ok(download) => {
            let digest_matches =
                compare_github_digest(asset.digest.as_deref(), &download.result.sha256);
            (
                AssetEvidence {
                    name: asset.name.clone(),
                    url: asset.browser_download_url.clone(),
                    size: download.result.size,
                    github_digest: asset.digest.clone(),
                    computed_sha256: Some(download.result.sha256.clone()),
                    digest_matches,
                    signature_url: signature.map(|asset| asset.browser_download_url.clone()),
                    signature_published: signature.is_some(),
                    error: None,
                },
                Some(download.path.clone()),
            )
        }
        Err(error) => (
            AssetEvidence {
                name: asset.name.clone(),
                url: asset.browser_download_url.clone(),
                size: asset.size,
                github_digest: asset.digest.clone(),
                computed_sha256: None,
                digest_matches: None,
                signature_url: signature.map(|asset| asset.browser_download_url.clone()),
                signature_published: signature.is_some(),
                error: Some(error.to_string()),
            },
            None,
        ),
    }
}

fn compare_github_digest(digest: Option<&str>, computed_sha256: &str) -> Option<bool> {
    digest
        .and_then(|value| value.strip_prefix("sha256:"))
        .map(|expected| expected.eq_ignore_ascii_case(computed_sha256))
}

#[derive(Debug, Clone)]
struct CachedDownload {
    path: PathBuf,
    result: DownloadResult,
}

struct DownloadCache<'a> {
    github: &'a GithubClient,
    workspace: TempDir,
    persistent: Option<AssetCache>,
    entries: HashMap<String, CachedDownload>,
    next_id: usize,
}

impl<'a> DownloadCache<'a> {
    fn new(github: &'a GithubClient, workspace: TempDir, cache_dir: &std::path::Path) -> Self {
        let persistent = match AssetCache::new(cache_dir) {
            Ok(cache) => Some(cache),
            Err(error) => {
                eprintln!(
                    "warning: persistent asset cache at {} is unavailable: {error:#}",
                    cache_dir.display()
                );
                None
            }
        };
        Self {
            github,
            workspace,
            persistent,
            entries: HashMap::new(),
            next_id: 0,
        }
    }

    async fn get(&mut self, asset: &GithubAsset) -> anyhow::Result<CachedDownload> {
        if let Some(download) = self.entries.get(&asset.browser_download_url) {
            return Ok(download.clone());
        }
        if let Some(persistent) = &self.persistent {
            match persistent.lookup(
                &asset.browser_download_url,
                asset.size,
                asset.digest.as_deref(),
            ) {
                Ok(Some(cached)) => {
                    let download = CachedDownload {
                        path: cached.path,
                        result: cached.result,
                    };
                    self.entries
                        .insert(asset.browser_download_url.clone(), download.clone());
                    return Ok(download);
                }
                Ok(None) => {}
                Err(error) => eprintln!(
                    "warning: failed to read cached asset {}: {error:#}",
                    asset.name
                ),
            }
        }
        let safe_hint = asset
            .name
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let path = self
            .workspace
            .path()
            .join(format!("{:03}-{safe_hint}", self.next_id));
        self.next_id += 1;
        let result = self
            .github
            .download_to(&asset.browser_download_url, &path)
            .await?;
        let download = if let Some(persistent) = &self.persistent {
            match persistent.store(
                &asset.browser_download_url,
                asset.size,
                asset.digest.as_deref(),
                &path,
                &result,
            ) {
                Ok(cached) => CachedDownload {
                    path: cached.path,
                    result: cached.result,
                },
                Err(error) => {
                    eprintln!(
                        "warning: failed to cache downloaded asset {}: {error:#}",
                        asset.name
                    );
                    CachedDownload { path, result }
                }
            }
        } else {
            CachedDownload { path, result }
        };
        self.entries
            .insert(asset.browser_download_url.clone(), download.clone());
        Ok(download)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        github::{GithubAsset, GithubRelease},
        release::discover_elves,
    };

    use super::{compare_github_digest, signature_for};

    #[test]
    fn groups_profiling_variant_with_primary_family() {
        let release = GithubRelease {
            tag_name: "v1".into(),
            target_commitish: "abc".into(),
            html_url: "https://github.com/example/release".into(),
            published_at: "2026-01-01T00:00:00Z".into(),
            name: None,
            body: String::new(),
            assets: vec![
                asset("stateless-validator-reth-zisk-v1.0.0.elf"),
                asset("stateless-validator-reth-zisk-v1.0.0-profiling.elf"),
            ],
        };
        let zkvms = vec!["zisk".to_string()];
        let artifacts = discover_elves(&release, &zkvms);
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].family_id, artifacts[1].family_id);
    }

    #[test]
    fn pairs_exact_signature_names() {
        let elf = asset("guest.elf");
        let signature = asset("guest.elf.minisig");
        let assets = [elf, signature.clone()]
            .into_iter()
            .map(|asset| (asset.name.clone(), asset))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            signature_for(&assets, "guest.elf").map(|asset| asset.name.as_str()),
            Some(signature.name.as_str())
        );
        assert!(signature_for(&assets, "other.elf").is_none());
    }

    #[test]
    fn compares_only_github_sha256_digests() {
        assert_eq!(
            compare_github_digest(Some("sha256:ABCDEF"), "abcdef"),
            Some(true)
        );
        assert_eq!(
            compare_github_digest(Some("sha256:000000"), "abcdef"),
            Some(false)
        );
        assert_eq!(compare_github_digest(Some("sha512:abc"), "abc"), None);
        assert_eq!(compare_github_digest(None, "abc"), None);
    }

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: format!("https://github.com/example/{name}"),
            size: 1,
            digest: None,
        }
    }
}
