use std::collections::BTreeMap;

use regex::Regex;
use url::Url;

use crate::{
    github::{GithubAsset, GithubRelease},
    model::ArtifactOrigin,
};

#[derive(Debug, Clone)]
pub struct DiscoveredElf {
    pub asset: GithubAsset,
    pub id: String,
    pub family_id: String,
    pub guest: String,
    pub zkvm: String,
    pub zkvm_version: String,
    pub metadata: Option<ReleaseRow>,
}

#[derive(Debug, Clone)]
pub struct ReleaseRow {
    pub guest: String,
    pub guest_version: String,
    pub zkvm: String,
    pub zkvm_version: String,
    pub target: String,
    pub asset_name: String,
    pub origin: ArtifactOrigin,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceAssetUrl {
    pub owner: String,
    pub repo: String,
    pub tag: String,
    pub asset_name: String,
}

pub fn compiler_version(body: &str) -> Option<String> {
    Regex::new(r"Built with Ere compiler version:\s*`([^`]+)`")
        .expect("valid compiler regex")
        .captures(body)
        .map(|captures| captures[1].to_string())
}

pub fn discover_elves(release: &GithubRelease, zkvm_identifiers: &[String]) -> Vec<DiscoveredElf> {
    let rows = parse_release_rows(&release.body);
    let row_by_asset: BTreeMap<_, _> = rows
        .into_iter()
        .map(|row| (row.asset_name.clone(), row))
        .collect();

    let mut discovered = release
        .assets
        .iter()
        .filter_map(|asset| {
            let filename = asset.name.strip_suffix(".elf")?;
            if filename.ends_with("-profiling") {
                return None;
            }
            let family = filename;
            let parsed = parse_artifact_stem(family, zkvm_identifiers)?;
            let metadata = row_by_asset
                .get(&asset.name)
                .or_else(|| row_by_asset.get(&format!("{family}.elf")))
                .cloned();
            Some(DiscoveredElf {
                asset: asset.clone(),
                id: filename.to_string(),
                family_id: family.to_string(),
                guest: parsed.0,
                zkvm: parsed.1,
                zkvm_version: parsed.2,
                metadata,
            })
        })
        .collect::<Vec<_>>();
    discovered.sort_by(|left, right| {
        (
            left.guest.as_str(),
            left.zkvm.as_str(),
            left.zkvm_version.as_str(),
        )
            .cmp(&(
                right.guest.as_str(),
                right.zkvm.as_str(),
                right.zkvm_version.as_str(),
            ))
    });
    discovered
}

pub fn parse_release_rows(body: &str) -> Vec<ReleaseRow> {
    let link_regex = Regex::new(r"\[[^\]]+\]\((https://[^)]+)\)").expect("valid link regex");
    let source_regex = Regex::new(r"\[Source\]\((https://[^)]+)\)").expect("valid source regex");
    let mut origin = ArtifactOrigin::Compiled;
    let mut rows = Vec::new();

    for line in body.lines() {
        if line.starts_with("## Republished guest programs") {
            origin = ArtifactOrigin::Republished;
            continue;
        }
        if line.starts_with("## Compiled guest programs") {
            origin = ArtifactOrigin::Compiled;
            continue;
        }
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let cells = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim())
            .collect::<Vec<_>>();
        if cells.len() < 7 || cells[0].contains("---") || cells[0].contains("Stateless Validator") {
            continue;
        }

        let links = link_regex
            .captures_iter(cells[5])
            .map(|capture| capture[1].to_string())
            .collect::<Vec<_>>();
        let Some(asset_url) = links.first() else {
            continue;
        };
        let Ok(url) = Url::parse(asset_url) else {
            continue;
        };
        let Some(asset_name) = url.path_segments().and_then(Iterator::last) else {
            continue;
        };
        rows.push(ReleaseRow {
            guest: clean_cell(cells[0]),
            guest_version: clean_cell(cells[1]),
            zkvm: clean_cell(cells[2]),
            zkvm_version: clean_cell(cells[3]),
            target: clean_cell(cells[4]),
            asset_name: asset_name.to_string(),
            origin,
            source_url: source_regex
                .captures(cells[5])
                .map(|capture| capture[1].to_string()),
        });
    }
    rows
}

pub fn parse_source_asset_url(raw: &str) -> Option<SourceAssetUrl> {
    let url = Url::parse(raw).ok()?;
    if url.host_str()? != "github.com" {
        return None;
    }
    let parts = url.path_segments()?.collect::<Vec<_>>();
    if parts.len() < 6 || parts[2] != "releases" || parts[3] != "download" {
        return None;
    }
    Some(SourceAssetUrl {
        owner: parts[0].to_string(),
        repo: parts[1].to_string(),
        tag: parts[4].to_string(),
        asset_name: parts[5..].join("/"),
    })
}

fn parse_artifact_stem(
    stem: &str,
    zkvm_identifiers: &[String],
) -> Option<(String, String, String)> {
    let stem = stem.strip_prefix("stateless-validator-")?;
    for zkvm in zkvm_identifiers {
        let needle = format!("-{zkvm}-");
        if let Some((guest, version)) = stem.rsplit_once(&needle)
            && !guest.is_empty()
            && !version.is_empty()
        {
            return Some((guest.to_string(), zkvm.to_string(), version.to_string()));
        }
    }
    None
}

fn clean_cell(cell: &str) -> String {
    cell.trim().trim_matches('`').to_string()
}

#[cfg(test)]
mod tests {
    use super::{discover_elves, parse_artifact_stem, parse_release_rows, parse_source_asset_url};
    use crate::github::{GithubAsset, GithubRelease};
    use crate::model::ArtifactOrigin;

    #[test]
    fn parses_compiled_and_republished_rows() {
        let body = r#"
## Compiled guest programs
| Stateless Validator | Version | zkVM | zkVM Version | Target | ELF | Program VK |
| --- | --- | --- | --- | --- | --- | --- |
| `reth` | `abc123` | `sp1` | `v6.3.1` | `riscv64im` | [Link](https://github.com/eth-act/ere-guests/releases/download/v1/stateless-validator-reth-sp1-v6.3.1.elf) | [Link](vk) |
## Republished guest programs
| `zesu` | `devnet` | `zisk` | `v1.0.0-alpha` | `riscv64im` | [Link](https://github.com/eth-act/ere-guests/releases/download/v1/stateless-validator-zesu-zisk-v1.0.0-alpha.elf) / [Source](https://github.com/Consensys/zesu-zkvm/releases/download/devnet/stateless-validator-zesu-zisk-1.0.0-alpha.elf) | [Link](vk) |
"#;
        let rows = parse_release_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].origin, ArtifactOrigin::Compiled);
        assert_eq!(rows[1].origin, ArtifactOrigin::Republished);
        assert!(rows[1].source_url.is_some());
    }

    #[test]
    fn parses_source_release_url() {
        let parsed = parse_source_asset_url(
            "https://github.com/Consensys/zesu-zkvm/releases/download/devnet/file.elf",
        )
        .unwrap();
        assert_eq!(parsed.owner, "Consensys");
        assert_eq!(parsed.repo, "zesu-zkvm");
        assert_eq!(parsed.tag, "devnet");
        assert_eq!(parsed.asset_name, "file.elf");
    }

    #[test]
    fn recognizes_only_configured_zkvms() {
        let configured = vec!["sp1".to_string()];
        assert!(parse_artifact_stem("stateless-validator-reth-sp1-v6.3.1", &configured).is_some());
        assert!(
            parse_artifact_stem("stateless-validator-reth-openvm-v2.0.0", &configured).is_none()
        );
    }

    #[test]
    fn retains_recognized_asset_when_release_table_is_malformed() {
        let release = GithubRelease {
            tag_name: "v1".into(),
            target_commitish: "main".into(),
            html_url: "https://github.com/example/release".into(),
            published_at: "2026-01-01T00:00:00Z".into(),
            name: None,
            body: "| malformed | release | row |".into(),
            assets: vec![GithubAsset {
                name: "stateless-validator-reth-sp1-v1.0.0.elf".into(),
                browser_download_url: "https://github.com/example/guest.elf".into(),
                size: 1,
                digest: None,
            }],
        };
        let artifacts = discover_elves(&release, &["sp1".to_string()]);
        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].metadata.is_none());
    }

    #[test]
    fn ignores_profiling_elves() {
        let release = GithubRelease {
            tag_name: "v1".into(),
            target_commitish: "main".into(),
            html_url: "https://github.com/example/release".into(),
            published_at: "2026-01-01T00:00:00Z".into(),
            name: None,
            body: String::new(),
            assets: vec![
                asset("stateless-validator-reth-zisk-v1.0.0.elf"),
                asset("stateless-validator-reth-zisk-v1.0.0-profiling.elf"),
            ],
        };

        let artifacts = discover_elves(&release, &["zisk".to_string()]);

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].id, "stateless-validator-reth-zisk-v1.0.0");
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
