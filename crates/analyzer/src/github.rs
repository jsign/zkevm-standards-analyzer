use std::{collections::BTreeMap, fs::File, io::Write, path::Path, time::Duration};

use anyhow::{Context, anyhow, bail};
use futures_util::StreamExt;
use reqwest::{
    Client, Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT},
    redirect::{Attempt, Policy},
};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use url::Url;

use crate::model::LicenseEvidence;

const API_ROOT: &str = "https://api.github.com";
const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;
const RETRIES: usize = 3;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub target_commitish: String,
    pub html_url: String,
    pub published_at: String,
    pub name: Option<String>,
    #[serde(default)]
    pub body: String,
    pub assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRef {
    pub commit: String,
    pub tree: String,
    pub blobs: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone)]
pub struct GithubClient {
    client: Client,
}

impl GithubClient {
    pub fn new() -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("jsign/zkevm-standards-analyzer"),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        if let Ok(token) = std::env::var("GITHUB_TOKEN")
            && !token.trim().is_empty()
        {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }

        let client = Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(180))
            .redirect(Policy::custom(validate_redirect))
            .build()?;
        Ok(Self { client })
    }

    pub async fn release(
        &self,
        owner: &str,
        repo: &str,
        release: &str,
    ) -> anyhow::Result<GithubRelease> {
        let endpoint = if release == "latest" {
            format!("{API_ROOT}/repos/{owner}/{repo}/releases/latest")
        } else {
            format!("{API_ROOT}/repos/{owner}/{repo}/releases/tags/{release}")
        };
        self.get_json(&endpoint)
            .await
            .with_context(|| format!("failed to resolve {owner}/{repo} release {release}"))
    }

    pub async fn resolve_ref(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> anyhow::Result<ResolvedRef> {
        #[derive(Deserialize)]
        struct CommitResponse {
            sha: String,
            commit: CommitDetail,
        }
        #[derive(Deserialize)]
        struct CommitDetail {
            tree: TreePointer,
        }
        #[derive(Deserialize)]
        struct TreePointer {
            sha: String,
        }
        #[derive(Deserialize)]
        struct TreeResponse {
            tree: Vec<TreeEntry>,
            truncated: bool,
        }
        #[derive(Deserialize)]
        struct TreeEntry {
            path: String,
            #[serde(rename = "type")]
            kind: String,
            sha: String,
        }

        let commit: CommitResponse = self
            .get_json(&format!(
                "{API_ROOT}/repos/{owner}/{repo}/commits/{reference}"
            ))
            .await?;
        let tree: TreeResponse = self
            .get_json(&format!(
                "{API_ROOT}/repos/{owner}/{repo}/git/trees/{}?recursive=1",
                commit.commit.tree.sha
            ))
            .await?;
        if tree.truncated {
            bail!("GitHub returned a truncated tree for {owner}/{repo}@{reference}");
        }
        let blobs = tree
            .tree
            .into_iter()
            .filter(|entry| entry.kind == "blob")
            .map(|entry| (entry.path, entry.sha))
            .collect();
        Ok(ResolvedRef {
            commit: commit.sha,
            tree: commit.commit.tree.sha,
            blobs,
        })
    }

    pub async fn successful_workflow_url(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
        preferred_name: &str,
    ) -> anyhow::Result<Option<String>> {
        #[derive(Deserialize)]
        struct WorkflowRuns {
            workflow_runs: Vec<WorkflowRun>,
        }
        #[derive(Deserialize)]
        struct WorkflowRun {
            name: String,
            status: String,
            conclusion: Option<String>,
            html_url: String,
        }

        let mut url = Url::parse(&format!("{API_ROOT}/repos/{owner}/{repo}/actions/runs"))?;
        url.query_pairs_mut().append_pair("head_sha", commit);
        let response: WorkflowRuns = self.get_json(url.as_str()).await?;
        let successful = response
            .workflow_runs
            .into_iter()
            .filter(|run| run.status == "completed" && run.conclusion.as_deref() == Some("success"))
            .collect::<Vec<_>>();
        Ok(successful
            .iter()
            .find(|run| run.name == preferred_name)
            .or_else(|| successful.first())
            .map(|run| run.html_url.clone()))
    }

    pub async fn license_evidence(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> LicenseEvidence {
        let repository = format!("{owner}/{repo}");
        match self.resolve_ref(owner, repo, reference).await {
            Ok(resolved) => {
                let mut inspected_paths: Vec<String> = resolved
                    .blobs
                    .keys()
                    .filter(|path| {
                        !path.contains('/') && path.to_ascii_lowercase().starts_with("license")
                    })
                    .cloned()
                    .collect();
                inspected_paths.sort();
                let names = inspected_paths
                    .iter()
                    .map(|path| path.to_ascii_lowercase())
                    .collect::<Vec<_>>();
                LicenseEvidence {
                    repository,
                    reference: resolved.commit,
                    mit: names.iter().any(|name| name.contains("mit")),
                    apache_2: names
                        .iter()
                        .any(|name| name.contains("apache") || name.contains("apache-2")),
                    inspected_paths,
                    error: None,
                }
            }
            Err(error) => LicenseEvidence {
                repository,
                reference: reference.to_string(),
                error: Some(error.to_string()),
                ..LicenseEvidence::default()
            },
        }
    }

    pub async fn download_to(
        &self,
        raw_url: &str,
        destination: &Path,
    ) -> anyhow::Result<DownloadResult> {
        let url = Url::parse(raw_url).context("asset URL is not valid")?;
        validate_asset_url(&url)?;

        let mut last_error = None;
        for attempt in 0..RETRIES {
            match self.download_once(url.as_str(), destination).await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < RETRIES {
                        tokio::time::sleep(Duration::from_millis(250 * (1_u64 << attempt))).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("download failed")))
            .with_context(|| format!("failed to download {url}"))
    }

    async fn download_once(&self, url: &str, destination: &Path) -> anyhow::Result<DownloadResult> {
        let response = self.client.get(url).send().await?.error_for_status()?;
        if let Some(length) = response.content_length()
            && length > MAX_ASSET_BYTES
        {
            bail!("asset declares {length} bytes, exceeding the 256 MiB limit");
        }

        let mut stream = response.bytes_stream();
        let mut file = File::create(destination)?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = size
                .checked_add(chunk.len() as u64)
                .context("asset size overflow")?;
            if size > MAX_ASSET_BYTES {
                bail!("asset exceeds the 256 MiB limit");
            }
            hasher.update(&chunk);
            file.write_all(&chunk)?;
        }
        file.flush()?;
        Ok(DownloadResult {
            sha256: hex::encode(hasher.finalize()),
            size,
        })
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let response = self.get_response(url).await?;
        Ok(response.json().await?)
    }

    async fn get_response(&self, url: &str) -> anyhow::Result<Response> {
        let parsed = Url::parse(url)?;
        validate_asset_url(&parsed)?;
        let mut last_error = None;
        for attempt in 0..RETRIES {
            match self.client.get(parsed.clone()).send().await {
                Ok(response)
                    if response.status().is_success()
                        || response.status() == StatusCode::NOT_FOUND =>
                {
                    return Ok(response.error_for_status()?);
                }
                Ok(response) => {
                    last_error = Some(anyhow!(
                        "GitHub returned HTTP {} for {}",
                        response.status(),
                        parsed
                    ));
                }
                Err(error) => last_error = Some(error.into()),
            }
            if attempt + 1 < RETRIES {
                tokio::time::sleep(Duration::from_millis(250 * (1_u64 << attempt))).await;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("GitHub request failed")))
    }
}

fn validate_redirect(attempt: Attempt<'_>) -> reqwest::redirect::Action {
    if attempt.previous().len() > 10 {
        return attempt.error("too many redirects");
    }
    match validate_asset_url(attempt.url()) {
        Ok(()) => attempt.follow(),
        Err(error) => attempt.error(error),
    }
}

fn validate_asset_url(url: &Url) -> anyhow::Result<()> {
    if url.scheme() != "https" {
        bail!("only HTTPS URLs are accepted");
    }
    let host = url.host_str().unwrap_or_default();
    const ALLOWED: &[&str] = &[
        "api.github.com",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "codeload.github.com",
    ];
    if !ALLOWED.contains(&host) && !host.ends_with(".githubusercontent.com") {
        bail!("untrusted asset host: {host}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_asset_url;

    #[test]
    fn asset_host_policy() {
        assert!(validate_asset_url(&"https://github.com/a/b".parse().unwrap()).is_ok());
        assert!(
            validate_asset_url(
                &"https://release-assets.githubusercontent.com/file"
                    .parse()
                    .unwrap()
            )
            .is_ok()
        );
        assert!(validate_asset_url(&"http://github.com/a/b".parse().unwrap()).is_err());
        assert!(validate_asset_url(&"https://example.com/a".parse().unwrap()).is_err());
    }
}
