use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::github::DownloadResult;

const CACHE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub(crate) struct CachedAsset {
    pub path: PathBuf,
    pub result: DownloadResult,
}

#[derive(Debug)]
pub(crate) struct AssetCache {
    objects_dir: PathBuf,
    urls_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct UrlEntry {
    schema_version: u8,
    url: String,
    published_size: u64,
    published_digest: Option<String>,
    sha256: String,
    size: u64,
}

impl AssetCache {
    pub fn new(root: &Path) -> anyhow::Result<Self> {
        let objects_dir = root.join("objects").join("sha256");
        let urls_dir = root.join("urls");
        fs::create_dir_all(&objects_dir)
            .with_context(|| format!("failed to create {}", objects_dir.display()))?;
        fs::create_dir_all(&urls_dir)
            .with_context(|| format!("failed to create {}", urls_dir.display()))?;
        Ok(Self {
            objects_dir,
            urls_dir,
        })
    }

    pub fn lookup(
        &self,
        url: &str,
        published_size: u64,
        published_digest: Option<&str>,
    ) -> anyhow::Result<Option<CachedAsset>> {
        if let Some(expected) = published_sha256(published_digest) {
            let path = self.object_path(&expected);
            if let Some(result) = verified_file(&path, &expected, None)? {
                return Ok(Some(CachedAsset { path, result }));
            }
        }

        let entry_path = self.url_entry_path(url);
        let entry_bytes = match fs::read(&entry_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", entry_path.display()));
            }
        };
        let Ok(entry) = serde_json::from_slice::<UrlEntry>(&entry_bytes) else {
            return Ok(None);
        };
        if entry.schema_version != CACHE_SCHEMA_VERSION
            || entry.url != url
            || entry.published_size != published_size
            || entry.published_digest.as_deref() != published_digest
            || !valid_sha256(&entry.sha256)
        {
            return Ok(None);
        }

        let path = self.object_path(&entry.sha256);
        Ok(verified_file(&path, &entry.sha256, Some(entry.size))?
            .map(|result| CachedAsset { path, result }))
    }

    pub fn store(
        &self,
        url: &str,
        published_size: u64,
        published_digest: Option<&str>,
        source: &Path,
        result: &DownloadResult,
    ) -> anyhow::Result<CachedAsset> {
        let object_path = self.object_path(&result.sha256);
        if verified_file(&object_path, &result.sha256, Some(result.size))?.is_none() {
            let mut temporary = tempfile::Builder::new()
                .prefix(".asset-")
                .tempfile_in(&self.objects_dir)
                .context("failed to create a temporary cache object")?;
            let mut input = File::open(source)
                .with_context(|| format!("failed to open {}", source.display()))?;
            std::io::copy(&mut input, &mut temporary)
                .context("failed to copy the downloaded asset into the cache")?;
            temporary
                .flush()
                .context("failed to flush the temporary cache object")?;
            temporary
                .persist(&object_path)
                .map_err(|error| error.error)
                .with_context(|| format!("failed to persist {}", object_path.display()))?;
        }

        let entry = UrlEntry {
            schema_version: CACHE_SCHEMA_VERSION,
            url: url.to_string(),
            published_size,
            published_digest: published_digest.map(str::to_string),
            sha256: result.sha256.clone(),
            size: result.size,
        };
        let entry_path = self.url_entry_path(url);
        let mut temporary = tempfile::Builder::new()
            .prefix(".url-")
            .tempfile_in(&self.urls_dir)
            .context("failed to create a temporary cache index entry")?;
        serde_json::to_writer(&mut temporary, &entry)
            .context("failed to serialize the cache index entry")?;
        temporary
            .flush()
            .context("failed to flush the cache index entry")?;
        temporary
            .persist(&entry_path)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to persist {}", entry_path.display()))?;

        Ok(CachedAsset {
            path: object_path,
            result: result.clone(),
        })
    }

    fn object_path(&self, sha256: &str) -> PathBuf {
        self.objects_dir.join(sha256)
    }

    fn url_entry_path(&self, url: &str) -> PathBuf {
        let digest = Sha256::digest(url.as_bytes());
        self.urls_dir.join(format!("{}.json", hex::encode(digest)))
    }
}

fn published_sha256(digest: Option<&str>) -> Option<String> {
    let value = digest?.strip_prefix("sha256:")?;
    valid_sha256(value).then(|| value.to_ascii_lowercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn verified_file(
    path: &Path,
    expected_sha256: &str,
    expected_size: Option<u64>,
) -> anyhow::Result<Option<DownloadResult>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    let sha256 = hex::encode(hasher.finalize());
    if !sha256.eq_ignore_ascii_case(expected_sha256)
        || expected_size.is_some_and(|expected| expected != size)
    {
        return Ok(None);
    }
    Ok(Some(DownloadResult { sha256, size }))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sha2::{Digest, Sha256};

    use super::AssetCache;
    use crate::github::DownloadResult;

    #[test]
    fn stores_and_reuses_a_verified_asset() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("download");
        fs::write(&source, b"guest elf").unwrap();
        let sha256 = hex::encode(Sha256::digest(b"guest elf"));
        let result = DownloadResult {
            sha256: sha256.clone(),
            size: 9,
        };
        let cache = AssetCache::new(&directory.path().join("cache")).unwrap();

        let stored = cache
            .store(
                "https://github.com/example/guest.elf",
                9,
                Some(&format!("sha256:{sha256}")),
                &source,
                &result,
            )
            .unwrap();
        fs::remove_file(source).unwrap();
        let cached = cache
            .lookup(
                "https://github.com/example/guest.elf",
                9,
                Some(&format!("sha256:{sha256}")),
            )
            .unwrap()
            .unwrap();

        assert_eq!(cached.path, stored.path);
        assert_eq!(cached.result.sha256, sha256);
        assert_eq!(fs::read(cached.path).unwrap(), b"guest elf");
    }

    #[test]
    fn published_digest_reuses_content_across_urls() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("download");
        fs::write(&source, b"same bytes").unwrap();
        let sha256 = hex::encode(Sha256::digest(b"same bytes"));
        let result = DownloadResult {
            sha256: sha256.clone(),
            size: 10,
        };
        let cache = AssetCache::new(&directory.path().join("cache")).unwrap();
        cache
            .store(
                "https://github.com/example/first.elf",
                10,
                Some(&format!("sha256:{sha256}")),
                &source,
                &result,
            )
            .unwrap();

        let cached = cache
            .lookup(
                "https://github.com/example/second.elf",
                10,
                Some(&format!("sha256:{sha256}")),
            )
            .unwrap();

        assert!(cached.is_some());
    }

    #[test]
    fn rejects_a_corrupted_object() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("download");
        fs::write(&source, b"original").unwrap();
        let sha256 = hex::encode(Sha256::digest(b"original"));
        let result = DownloadResult {
            sha256: sha256.clone(),
            size: 8,
        };
        let cache = AssetCache::new(&directory.path().join("cache")).unwrap();
        let stored = cache
            .store(
                "https://github.com/example/guest.elf",
                8,
                Some(&format!("sha256:{sha256}")),
                &source,
                &result,
            )
            .unwrap();
        fs::write(stored.path, b"tampered").unwrap();

        let cached = cache
            .lookup(
                "https://github.com/example/guest.elf",
                8,
                Some(&format!("sha256:{sha256}")),
            )
            .unwrap();

        assert!(cached.is_none());
    }

    #[test]
    fn invalidates_url_entry_when_release_metadata_changes() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("download");
        fs::write(&source, b"asset").unwrap();
        let result = DownloadResult {
            sha256: hex::encode(Sha256::digest(b"asset")),
            size: 5,
        };
        let cache = AssetCache::new(&directory.path().join("cache")).unwrap();
        cache
            .store(
                "https://github.com/example/guest.elf",
                5,
                None,
                &source,
                &result,
            )
            .unwrap();

        let cached = cache
            .lookup("https://github.com/example/guest.elf", 6, None)
            .unwrap();

        assert!(cached.is_none());
    }
}
