use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub dir: PathBuf,
    pub ttl: Duration,
    pub max_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: default_cache_dir(),
            ttl: Duration::from_secs(7 * 24 * 60 * 60),
            max_bytes: 500 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeCache {
    cfg: CacheConfig,
}

impl BytecodeCache {
    pub fn new(cfg: CacheConfig) -> Self {
        Self { cfg }
    }

    pub fn cfg(&self) -> &CacheConfig {
        &self.cfg
    }

    pub fn get(&self, chain_id: u64, address: Address) -> io::Result<Option<Vec<u8>>> {
        if !self.cfg.enabled {
            return Ok(None);
        }

        let (bin_path, meta_path) = self.entry_paths(chain_id, address);
        let meta_bytes = match fs::read(&meta_path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let mut meta: CacheMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(_) => {
                // Corrupt meta -> best-effort delete.
                let _ = fs::remove_file(&meta_path);
                let _ = fs::remove_file(&bin_path);
                return Ok(None);
            }
        };

        if !bin_path.exists() {
            let _ = fs::remove_file(&meta_path);
            return Ok(None);
        }

        let now = unix_now_secs();
        if now.saturating_sub(meta.fetched_at) > self.cfg.ttl.as_secs() {
            let _ = fs::remove_file(&meta_path);
            let _ = fs::remove_file(&bin_path);
            return Ok(None);
        }

        let bytes = fs::read(&bin_path)?;
        meta.last_accessed = now;
        meta.byte_len = bytes.len() as u64;
        let _ = fs::write(&meta_path, serde_json::to_vec(&meta).unwrap_or_default());

        debug!(
            chain_id,
            address = %format!("{address:#x}"),
            byte_len = bytes.len(),
            "bytecode_cache_hit"
        );
        Ok(Some(bytes))
    }

    pub fn put(&self, chain_id: u64, address: Address, bytecode: &[u8]) -> io::Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }

        fs::create_dir_all(&self.chain_dir(chain_id))?;
        let (bin_path, meta_path) = self.entry_paths(chain_id, address);
        fs::write(&bin_path, bytecode)?;

        let now = unix_now_secs();
        let meta = CacheMeta {
            chain_id,
            address: format!("{address:#x}"),
            fetched_at: now,
            last_accessed: now,
            byte_len: bytecode.len() as u64,
        };
        fs::write(&meta_path, serde_json::to_vec(&meta).unwrap_or_default())?;

        debug!(
            chain_id,
            address = %format!("{address:#x}"),
            byte_len = bytecode.len(),
            "bytecode_cache_put"
        );

        self.cleanup()
    }

    /// Removes expired entries and enforces max cache size via LRU.
    pub fn cleanup(&self) -> io::Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }
        if !self.cfg.dir.exists() {
            return Ok(());
        }

        let now = unix_now_secs();

        // First pass: load meta files, drop expired/corrupt/missing binaries.
        let mut entries: Vec<Entry> = Vec::new();
        for chain_dir in list_dirs(&self.cfg.dir)? {
            // chain_id is the directory name (decimal), but we also trust meta.
            for meta_path in list_files_with_ext(&chain_dir, "json")? {
                let meta_bytes = match fs::read(&meta_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let meta: CacheMeta = match serde_json::from_slice(&meta_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        let _ = fs::remove_file(&meta_path);
                        continue;
                    }
                };

                let bin_path = meta_path.with_extension("bin");
                if !bin_path.exists() {
                    let _ = fs::remove_file(&meta_path);
                    continue;
                }

                if now.saturating_sub(meta.fetched_at) > self.cfg.ttl.as_secs() {
                    let _ = fs::remove_file(&meta_path);
                    let _ = fs::remove_file(&bin_path);
                    continue;
                }

                let size = fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0);
                entries.push(Entry {
                    meta_path,
                    bin_path,
                    last_accessed: meta.last_accessed,
                    size,
                });
            }
        }

        let mut total: u64 = entries.iter().map(|e| e.size).sum();
        if total <= self.cfg.max_bytes {
            return Ok(());
        }

        // LRU prune: oldest last_accessed first.
        entries.sort_by_key(|e| e.last_accessed);
        for e in entries {
            if total <= self.cfg.max_bytes {
                break;
            }
            let _ = fs::remove_file(&e.meta_path);
            let _ = fs::remove_file(&e.bin_path);
            total = total.saturating_sub(e.size);
        }

        Ok(())
    }

    pub fn purge(&self) -> io::Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }
        if self.cfg.dir.exists() {
            fs::remove_dir_all(&self.cfg.dir)?;
        }
        Ok(())
    }

    fn chain_dir(&self, chain_id: u64) -> PathBuf {
        self.cfg.dir.join(chain_id.to_string())
    }

    fn entry_paths(&self, chain_id: u64, address: Address) -> (PathBuf, PathBuf) {
        let addr = format!("{address:#x}");
        let base = self.chain_dir(chain_id).join(addr);
        (base.with_extension("bin"), base.with_extension("json"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheMeta {
    chain_id: u64,
    address: String,
    fetched_at: u64,
    last_accessed: u64,
    byte_len: u64,
}

#[derive(Debug)]
struct Entry {
    meta_path: PathBuf,
    bin_path: PathBuf,
    last_accessed: u64,
    size: u64,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("which-dex");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache").join("which-dex")
}

fn list_dirs(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            out.push(p);
        }
    }
    Ok(out)
}

fn list_files_with_ext(root: &Path, ext: &str) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(p);
        }
    }
    Ok(out)
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration number: {num}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 60 * 60,
        "d" => n * 24 * 60 * 60,
        _ => return Err("invalid duration unit (use s|m|h|d)".to_string()),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("which_dex_cache_test_{nanos}"))
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("7d").unwrap().as_secs(), 7 * 24 * 60 * 60);
        assert_eq!(parse_duration("1h").unwrap().as_secs(), 60 * 60);
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("1w").is_err());
    }

    #[test]
    fn test_ttl_expiry_removes_entry() {
        let dir = temp_cache_dir();
        let cfg = CacheConfig {
            enabled: true,
            dir: dir.clone(),
            ttl: Duration::from_secs(1),
            max_bytes: 10_000_000,
        };
        let cache = BytecodeCache::new(cfg);
        let addr: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        cache.put(1, addr, &[1, 2, 3]).unwrap();

        // Force fetched_at in meta to be old.
        let (_bin, meta) = cache.entry_paths(1, addr);
        let mut m: CacheMeta = serde_json::from_slice(&fs::read(&meta).unwrap()).unwrap();
        m.fetched_at = unix_now_secs().saturating_sub(10);
        fs::write(&meta, serde_json::to_vec(&m).unwrap()).unwrap();

        assert!(cache.get(1, addr).unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_lru_prunes_to_max_bytes() {
        let dir = temp_cache_dir();
        let cfg = CacheConfig {
            enabled: true,
            dir: dir.clone(),
            ttl: Duration::from_secs(7 * 24 * 60 * 60),
            max_bytes: 2,
        };
        let cache = BytecodeCache::new(cfg);

        let a1: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let a2: Address = "0x0000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let a3: Address = "0x0000000000000000000000000000000000000003"
            .parse()
            .unwrap();

        cache.put(1, a1, &[1]).unwrap();
        cache.put(1, a2, &[2]).unwrap();
        cache.put(1, a3, &[3]).unwrap();

        // Total would be 3 bytes; cap is 2 bytes => should prune 1 entry.
        let mut present = 0;
        present += cache.get(1, a1).unwrap().is_some() as i32;
        present += cache.get(1, a2).unwrap().is_some() as i32;
        present += cache.get(1, a3).unwrap().is_some() as i32;
        assert_eq!(present, 2);

        let _ = fs::remove_dir_all(dir);
    }
}
