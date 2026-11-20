//! Static file serving for routes that have a `ROOT` instead of an upstream.
//!
//! Files are streamed from disk by default: the operating system keeps hot
//! files in its page cache, so a second copy in this process buys little. A
//! route can opt in to holding small files in memory. Those copies are loaded
//! at startup, trusted for a refresh window (five minutes by default), then
//! checked against the file again, and reloaded or dropped if it changed.
//! Anything not in memory (too large, outside the chosen paths, added later,
//! or no longer matching) is read from disk on each request.
//!
//! Text is sent compressed to clients that can read it, without compressing
//! anything twice: a file held in memory is gzipped once when it is loaded,
//! and a precompressed copy next to a file (`site.css.br`, `site.css.gz`) is
//! used wherever the file is served from.
//!
//! There are no directory listings. Dotfiles are never served (so a stray
//! `.env` or `.git` cannot leak), with the exception of `.well-known`.

use std::collections::HashMap;
use std::io::{SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use flate2::Compression;
use flate2::write::GzEncoder;
use log::info;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::certs::BoxError;
use crate::config::StaticSite;
use crate::proxy::respond;

const INDEX: &str = "index.html";
const CHUNK: usize = 64 * 1024;
/// Smaller files are not compressed here: the headers outweigh the saving.
const COMPRESS_MIN: usize = 256;
/// The usual middle setting. Higher levels shave a percent or two off and
/// take several times as long, which is paid at startup.
const GZIP_LEVEL: u32 = 6;

/// A way of compressing a response that the client can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Brotli,
    Gzip,
}

impl Coding {
    /// Smallest first: a client that reads both gets brotli.
    const ALL: [Coding; 2] = [Coding::Brotli, Coding::Gzip];

    /// The name in `Accept-Encoding` and `Content-Encoding`.
    fn token(self) -> &'static str {
        match self {
            Coding::Brotli => "br",
            Coding::Gzip => "gzip",
        }
    }

    /// What a precompressed copy is called: `site.css.br` for `site.css`.
    fn extension(self) -> &'static str {
        match self {
            Coding::Brotli => ".br",
            Coding::Gzip => ".gz",
        }
    }
}

/// The codings a client says it can read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Accepts {
    brotli: bool,
    gzip: bool,
}

impl Accepts {
    /// Reads an `Accept-Encoding` header. Without one nothing is assumed.
    /// The client's order of preference is not followed, only what it rules
    /// in and out: among what it accepts, the smallest is sent.
    fn parse(header: Option<&str>) -> Accepts {
        let (mut brotli, mut gzip, mut rest) = (None, None, None);
        for item in header.unwrap_or("").split(',') {
            let mut parts = item.split(';').map(str::trim);
            let coding = parts.next().unwrap_or("").to_ascii_lowercase();
            // `q=0` means "not this one". A weight that cannot be read is
            // taken the same way: sending the file as it is always works.
            let wanted = parts
                .filter_map(|p| p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")))
                .all(|q| q.parse::<f32>().is_ok_and(|q| q > 0.0));
            match coding.as_str() {
                "br" => brotli = Some(wanted),
                "gzip" | "x-gzip" => gzip = Some(wanted),
                "*" => rest = Some(wanted),
                _ => {}
            }
        }
        let rest = rest.unwrap_or(false);
        Accepts {
            brotli: brotli.unwrap_or(rest),
            gzip: gzip.unwrap_or(rest),
        }
    }

    fn takes(self, coding: Coding) -> bool {
        match coding {
            Coding::Brotli => self.brotli,
            Coding::Gzip => self.gzip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Meta {
    len: u64,
    /// Modification time, in whole seconds since the Unix epoch.
    modified: u64,
    content_type: &'static str,
}

impl Meta {
    fn new(path: &Path, metadata: &std::fs::Metadata) -> Meta {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        Meta {
            len: metadata.len(),
            modified,
            content_type: content_type(path),
        }
    }

    /// Same recipe as nginx: cheap, and identical whether the file is served
    /// from memory or from disk.
    fn etag(&self) -> String {
        format!("\"{:x}-{:x}\"", self.modified, self.len)
    }

    /// A compressed copy is different bytes, so it needs a tag of its own:
    /// the file's, plus the coding and the length of the copy.
    fn etag_of(&self, coding: Coding, len: u64) -> String {
        format!(
            "\"{:x}-{:x}-{}-{len:x}\"",
            self.modified,
            self.len,
            coding.token()
        )
    }

    fn last_modified(&self) -> String {
        httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(self.modified))
    }
}

/// Whether a file found next to another can be sent in its place: not older
/// than the original, so not left behind by a previous version of it, and
/// smaller, or there is no point.
fn stands_in(original: &Meta, copy: &Meta) -> bool {
    copy.modified >= original.modified && copy.len > 0 && copy.len < original.len
}

/// Bytes held in memory across every route, so the total stays bounded for the
/// life of the process, not just at startup.
pub struct MemoryBudget {
    max: u64,
    used: AtomicU64,
}

impl MemoryBudget {
    pub fn new(max: u64) -> Arc<Self> {
        Arc::new(Self {
            max,
            used: AtomicU64::new(0),
        })
    }

    fn try_take(&self, bytes: u64) -> bool {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let Some(total) = used.checked_add(bytes).filter(|t| *t <= self.max) else {
                return false;
            };
            match self
                .used
                .compare_exchange_weak(used, total, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(actual) => used = actual,
            }
        }
    }

    fn give_back(&self, bytes: u64) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

struct MemFile {
    meta: Meta,
    body: Bytes,
    /// The same content compressed, settled when the file was loaded: read
    /// from a precompressed copy next to it, or (gzip only) made here.
    encoded: Vec<(Coding, Bytes)>,
    /// Where it was read from, to check it again.
    path: PathBuf,
    /// When it was last known to match the disk, in milliseconds since the
    /// site was loaded.
    checked: AtomicU64,
}

impl MemFile {
    fn encoded(&self, coding: Coding) -> Option<&Bytes> {
        let (_, bytes) = self.encoded.iter().find(|(c, _)| *c == coding)?;
        Some(bytes)
    }

    /// Bytes held for this file, compressed copies included.
    fn cost(&self) -> u64 {
        let copies: usize = self.encoded.iter().map(|(_, bytes)| bytes.len()).sum();
        (self.body.len() + copies) as u64
    }
}

enum Found {
    Memory(Arc<MemFile>),
    Disk(tokio::fs::File, Meta),
}

impl Found {
    fn meta(&self) -> Meta {
        match self {
            Found::Memory(file) => file.meta,
            Found::Disk(_, meta) => *meta,
        }
    }

    fn into_body(self) -> Body {
        match self {
            Found::Memory(file) => Body::Memory(file.body.clone()),
            Found::Disk(file, _) => Body::Disk(file),
        }
    }
}

enum Body {
    Memory(Bytes),
    Disk(tokio::fs::File),
}

/// What is sent for a file: the file, or a compressed copy of it.
struct Representation {
    body: Body,
    len: u64,
    etag: String,
    coding: Option<Coding>,
}

enum Lookup {
    /// The file, and the URL path below the root it was found at.
    File(String, Found),
    /// A directory with an index, asked for without its trailing slash.
    AddSlash,
    NotFound,
}

pub struct Site {
    /// Canonical, so that symlinks pointing outside it can be detected.
    root: PathBuf,
    /// Keyed by URL path below the root, like `/css/site.css`.
    memory: RwLock<HashMap<String, Arc<MemFile>>>,
    memory_max_file: u64,
    memory_refresh: Option<Duration>,
    budget: Arc<MemoryBudget>,
    started: Instant,
    fallback: Option<String>,
    cache_control: String,
    compress: bool,
}

impl Site {
    /// Loads the files chosen for memory. Failing to fit them in the shared
    /// budget is an error now: running out of memory later, under load, is a
    /// much worse way to find out that a directory was bigger than expected.
    pub fn load(
        route: &str,
        config: &StaticSite,
        budget: Arc<MemoryBudget>,
    ) -> Result<Site, BoxError> {
        let root = std::fs::canonicalize(&config.root)
            .map_err(|e| format!("route {route}: {}: {e}", config.root.display()))?;
        if !root.is_dir() {
            return Err(format!("route {route}: {} is not a directory", root.display()).into());
        }

        let started = Instant::now();
        let mut memory = HashMap::new();
        if config.memory_max_file > 0 {
            snapshot(&root, "", config, &budget, &mut memory)
                .map_err(|e| format!("route {route}: {e}"))?;
        }
        let bytes: u64 = memory.values().map(|f: &Arc<MemFile>| f.cost()).sum();
        let copies = memory.values().filter(|f| !f.encoded.is_empty()).count();
        info!(
            "route {route}: {} files ({} KiB, {copies} with a compressed copy) held in memory from {}",
            memory.len(),
            bytes.div_ceil(1024),
            root.display()
        );

        Ok(Site {
            root,
            memory: RwLock::new(memory),
            memory_max_file: config.memory_max_file,
            memory_refresh: config.memory_refresh,
            budget,
            started,
            fallback: config.fallback.clone(),
            cache_control: config.cache_control.clone(),
            compress: config.compress,
        })
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn is_fresh(&self, file: &MemFile) -> bool {
        match self.memory_refresh {
            None => true,
            Some(window) => {
                let age = self
                    .now_ms()
                    .saturating_sub(file.checked.load(Ordering::Relaxed));
                age < window.as_millis() as u64
            }
        }
    }

    async fn find(&self, key: &str) -> Option<Found> {
        let cached = self.memory.read().unwrap().get(key).cloned();
        if let Some(file) = cached {
            if self.is_fresh(&file) {
                return Some(Found::Memory(file));
            }
            if let Some(found) = self.revalidate(key, file).await {
                return Some(found);
            }
            // Gone, replaced or no longer fitting: the disk has the answer.
        }
        self.find_on_disk(key).await
    }

    /// Checks a memory copy whose window ran out against the file. `None`
    /// means the copy was dropped.
    async fn revalidate(&self, key: &str, file: Arc<MemFile>) -> Option<Found> {
        // Not `metadata`: a file swapped for a symlink must go back through
        // the checks in `find_on_disk`.
        let metadata = tokio::fs::symlink_metadata(&file.path).await.ok();
        let Some(metadata) = metadata.filter(|m| m.is_file()) else {
            self.swap(key, &file, None);
            return None;
        };
        let now = Meta::new(&file.path, &metadata);
        if now.modified == file.meta.modified && now.len == file.meta.len {
            file.checked.store(self.now_ms(), Ordering::Relaxed);
            return Some(Found::Memory(file));
        }
        if metadata.len() <= self.memory_max_file {
            let (path, compress, checked) = (file.path.clone(), self.compress, self.now_ms());
            // Off this thread: there is a file to read and maybe to compress.
            let load = tokio::task::spawn_blocking(move || {
                let body = std::fs::read(&path).ok()?;
                Some(mem_file(&path, &metadata, body, checked, compress))
            });
            if let Ok(Some(fresh)) = load.await {
                let fresh = Arc::new(fresh);
                if self.swap(key, &file, Some(fresh.clone())) {
                    return Some(Found::Memory(fresh));
                }
                return None;
            }
        }
        self.swap(key, &file, None);
        None
    }

    /// Replaces `old` with `new` (or removes it) unless someone else already
    /// did. Returns whether `new` is now in place.
    fn swap(&self, key: &str, old: &Arc<MemFile>, new: Option<Arc<MemFile>>) -> bool {
        let mut memory = self.memory.write().unwrap();
        if !memory
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, old))
        {
            return false;
        }
        self.budget.give_back(old.cost());
        match new {
            Some(new) if self.budget.try_take(new.cost()) => {
                memory.insert(key.to_string(), new);
                true
            }
            _ => {
                memory.remove(key);
                false
            }
        }
    }

    async fn find_on_disk(&self, key: &str) -> Option<Found> {
        let path = tokio::fs::canonicalize(self.root.join(&key[1..]))
            .await
            .ok()?;
        // A symlink may point anywhere; only follow it inside the root, and
        // never into something the request path itself could not name.
        if !visible_below(&self.root, &path) {
            return None;
        }
        let file = tokio::fs::File::open(&path).await.ok()?;
        let metadata = file.metadata().await.ok()?;
        metadata
            .is_file()
            .then(|| Found::Disk(file, Meta::new(&path, &metadata)))
    }

    async fn lookup(&self, segments: &[String], trailing_slash: bool) -> Lookup {
        let key = format!("/{}", segments.join("/"));
        let index = format!("{}/{INDEX}", key.trim_end_matches('/'));
        // Only possible below a path prefix: `/docs` for a route at `/docs`.
        // Serving the index there would break its relative links.
        if segments.is_empty() && !trailing_slash {
            return Lookup::AddSlash;
        }
        if trailing_slash {
            return match self.find(&index).await {
                Some(found) => Lookup::File(index, found),
                None => Lookup::NotFound,
            };
        }
        match self.find(&key).await {
            Some(found) => Lookup::File(key, found),
            None if self.find(&index).await.is_some() => Lookup::AddSlash,
            None => Lookup::NotFound,
        }
    }

    /// Whether the answer for this file depends on what the client accepts.
    fn negotiable(&self, meta: &Meta) -> bool {
        self.compress && compressible(meta.content_type)
    }

    /// Picks what to send for the file found at `key`: the smallest
    /// compressed copy the client can read, or the file as it is.
    async fn represent(&self, key: &str, found: Found, accepts: Accepts) -> Representation {
        let meta = found.meta();
        if self.negotiable(&meta) {
            for coding in Coding::ALL.into_iter().filter(|c| accepts.takes(*c)) {
                let copy = match &found {
                    // Settled when the copy was loaded: nothing to look up.
                    Found::Memory(file) => file
                        .encoded(coding)
                        .map(|bytes| (Body::Memory(bytes.clone()), bytes.len() as u64)),
                    Found::Disk(..) => self.precompressed(key, coding, &meta).await,
                };
                if let Some((body, len)) = copy {
                    return Representation {
                        body,
                        len,
                        etag: meta.etag_of(coding, len),
                        coding: Some(coding),
                    };
                }
            }
        }
        Representation {
            body: found.into_body(),
            len: meta.len,
            etag: meta.etag(),
            coding: None,
        }
    }

    /// The precompressed copy next to a file served from disk, if there is a
    /// usable one. It goes through `find`, so it is subject to the same
    /// checks as any other file.
    async fn precompressed(&self, key: &str, coding: Coding, meta: &Meta) -> Option<(Body, u64)> {
        let copy = self.find(&format!("{key}{}", coding.extension())).await?;
        let found = copy.meta();
        stands_in(meta, &found).then(|| (copy.into_body(), found.len))
    }
}

/// A file to hold in memory, with its compressed copies if `compress` is set
/// and it is the kind of file that shrinks.
fn mem_file(
    path: &Path,
    metadata: &std::fs::Metadata,
    body: Vec<u8>,
    checked: u64,
    compress: bool,
) -> MemFile {
    // The length is taken from what was read, not from the earlier stat, so
    // Content-Length always matches the body.
    let meta = Meta {
        len: body.len() as u64,
        ..Meta::new(path, metadata)
    };
    let mut encoded = Vec::new();
    if compress && compressible(meta.content_type) {
        for coding in Coding::ALL {
            // A copy somebody made beforehand is as good as it gets. Failing
            // that, gzip is cheap enough to do here; brotli worth having is not.
            let copy = read_precompressed(path, coding, &meta).or_else(|| match coding {
                Coding::Gzip => gzip(&body),
                Coding::Brotli => None,
            });
            encoded.extend(copy.map(|bytes| (coding, Bytes::from(bytes))));
        }
    }
    MemFile {
        meta,
        body: Bytes::from(body),
        encoded,
        path: path.to_path_buf(),
        checked: AtomicU64::new(checked),
    }
}

/// `site.css.br` for `site.css`.
fn precompressed_path(path: &Path, coding: Coding) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(coding.extension());
    PathBuf::from(name)
}

/// Reads the precompressed copy next to `path`, if it is a plain file (not a
/// link, which could lead anywhere) that can stand in for it.
fn read_precompressed(path: &Path, coding: Coding, meta: &Meta) -> Option<Vec<u8>> {
    let copy = precompressed_path(path, coding);
    let metadata = std::fs::symlink_metadata(&copy).ok()?;
    if !metadata.is_file() || !stands_in(meta, &Meta::new(&copy, &metadata)) {
        return None;
    }
    let bytes = std::fs::read(&copy).ok()?;
    // Checked again on what was read: the file may have changed since.
    (!bytes.is_empty() && (bytes.len() as u64) < meta.len).then_some(bytes)
}

/// `None` when it is not worth it: a tiny file, or one that hardly shrinks.
fn gzip(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < COMPRESS_MIN {
        return None;
    }
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(body.len() / 3),
        Compression::new(GZIP_LEVEL),
    );
    encoder.write_all(body).ok()?;
    let compressed = encoder.finish().ok()?;
    // A tenth smaller at least, or the copy is not worth its memory.
    (compressed.len() <= body.len() - body.len() / 10).then_some(compressed)
}

/// Whether `name` is the precompressed copy of a file that is itself held in
/// memory. Such a copy is kept with its original, not loaded a second time
/// under its own name.
fn kept_with_original(dir: &Path, url: &str, name: &str, config: &StaticSite) -> bool {
    config.compress
        && Coding::ALL.into_iter().any(|coding| {
            let Some(original) = name.strip_suffix(coding.extension()) else {
                return false;
            };
            let path = dir.join(original);
            compressible(content_type(&path))
                && wanted(&config.memory_paths, &format!("{url}/{original}"), false)
                && std::fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.is_file() && m.len() <= config.memory_max_file)
        })
}

/// A canonical `path` below `root` that a request could have named: nothing
/// hidden along the way, so a symlink to `.git` or `.env` leads nowhere.
fn visible_below(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|relative| {
        relative
            .components()
            .all(|c| c.as_os_str().to_str().is_some_and(servable_segment))
    })
}

/// Whether `key` (a URL path below the root) may be held in memory.
fn wanted(paths: &[String], key: &str, is_dir: bool) -> bool {
    paths.iter().any(|p| {
        p.is_empty()
            || key == p
            || key.strip_prefix(p.as_str()).is_some_and(|r| r.starts_with('/'))
            // A directory on the way to a wanted path still has to be entered.
            || (is_dir && p.strip_prefix(key).is_some_and(|r| r.starts_with('/')))
    })
}

fn snapshot(
    dir: &Path,
    url: &str,
    config: &StaticSite,
    budget: &MemoryBudget,
    memory: &mut HashMap<String, Arc<MemFile>>,
) -> Result<(), BoxError> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !servable_segment(&name) {
            continue;
        }
        let key = format!("{url}/{name}");
        // `file_type` does not follow symlinks, which are left out of the
        // snapshot on purpose: no loops to guard against here, and they are
        // still served from disk, where the escape check happens.
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if wanted(&config.memory_paths, &key, true) {
                snapshot(&entry.path(), &key, config, budget, memory)?;
            }
        } else if kind.is_file() && wanted(&config.memory_paths, &key, false) {
            let metadata = entry.metadata()?;
            if metadata.len() > config.memory_max_file
                || kept_with_original(dir, url, &name, config)
            {
                continue;
            }
            let path = entry.path();
            let body = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let file = mem_file(&path, &metadata, body, 0, config.compress);
            if !budget.try_take(file.cost()) {
                return Err(format!(
                    "files to hold in memory, with their compressed copies, exceed \
                     PINGENV_MEMORY_MAX_TOTAL ({} bytes); raise it, narrow \
                     PINGENV_ROUTE_<NAME>_MEMORY_PATHS, or lower \
                     PINGENV_ROUTE_<NAME>_MEMORY_MAX_FILE (0 serves from disk)",
                    budget.max
                )
                .into());
            }
            memory.insert(key, Arc::new(file));
        }
    }
    Ok(())
}

fn servable_segment(segment: &str) -> bool {
    segment == ".well-known" || !segment.starts_with('.')
}

/// Turns the request path below the route prefix into validated segments.
/// `None` means the path must not be served at all.
fn clean_path(raw: &str) -> Option<(Vec<String>, bool)> {
    let decoded = percent_decode(raw)?;
    if decoded.contains(['\0', '\\']) {
        return None;
    }
    let mut segments = Vec::new();
    for segment in decoded.split('/').filter(|s| !s.is_empty()) {
        // Checked after decoding, so `%2e%2e` and `%2F..` get no further than
        // a literal `..` does.
        if segment == "." || segment == ".." || !servable_segment(segment) {
            return None;
        }
        segments.push(segment.to_string());
    }
    Some((segments, decoded.ends_with('/')))
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[derive(Debug, PartialEq, Eq)]
enum ByteRange {
    Full,
    /// Inclusive on both ends.
    Partial(u64, u64),
    Unsatisfiable,
}

/// Single ranges only. Anything else (several ranges, other units, garbage) is
/// answered with the whole file, which the specification allows.
fn parse_range(header: &str, len: u64) -> ByteRange {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return ByteRange::Full;
    };
    let Some((start, end)) = spec.split_once('-') else {
        return ByteRange::Full;
    };
    let (start, end) = (start.trim(), end.trim());
    if spec.contains(',') {
        return ByteRange::Full;
    }
    if start.is_empty() {
        // Suffix form: the last N bytes.
        return match end.parse::<u64>() {
            Ok(0) => ByteRange::Unsatisfiable,
            Ok(n) if len > 0 => ByteRange::Partial(len.saturating_sub(n), len - 1),
            Ok(_) => ByteRange::Unsatisfiable,
            Err(_) => ByteRange::Full,
        };
    }
    let Ok(start) = start.parse::<u64>() else {
        return ByteRange::Full;
    };
    let end = if end.is_empty() {
        len.saturating_sub(1)
    } else {
        match end.parse::<u64>() {
            Ok(end) => end.min(len.saturating_sub(1)),
            Err(_) => return ByteRange::Full,
        }
    };
    if start >= len {
        ByteRange::Unsatisfiable
    } else if start > end {
        ByteRange::Full
    } else {
        ByteRange::Partial(start, end)
    }
}

fn etag_matches(header: &str, etag: &str) -> bool {
    header.trim() == "*"
        || header
            .split(',')
            .map(|candidate| candidate.trim().trim_start_matches("W/"))
            .any(|candidate| candidate == etag)
}

fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// Types that shrink. Images, video, archives and the WOFF fonts are
/// compressed already, and trying again only costs time.
fn compressible(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json"
                | "application/manifest+json"
                | "application/xml"
                | "application/wasm"
                | "image/svg+xml"
                | "image/x-icon"
                | "font/ttf"
                | "font/otf"
        )
}

/// Where a directory asked for without its trailing slash is sent. Leading
/// slashes are collapsed: `//docs/` would be read as a link to another host.
fn add_slash_location(path: &str, query: Option<&str>) -> String {
    let path = path.trim_start_matches('/');
    match query {
        Some(q) => format!("/{path}/?{q}"),
        None => format!("/{path}/"),
    }
}

fn header(session: &Session, name: http::header::HeaderName) -> Option<String> {
    session
        .req_header()
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Answers the request from `site`. Returns where the response came from, for
/// the access log.
pub async fn serve(
    site: &Site,
    session: &mut Session,
    prefix: &str,
    hsts: Option<&str>,
) -> Result<&'static str> {
    let req = session.req_header();
    let head = req.method == http::Method::HEAD;
    if !head && req.method != http::Method::GET {
        respond(
            session,
            405,
            &[("Allow", "GET, HEAD".into())],
            "method not allowed\n",
            hsts,
        )
        .await?;
        return Ok("-");
    }

    let path = req.uri.path().to_string();
    let query = req.uri.query().map(str::to_string);
    let below_prefix = if prefix == "/" {
        path.as_str()
    } else {
        &path[prefix.len()..]
    };
    let Some((segments, trailing_slash)) = clean_path(below_prefix) else {
        respond(session, 404, &[], "not found\n", hsts).await?;
        return Ok("-");
    };

    let found = match site.lookup(&segments, trailing_slash).await {
        Lookup::File(key, found) => Some((key, found)),
        Lookup::AddSlash => {
            let location = add_slash_location(&path, query.as_deref());
            respond(session, 308, &[("Location", location)], "", hsts).await?;
            return Ok("-");
        }
        // Only for paths that look like application routes: answering a
        // missing `/app.js` with HTML and a 200 hides the real problem.
        Lookup::NotFound => match &site.fallback {
            Some(fallback) if segments.last().is_none_or(|s| !s.contains('.')) => {
                let found = site.find(fallback).await;
                found.map(|found| (fallback.clone(), found))
            }
            _ => None,
        },
    };
    let Some((key, found)) = found else {
        respond(session, 404, &[], "not found\n", hsts).await?;
        return Ok("-");
    };

    let meta = found.meta();
    let varies = site.negotiable(&meta);
    let accepts = Accepts::parse(header(session, http::header::ACCEPT_ENCODING).as_deref());
    // From here on lengths, ranges and the tag are those of what is sent,
    // which may be a compressed copy; the type and the date are the file's.
    let Representation {
        body,
        len,
        etag,
        coding,
    } = site.represent(&key, found, accepts).await;
    let source = match body {
        Body::Memory(_) => "memory",
        Body::Disk(_) => "disk",
    };

    let common = |resp: &mut ResponseHeader| -> Result<()> {
        resp.insert_header("ETag", &etag)?;
        resp.insert_header("Last-Modified", meta.last_modified())?;
        resp.insert_header("Cache-Control", &site.cache_control)?;
        if varies {
            // Also on the uncompressed answer: a cache has to know that
            // another client may be owed a different one.
            resp.insert_header("Vary", "Accept-Encoding")?;
        }
        if let Some(value) = hsts {
            resp.insert_header("Strict-Transport-Security", value)?;
        }
        Ok(())
    };

    let not_modified = match header(session, http::header::IF_NONE_MATCH) {
        Some(candidates) => etag_matches(&candidates, &etag),
        None => header(session, http::header::IF_MODIFIED_SINCE)
            .and_then(|date| httpdate::parse_http_date(&date).ok())
            .and_then(|date| date.duration_since(SystemTime::UNIX_EPOCH).ok())
            .is_some_and(|since| meta.modified <= since.as_secs()),
    };
    if not_modified {
        let mut resp = ResponseHeader::build(304, Some(5))?;
        common(&mut resp)?;
        session.write_response_header(Box::new(resp), true).await?;
        return Ok(source);
    }

    let range = match header(session, http::header::RANGE) {
        // A range against a different version of the file gets all of it.
        Some(range) if header(session, http::header::IF_RANGE).is_none_or(|v| v.trim() == etag) => {
            parse_range(&range, len)
        }
        _ => ByteRange::Full,
    };
    let (status, start, end) = match range {
        ByteRange::Full => (200, 0, len),
        ByteRange::Partial(start, last) => (206, start, last + 1),
        ByteRange::Unsatisfiable => {
            let total = format!("bytes */{len}");
            respond(
                session,
                416,
                &[("Content-Range", total)],
                "range not satisfiable\n",
                hsts,
            )
            .await?;
            return Ok(source);
        }
    };

    let mut resp = ResponseHeader::build(status, Some(10))?;
    common(&mut resp)?;
    resp.insert_header("Content-Type", meta.content_type)?;
    resp.insert_header("Content-Length", (end - start).to_string())?;
    if let Some(coding) = coding {
        resp.insert_header("Content-Encoding", coding.token())?;
    }
    resp.insert_header("Accept-Ranges", "bytes")?;
    resp.insert_header("X-Content-Type-Options", "nosniff")?;
    if status == 206 {
        let content_range = format!("bytes {start}-{}/{len}", end - 1);
        resp.insert_header("Content-Range", content_range)?;
    }
    let no_body = head || start == end;
    session
        .write_response_header(Box::new(resp), no_body)
        .await?;
    if no_body {
        return Ok(source);
    }

    match body {
        Body::Memory(bytes) => {
            let body = bytes.slice(start as usize..end as usize);
            session.write_response_body(Some(body), true).await?;
        }
        Body::Disk(mut file) => {
            if start > 0 {
                file.seek(SeekFrom::Start(start))
                    .await
                    .or_err(ReadError, "seeking in file")?;
            }
            let mut remaining = end - start;
            while remaining > 0 {
                let want = remaining.min(CHUNK as u64) as usize;
                let mut chunk = BytesMut::zeroed(want);
                // Fails if the file shrank underneath us. The headers already
                // promised a length, so dropping the connection is the only
                // honest thing left to do.
                file.read_exact(&mut chunk)
                    .await
                    .or_err(ReadError, "reading file")?;
                remaining -= chunk.len() as u64;
                session
                    .write_response_body(Some(chunk.freeze()), remaining == 0)
                    .await?;
            }
        }
    }
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(raw: &str) -> Option<(Vec<&'static str>, bool)> {
        clean_path(raw).map(|(segments, slash)| {
            let leaked: Vec<&'static str> = segments
                .into_iter()
                .map(|s| &*Box::leak(s.into_boxed_str()))
                .collect();
            (leaked, slash)
        })
    }

    #[test]
    fn paths_are_normalised() {
        assert_eq!(clean(""), Some((vec![], false)));
        assert_eq!(clean("/"), Some((vec![], true)));
        assert_eq!(clean("/a/b.css"), Some((vec!["a", "b.css"], false)));
        assert_eq!(clean("//a///b/"), Some((vec!["a", "b"], true)));
        assert_eq!(clean("/a%20b/%C3%A9"), Some((vec!["a b", "é"], false)));
        assert_eq!(
            clean("/.well-known/security.txt"),
            Some((vec![".well-known", "security.txt"], false))
        );
    }

    #[test]
    fn traversal_and_dotfiles_are_refused() {
        for bad in [
            "/..",
            "/../etc/passwd",
            "/a/../../etc/passwd",
            "/%2e%2e/etc/passwd",
            "/a/%2E%2E/b",
            "/a%2f..%2f..%2fetc/passwd",
            "/./a",
            "/.env",
            "/.git/config",
            "/a/.htpasswd",
            "/a\\..\\b",
            "/a%00.html",
            "/%zz",
            "/%2",
            "/%ff",
        ] {
            assert_eq!(clean(bad), None, "{bad}");
        }
    }

    #[test]
    fn ranges() {
        use ByteRange::*;
        assert_eq!(parse_range("bytes=0-99", 1000), Partial(0, 99));
        assert_eq!(parse_range("bytes=500-", 1000), Partial(500, 999));
        assert_eq!(parse_range("bytes=-100", 1000), Partial(900, 999));
        assert_eq!(parse_range("bytes=-5000", 1000), Partial(0, 999));
        assert_eq!(parse_range("bytes=990-2000", 1000), Partial(990, 999));
        assert_eq!(parse_range("bytes=0-0", 1000), Partial(0, 0));
        assert_eq!(parse_range("bytes=1000-", 1000), Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 1000), Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), Unsatisfiable);
        assert_eq!(parse_range("bytes=5-2", 1000), Full);
        assert_eq!(parse_range("bytes=0-1,5-6", 1000), Full);
        assert_eq!(parse_range("items=0-1", 1000), Full);
        assert_eq!(parse_range("bytes=a-b", 1000), Full);
    }

    #[test]
    fn etags() {
        let etag = "\"5f-10\"";
        assert!(etag_matches("\"5f-10\"", etag));
        assert!(etag_matches("W/\"5f-10\"", etag));
        assert!(etag_matches("\"other\", \"5f-10\"", etag));
        assert!(etag_matches(" * ", etag));
        assert!(!etag_matches("\"5f-11\"", etag));
    }

    #[test]
    fn content_types() {
        assert_eq!(
            content_type(Path::new("/x/INDEX.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("app.min.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("LICENSE")),
            "application/octet-stream"
        );
    }

    fn static_site(
        root: &Path,
        max_file: u64,
        paths: &[&str],
        refresh: Option<Duration>,
    ) -> StaticSite {
        StaticSite {
            root: root.to_path_buf(),
            memory_max_file: max_file,
            memory_paths: paths.iter().map(|p| p.to_string()).collect(),
            memory_refresh: refresh,
            fallback: None,
            cache_control: "no-cache".into(),
            compress: true,
        }
    }

    fn temp_site(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pingenv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn keys(site: &Site) -> Vec<String> {
        let mut keys: Vec<_> = site.memory.read().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    #[test]
    fn snapshot_respects_limits_and_skips_hidden_and_linked_entries() {
        let dir = temp_site("snapshot");
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join("index.html"), "<h1>hi</h1>").unwrap();
        std::fs::write(dir.join("css/site.css"), "body{}").unwrap();
        std::fs::write(dir.join("big.bin"), vec![0u8; 5000]).unwrap();
        std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.join(".git/config"), "x").unwrap();
        std::os::unix::fs::symlink(dir.join("index.html"), dir.join("link.html")).unwrap();

        let config = static_site(&dir, 1000, &[""], None);
        let budget = MemoryBudget::new(1 << 20);
        let site = Site::load("t", &config, budget.clone()).unwrap();
        assert_eq!(keys(&site), ["/css/site.css", "/index.html"]);
        assert_eq!(budget.used.load(Ordering::Relaxed), 17);

        let too_small = Site::load("t", &config, MemoryBudget::new(10));
        assert!(too_small.is_err_and(|e| e.to_string().contains("PINGENV_MEMORY_MAX_TOTAL")));

        let off = static_site(&dir, 0, &[""], None);
        assert!(keys(&Site::load("t", &off, MemoryBudget::new(1 << 20)).unwrap()).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_chosen_paths_are_held_in_memory() {
        let dir = temp_site("paths");
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::create_dir_all(dir.join("docs/deep")).unwrap();
        std::fs::write(dir.join("index.html"), "a").unwrap();
        std::fs::write(dir.join("css/site.css"), "b").unwrap();
        std::fs::write(dir.join("docs/deep/x.txt"), "c").unwrap();
        std::fs::write(dir.join("docs/y.txt"), "d").unwrap();

        let config = static_site(
            &dir,
            1000,
            &["/css", "/docs/deep/x.txt", "/index.html"],
            None,
        );
        let site = Site::load("t", &config, MemoryBudget::new(1 << 20)).unwrap();
        assert_eq!(
            keys(&site),
            ["/css/site.css", "/docs/deep/x.txt", "/index.html"]
        );
        assert!(wanted(&["/css".into()], "/css", true));
        assert!(!wanted(&["/css".into()], "/cssx/a", false));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn symlinks_cannot_reach_what_a_path_could_not_name() {
        let root = Path::new("/srv/site");
        assert!(visible_below(root, Path::new("/srv/site/css/a.css")));
        assert!(visible_below(root, Path::new("/srv/site/.well-known/x")));
        assert!(!visible_below(root, Path::new("/srv/site/.git/config")));
        assert!(!visible_below(root, Path::new("/srv/site/a/.env")));
        assert!(!visible_below(root, Path::new("/srv/other/a.css")));
    }

    #[test]
    fn symlink_to_a_hidden_directory_is_not_served() {
        let dir = temp_site("hidden-link");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/config"), "x").unwrap();
        std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.join("ok.txt"), "ok").unwrap();
        std::os::unix::fs::symlink(dir.join(".git"), dir.join("repo")).unwrap();
        std::os::unix::fs::symlink(dir.join(".env"), dir.join("env.txt")).unwrap();
        std::os::unix::fs::symlink(dir.join("ok.txt"), dir.join("alias.txt")).unwrap();

        let site = Site::load(
            "t",
            &static_site(&dir, 0, &[""], None),
            MemoryBudget::new(1),
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            assert!(site.find("/repo/config").await.is_none());
            assert!(site.find("/env.txt").await.is_none());
            assert!(site.find("/alias.txt").await.is_some());
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn memory_copies_are_checked_again_after_the_window() {
        let dir = temp_site("refresh");
        std::fs::write(dir.join("a.txt"), "one").unwrap();
        std::fs::write(dir.join("b.txt"), "to be removed").unwrap();
        let config = static_site(&dir, 1000, &[""], Some(Duration::from_millis(50)));
        let budget = MemoryBudget::new(1 << 20);
        let site = Site::load("t", &config, budget.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let body = |found: Option<Found>| match found {
            Some(Found::Memory(f)) => Some(String::from_utf8(f.body.to_vec()).unwrap()),
            _ => None,
        };

        rt.block_on(async {
            // Inside the window, a change on disk is not noticed.
            std::fs::write(dir.join("a.txt"), "changed!").unwrap();
            assert_eq!(body(site.find("/a.txt").await).as_deref(), Some("one"));

            // After it, the new content is loaded, and the budget follows.
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert_eq!(body(site.find("/a.txt").await).as_deref(), Some("changed!"));
            assert_eq!(budget.used.load(Ordering::Relaxed), 8 + 13);

            // A deleted file is dropped, and its bytes are given back.
            std::fs::remove_file(dir.join("b.txt")).unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(site.find("/b.txt").await.is_none());
            assert_eq!(budget.used.load(Ordering::Relaxed), 8);

            // Growing past the per-file limit falls back to the disk.
            std::fs::write(dir.join("a.txt"), vec![b'x'; 2000]).unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(matches!(site.find("/a.txt").await, Some(Found::Disk(..))));
            assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn accept_encoding_says_what_may_be_sent() {
        let parse = |header| Accepts::parse(Some(header));
        let (brotli, gzip) = (true, true);
        let both = Accepts { brotli, gzip };
        let only_gzip = Accepts {
            gzip,
            ..Default::default()
        };
        let only_brotli = Accepts {
            brotli,
            ..Default::default()
        };
        let neither = Accepts::default();

        assert_eq!(Accepts::parse(None), neither);
        assert_eq!(parse(""), neither);
        assert_eq!(parse("identity"), neither);
        assert_eq!(parse("deflate"), neither);
        assert_eq!(parse("gzip, deflate, br, zstd"), both);
        assert_eq!(parse("br;q=1.0, gzip;q=0.8"), both);
        assert_eq!(parse("GZIP"), only_gzip);
        assert_eq!(parse("x-gzip"), only_gzip);
        // q=0 rules a coding out, however it is spelled.
        assert_eq!(parse("gzip;q=0, br"), only_brotli);
        assert_eq!(parse("gzip; q=0.000 , br ; q=0.5"), only_brotli);
        assert_eq!(parse("gzip;q=lots"), neither);
        // `*` stands for whatever was not named.
        assert_eq!(parse("*"), both);
        assert_eq!(parse("*;q=0"), neither);
        assert_eq!(parse("br;q=0, *"), only_gzip);
        assert_eq!(parse("gzip, *;q=0"), only_gzip);
    }

    #[test]
    fn only_types_that_shrink_are_compressed() {
        for name in [
            "a.html", "a.css", "a.js", "a.json", "a.svg", "a.txt", "a.wasm",
        ] {
            assert!(compressible(content_type(Path::new(name))), "{name}");
        }
        for name in [
            "a.png", "a.jpg", "a.woff2", "a.mp4", "a.zip", "a.gz", "a.bin",
        ] {
            assert!(!compressible(content_type(Path::new(name))), "{name}");
        }
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// Text that compresses well, `lines` lines of it.
    fn script(lines: usize) -> String {
        "function answer() { return 42; }\n".repeat(lines)
    }

    #[test]
    fn gzip_is_kept_only_when_it_pays() {
        let text = script(100).into_bytes();
        let packed = gzip(&text).expect("text shrinks");
        assert!(packed.len() < text.len() / 5, "{} bytes", packed.len());
        assert_eq!(gunzip(&packed), text);

        assert!(gzip(&text[..COMPRESS_MIN - 1]).is_none(), "too small");

        // Bytes with no pattern to them do not shrink.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let noise: Vec<u8> = std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .take(4096)
        .collect();
        assert!(gzip(&noise).is_none(), "nothing gained");
    }

    #[test]
    fn a_file_held_in_memory_keeps_a_gzip_copy_counted_in_the_budget() {
        let dir = temp_site("gzip");
        let text = script(100);
        std::fs::write(dir.join("app.js"), &text).unwrap();
        std::fs::write(dir.join("tiny.js"), "f()").unwrap();
        // Same bytes, but not a type that is compressed.
        std::fs::write(dir.join("photo.jpg"), &text).unwrap();

        let budget = MemoryBudget::new(1 << 20);
        let config = static_site(&dir, 1 << 16, &[""], None);
        let site = Site::load("t", &config, budget.clone()).unwrap();
        let memory = site.memory.read().unwrap();
        let packed = memory["/app.js"].encoded(Coding::Gzip).expect("a copy");
        assert_eq!(gunzip(packed), text.as_bytes());
        assert!(memory["/app.js"].encoded(Coding::Brotli).is_none());
        assert!(memory["/tiny.js"].encoded.is_empty());
        assert!(memory["/photo.jpg"].encoded.is_empty());
        assert_eq!(
            budget.used.load(Ordering::Relaxed),
            (2 * text.len() + "f()".len() + packed.len()) as u64
        );
        drop(memory);

        // A budget with room for the files but not for the copy is too small.
        let tight = MemoryBudget::new((2 * text.len() + 3) as u64);
        assert!(Site::load("t", &config, tight.clone()).is_err());
        let plain = StaticSite {
            compress: false,
            ..config
        };
        let site = Site::load("t", &plain, MemoryBudget::new(tight.max)).unwrap();
        assert!(site.memory.read().unwrap()["/app.js"].encoded.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn make_older(path: &Path) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
    }

    /// A site with precompressed copies of every kind: good ones, one that is
    /// older than its file, one that is a link out of the root, and one next
    /// to a file that is not compressed anyway.
    fn site_with_copies(name: &str) -> (PathBuf, String) {
        let dir = temp_site(name);
        let text = script(100);
        for file in ["app.js", "stale.js", "linked.js", "photo.jpg"] {
            std::fs::write(dir.join(file), &text).unwrap();
        }
        std::fs::write(dir.join("app.js.br"), "br").unwrap();
        std::fs::write(dir.join("app.js.gz"), "gz!").unwrap();
        std::fs::write(dir.join("photo.jpg.gz"), "gz!").unwrap();
        std::fs::write(dir.join("stale.js.br"), "left over").unwrap();
        make_older(&dir.join("stale.js.br"));
        let outside = temp_site(&format!("{name}-outside")).join("secret");
        std::fs::write(&outside, "secret").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("linked.js.br")).unwrap();
        (dir, text)
    }

    async fn pick(site: &Site, key: &str, accepts: Accepts) -> (Option<Coding>, Vec<u8>, String) {
        let found = site.find(key).await.expect(key);
        let chosen = site.represent(key, found, accepts).await;
        let bytes = match chosen.body {
            Body::Memory(bytes) => bytes.to_vec(),
            Body::Disk(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        };
        assert_eq!(bytes.len() as u64, chosen.len, "{key}");
        (chosen.coding, bytes, chosen.etag)
    }

    #[test]
    fn a_client_gets_the_smallest_copy_it_can_read() {
        let (dir, text) = site_with_copies("negotiate");
        let (brotli, gzip) = (true, true);
        let both = Accepts { brotli, gzip };
        let only_gzip = Accepts {
            gzip,
            ..Default::default()
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // The same answers whether files come from disk or from memory.
        for max_file in [0, 1 << 16] {
            let config = static_site(&dir, max_file, &[""], None);
            let site = Site::load("t", &config, MemoryBudget::new(1 << 20)).unwrap();
            rt.block_on(async {
                let (coding, body, br_tag) = pick(&site, "/app.js", both).await;
                assert_eq!(
                    (coding, body.as_slice()),
                    (Some(Coding::Brotli), &b"br"[..])
                );
                let (coding, body, gz_tag) = pick(&site, "/app.js", only_gzip).await;
                assert_eq!((coding, body.as_slice()), (Some(Coding::Gzip), &b"gz!"[..]));
                let (coding, body, tag) = pick(&site, "/app.js", Accepts::default()).await;
                assert_eq!((coding, body.as_slice()), (None, text.as_bytes()));
                // Three different bodies, so three different tags.
                assert!(br_tag != gz_tag && br_tag != tag && gz_tag != tag);

                // A copy older than its file was made from an earlier version.
                let (coding, body, _) = pick(&site, "/stale.js", both).await;
                assert_ne!(coding, Some(Coding::Brotli));
                assert_ne!(body, b"left over");
                // A copy that is a link out of the root is not followed.
                let (coding, body, _) = pick(&site, "/linked.js", both).await;
                assert_ne!(coding, Some(Coding::Brotli));
                assert_ne!(body, b"secret");
                // Not a type that is compressed: the copy is not looked at.
                let (coding, body, _) = pick(&site, "/photo.jpg", both).await;
                assert_eq!((coding, body.as_slice()), (None, text.as_bytes()));
            });

            let plain = StaticSite {
                compress: false,
                ..config
            };
            let site = Site::load("t", &plain, MemoryBudget::new(1 << 20)).unwrap();
            let (coding, ..) = rt.block_on(pick(&site, "/app.js", both));
            assert_eq!(coding, None, "switched off");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn precompressed_copies_live_with_their_file_in_memory() {
        let (dir, text) = site_with_copies("copies");
        std::fs::write(dir.join("backup.tar.gz"), "nobody's copy").unwrap();
        let budget = MemoryBudget::new(1 << 20);
        let config = static_site(&dir, 1 << 16, &[""], None);
        let site = Site::load("t", &config, budget.clone()).unwrap();

        // `photo.jpg.gz` is its own file, since `photo.jpg` takes no copies.
        // The copies of scripts are not loaded a second time under their name.
        assert_eq!(
            keys(&site),
            [
                "/app.js",
                "/backup.tar.gz",
                "/linked.js",
                "/photo.jpg",
                "/photo.jpg.gz",
                "/stale.js"
            ]
        );
        let memory = site.memory.read().unwrap();
        let app = &memory["/app.js"];
        assert_eq!(app.encoded(Coding::Brotli).unwrap(), &b"br"[..]);
        // The copy that was there is used; none is made.
        assert_eq!(app.encoded(Coding::Gzip).unwrap(), &b"gz!"[..]);
        assert_eq!(app.cost(), (text.len() + 2 + 3) as u64);
        // Without a usable copy, gzip is made here and brotli is done without.
        let stale = &memory["/stale.js"];
        assert!(stale.encoded(Coding::Brotli).is_none());
        assert_eq!(
            gunzip(stale.encoded(Coding::Gzip).unwrap()),
            text.as_bytes()
        );
        let total: u64 = memory.values().map(|f| f.cost()).sum();
        assert_eq!(budget.used.load(Ordering::Relaxed), total);
        drop(memory);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_compressed_copy_follows_its_file() {
        let dir = temp_site("follow");
        let (first, second) = (script(100), script(150));
        std::fs::write(dir.join("app.js"), &first).unwrap();
        let config = static_site(&dir, 1 << 16, &[""], Some(Duration::from_millis(50)));
        let budget = MemoryBudget::new(1 << 20);
        let site = Site::load("t", &config, budget.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let only_gzip = Accepts {
            gzip: true,
            ..Default::default()
        };

        rt.block_on(async {
            let (_, body, old_tag) = pick(&site, "/app.js", only_gzip).await;
            assert_eq!(gunzip(&body), first.as_bytes());

            std::fs::write(dir.join("app.js"), &second).unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            let (coding, body, tag) = pick(&site, "/app.js", only_gzip).await;
            assert_eq!(coding, Some(Coding::Gzip));
            assert_eq!(gunzip(&body), second.as_bytes());
            assert_ne!(tag, old_tag);
            // The old copy's bytes were given back, the new one's taken.
            assert_eq!(
                budget.used.load(Ordering::Relaxed),
                (second.len() + body.len()) as u64
            );
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_slash_redirect_stays_on_this_host() {
        assert_eq!(add_slash_location("/docs", None), "/docs/");
        assert_eq!(add_slash_location("/docs", Some("a=1")), "/docs/?a=1");
        assert_eq!(add_slash_location("//docs", None), "/docs/");
        assert_eq!(add_slash_location("///evil.test", None), "/evil.test/");
    }
}
