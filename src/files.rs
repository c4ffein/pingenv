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
//! There are no directory listings. Dotfiles are never served (so a stray
//! `.env` or `.git` cannot leak), with the exception of `.well-known`.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use log::info;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::certs::BoxError;
use crate::config::StaticSite;
use crate::proxy::respond;

const INDEX: &str = "index.html";
const CHUNK: usize = 64 * 1024;

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

    fn last_modified(&self) -> String {
        httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(self.modified))
    }
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
    /// Where it was read from, to check it again.
    path: PathBuf,
    /// When it was last known to match the disk, in milliseconds since the
    /// site was loaded.
    checked: AtomicU64,
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
}

enum Lookup {
    File(Found),
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
        let bytes: usize = memory.values().map(|f: &Arc<MemFile>| f.body.len()).sum();
        info!(
            "route {route}: {} files ({} KiB) held in memory from {}",
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
        if metadata.len() <= self.memory_max_file
            && let Ok(body) = tokio::fs::read(&file.path).await
        {
            let fresh = Arc::new(self.mem_file(&file.path, &metadata, body));
            if self.swap(key, &file, Some(fresh.clone())) {
                return Some(Found::Memory(fresh));
            }
            return None;
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
        self.budget.give_back(old.body.len() as u64);
        match new {
            Some(new) if self.budget.try_take(new.body.len() as u64) => {
                memory.insert(key.to_string(), new);
                true
            }
            _ => {
                memory.remove(key);
                false
            }
        }
    }

    fn mem_file(&self, path: &Path, metadata: &std::fs::Metadata, body: Vec<u8>) -> MemFile {
        mem_file(path, metadata, body, self.now_ms())
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
                Some(found) => Lookup::File(found),
                None => Lookup::NotFound,
            };
        }
        match self.find(&key).await {
            Some(found) => Lookup::File(found),
            None if self.find(&index).await.is_some() => Lookup::AddSlash,
            None => Lookup::NotFound,
        }
    }
}

fn mem_file(path: &Path, metadata: &std::fs::Metadata, body: Vec<u8>, checked: u64) -> MemFile {
    // The length is taken from what was read, not from the earlier stat, so
    // Content-Length always matches the body.
    let meta = Meta {
        len: body.len() as u64,
        ..Meta::new(path, metadata)
    };
    MemFile {
        meta,
        body: Bytes::from(body),
        path: path.to_path_buf(),
        checked: AtomicU64::new(checked),
    }
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
            if metadata.len() > config.memory_max_file {
                continue;
            }
            let path = entry.path();
            let body = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if !budget.try_take(body.len() as u64) {
                return Err(format!(
                    "files to hold in memory exceed PINGENV_MEMORY_MAX_TOTAL ({} bytes); \
                     raise it, narrow PINGENV_ROUTE_<NAME>_MEMORY_PATHS, or lower \
                     PINGENV_ROUTE_<NAME>_MEMORY_MAX_FILE (0 serves from disk)",
                    budget.max
                )
                .into());
            }
            memory.insert(key, Arc::new(mem_file(&path, &metadata, body, 0)));
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
        respond(session, 404, &[], "not found\n").await?;
        return Ok("-");
    };

    let found = match site.lookup(&segments, trailing_slash).await {
        Lookup::File(found) => Some(found),
        Lookup::AddSlash => {
            let location = add_slash_location(&path, query.as_deref());
            respond(session, 308, &[("Location", location)], "").await?;
            return Ok("-");
        }
        // Only for paths that look like application routes: answering a
        // missing `/app.js` with HTML and a 200 hides the real problem.
        Lookup::NotFound => match &site.fallback {
            Some(fallback) if segments.last().is_none_or(|s| !s.contains('.')) => {
                site.find(fallback).await
            }
            _ => None,
        },
    };
    let Some(found) = found else {
        respond(session, 404, &[], "not found\n").await?;
        return Ok("-");
    };

    let meta = found.meta();
    let etag = meta.etag();
    let source = match found {
        Found::Memory(_) => "memory",
        Found::Disk(..) => "disk",
    };

    let common = |resp: &mut ResponseHeader| -> Result<()> {
        resp.insert_header("ETag", &etag)?;
        resp.insert_header("Last-Modified", meta.last_modified())?;
        resp.insert_header("Cache-Control", &site.cache_control)?;
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
        let mut resp = ResponseHeader::build(304, Some(3))?;
        common(&mut resp)?;
        session.write_response_header(Box::new(resp), true).await?;
        return Ok(source);
    }

    let range = match header(session, http::header::RANGE) {
        // A range against a different version of the file gets all of it.
        Some(range) if header(session, http::header::IF_RANGE).is_none_or(|v| v.trim() == etag) => {
            parse_range(&range, meta.len)
        }
        _ => ByteRange::Full,
    };
    let (status, start, end) = match range {
        ByteRange::Full => (200, 0, meta.len),
        ByteRange::Partial(start, last) => (206, start, last + 1),
        ByteRange::Unsatisfiable => {
            let total = format!("bytes */{}", meta.len);
            respond(
                session,
                416,
                &[("Content-Range", total)],
                "range not satisfiable\n",
            )
            .await?;
            return Ok(source);
        }
    };

    let mut resp = ResponseHeader::build(status, Some(8))?;
    common(&mut resp)?;
    resp.insert_header("Content-Type", meta.content_type)?;
    resp.insert_header("Content-Length", (end - start).to_string())?;
    resp.insert_header("Accept-Ranges", "bytes")?;
    resp.insert_header("X-Content-Type-Options", "nosniff")?;
    if status == 206 {
        let content_range = format!("bytes {start}-{}/{}", end - 1, meta.len);
        resp.insert_header("Content-Range", content_range)?;
    }
    let no_body = head || start == end;
    session
        .write_response_header(Box::new(resp), no_body)
        .await?;
    if no_body {
        return Ok(source);
    }

    match found {
        Found::Memory(file) => {
            let body = file.body.slice(start as usize..end as usize);
            session.write_response_body(Some(body), true).await?;
        }
        Found::Disk(mut file, _) => {
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
    fn add_slash_redirect_stays_on_this_host() {
        assert_eq!(add_slash_location("/docs", None), "/docs/");
        assert_eq!(add_slash_location("/docs", Some("a=1")), "/docs/?a=1");
        assert_eq!(add_slash_location("//docs", None), "/docs/");
        assert_eq!(add_slash_location("///evil.test", None), "/evil.test/");
    }
}
