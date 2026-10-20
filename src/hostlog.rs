/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The host logs the detectors read, a bounded piece at a time, from
//! where the last piece stopped: the web server's access logs, sshd's
//! authentication lines, and the lines the firewall's trap ports write to
//! the kernel log.
//!
//! [`read`] is the one function that reads them, in process, for the
//! CLI, the TUI and `tick`. The caller holds a [`LogReader`] and asks it
//! for [`Request`]s until a reply says there is no more.
//!
//! The request-and-reply shape was made for the web console's root
//! helper, which read the logs for a console that could not; the console
//! is gone, and the shape stays because it is what bounds each read.
//!
//! ## What a request can choose, and what it cannot
//!
//! A request names one of the logs, never a path: where each is comes
//! from [`Sources`], which the reader is configured with — the host
//! settings ([`crate::hostconf`]), the web server's config and
//! autodetection; an access log is named by its place in
//! [`Sources::access`]. What a request does choose is where in that log to
//! start: a cursor, or a time for the journal. A cursor is a place,
//! compared with the log the reader finds and otherwise ignored; it cannot
//! point the read anywhere else.
//!
//! ## What comes back
//!
//! An access log's lines, every one, since every access-log detector and
//! the access statistics read them all. Of the SSH log, only the lines
//! sshd wrote about an authentication — `Accepted`, `Failed`, `Invalid
//! user`, as [`crate::sshlog`] reads them — and from the journal only the
//! entries of sshd's own units. Nothing else in `auth.log` (sudo, cron,
//! every user's sessions) and nothing else in the journal is returned.
//! Of the kernel log, only the trap's lines ([`crate::portscan`]).
//!
//! The lines come back unparsed, and are parsed where they are used.
//!
//! ## How much one request costs
//!
//! At most [`MAX_CHUNK`] bytes of log, stopping at a line or an entry:
//! a first read of a large log, or a journal with a month of brute-forcing
//! in it, is many requests, each quick.
//!
//! ## What logrotate kept
//!
//! The first read of an access log also reads its rotated copies,
//! `<log>.1` and `<log>.<n>.gz`, as far back as a detector looks
//! ([`read_rotated`]): on a host where the log was rotated last night, a
//! fresh install would otherwise start knowing nothing of the day before.
//! They are streamed straight to the caller rather than returned in
//! pieces, because a compressed file can only be read from its start, and
//! picking one up again where a piece stopped would unpack it again from
//! there each time. Only the first read does this; after it, the cursor
//! says where the log is, and a later rotation is followed as
//! [`crate::logread`] describes.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logread::{self, FileCursor};
use crate::sshlog::{self, Located, SshSource};

/// The most a request reads: 4 MB. A first read of a 100 MB log is 25
/// requests.
pub const MAX_CHUNK: u64 = 4 * 1024 * 1024;

/// How many cursors a request may offer; the SSH log may be in one of
/// [`sshlog::DEFAULT_LOG_PATHS`] or the journal, or one named file.
const MAX_CURSORS: usize = 4;

/// The stored form of a journal cursor, before journald's own.
pub const JOURNAL_CURSOR_PREFIX: &str = "journal ";

/// The most of its rotated copies a first read of an access log reads,
/// in bytes of lines: the gigabyte a pass reads of a live log at most.
pub const MAX_ROTATED_BYTES: u64 = 1 << 30;

/// How many rotated copies are looked for: more than any `rotate` a
/// distribution ships, and the windows stop the search well before.
const MAX_ROTATED_COPIES: u32 = 64;

/// Which log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Log {
    /// One of the web server's access logs, by [`Request::which`].
    Access,
    /// sshd's authentication lines: from the auth log file, or the
    /// journal.
    Ssh,
    /// The trap's lines in the kernel log: from `kern.log`, or the
    /// journal.
    Kernel,
}

/// One of the logs that may be in the journal: which entries are its,
/// and which of their lines are kept.
struct JournalLog {
    /// The key its cursor is stored under.
    source: &'static str,
    units: &'static [&'static str],
    matches: &'static [&'static str],
    /// What an unreadable journal is reported as.
    tried: &'static str,
    keep: fn(&str) -> bool,
}

const SSH_JOURNAL: JournalLog = JournalLog {
    source: sshlog::JOURNAL_SOURCE,
    units: sshlog::JOURNAL_UNITS,
    matches: &[],
    tried: "journald (units sshd and ssh)",
    keep: sshlog::is_auth_line,
};

const KERNEL_JOURNAL: JournalLog = JournalLog {
    source: crate::portscan::JOURNAL_SOURCE,
    units: &[],
    matches: crate::portscan::JOURNAL_MATCHES,
    tried: "journald (kernel messages)",
    keep: crate::portscan::is_trap_line,
};

/// Where an earlier read of one log stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    /// The log it is a place in, by the key its cursor is stored under:
    /// the path of a file, or [`sshlog::JOURNAL_SOURCE`]. Compared with the
    /// log the reader finds; never opened.
    pub source: String,
    /// The place, in its stored form: [`FileCursor::encode`], or
    /// [`JOURNAL_CURSOR_PREFIX`] and journald's cursor.
    pub at: String,
}

/// One read of one log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub log: Log,
    /// Which access log, by its place in [`Sources::access`]: 0 is the
    /// stored or default one. Not read for the other logs.
    #[serde(default)]
    pub which: usize,
    /// Where earlier reads stopped, one per place the log might be. The
    /// one for where it turns out to be is used; with none, the read starts
    /// at the beginning.
    pub cursors: Vec<Cursor>,
    /// With no cursor for the access log: the byte count 0.0.x's access
    /// statistics stopped at, to start there rather than at the beginning.
    pub legacy_offset: Option<u64>,
    /// With no cursor for the journal: the Unix time to read from. A file
    /// is read from its start; the journal is bounded by nothing else.
    pub since: Option<i64>,
    /// The most to read, in bytes; never more than [`MAX_CHUNK`].
    pub max_bytes: u64,
}

impl Request {
    /// The first read of `log`, or a later one from `cursors`, at the
    /// largest size.
    pub fn new(log: Log, cursors: Vec<Cursor>) -> Self {
        Request {
            log,
            which: 0,
            cursors,
            legacy_offset: None,
            since: None,
            max_bytes: MAX_CHUNK,
        }
    }

    /// The stored cursor offered for `source`.
    fn cursor_for(&self, source: &str) -> Option<&str> {
        self.cursors
            .iter()
            .take(MAX_CURSORS)
            .find(|cursor| cursor.source == source)
            .map(|cursor| cursor.at.as_str())
    }
}

/// What a read came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Read(Chunk),
    /// Nothing could be read; what was tried, for a report.
    Unavailable(String),
}

/// A piece of a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    /// The key the log's cursor is stored under: see [`Cursor::source`].
    pub source: String,
    /// The cursor the read started from, as it was offered, or `None` if
    /// none applied.
    pub from: Option<String>,
    /// Where the next read starts. `None` only for a journal that has
    /// never had anything from sshd in it.
    pub to: Option<String>,
    /// Whether this read carried on from an earlier one (a cursor, or the
    /// legacy offset), rather than starting at the beginning: a line with
    /// no time of its own was then written since that read.
    pub resumed: bool,
    /// The lines, each ending in a newline.
    pub lines: String,
    /// Bytes read from a file, or entries from the journal, the ones not
    /// returned included.
    pub amount: u64,
    /// Whether the read stopped at its size rather than at the end: ask
    /// again, from [`Self::to`].
    pub more: bool,
}

impl Chunk {
    /// The cursor to offer for the next read of this log.
    pub fn next(&self) -> Option<Cursor> {
        self.to.as_ref().map(|at| Cursor {
            source: self.source.clone(),
            at: at.clone(),
        })
    }
}

/// Where this host's logs are, as the reader resolves them. Never from
/// a request.
#[derive(Debug, Clone)]
pub struct Sources {
    /// The access logs: the stored or default one first, then those the
    /// web server's config names that are there to read (see
    /// [`crate::logpaths::LogPaths::access_logs_to_read`]).
    pub access: Vec<PathBuf>,
    pub ssh: SshSource,
    /// Where [`SshSource::Search`] looks before the journal.
    pub search: Vec<PathBuf>,
    /// The kernel log, or the search for it.
    pub kernel: crate::portscan::KernelSource,
    /// Where the kernel log's search looks before the journal.
    pub kernel_search: Vec<PathBuf>,
    /// `journalctl`, except in tests.
    pub journalctl: PathBuf,
}

impl Sources {
    /// The logs `paths` names, a flag winning over each: the access logs
    /// there are to read, and the SSH log or the search for it.
    pub fn new(
        paths: &crate::logpaths::LogPaths,
        access_flag: Option<&Path>,
        ssh_flag: Option<&Path>,
    ) -> Self {
        Sources {
            access: paths
                .access_logs_to_read(access_flag)
                .into_iter()
                .map(|log| log.path)
                .collect(),
            ssh: paths.ssh(ssh_flag),
            search: sshlog::DEFAULT_LOG_PATHS
                .iter()
                .map(PathBuf::from)
                .collect(),
            kernel: paths.kernel(None),
            kernel_search: crate::portscan::DEFAULT_KERNEL_LOG_PATHS
                .iter()
                .map(PathBuf::from)
                .collect(),
            journalctl: PathBuf::from("journalctl"),
        }
    }

    /// Only an SSH log, for its readers that read nothing else.
    pub fn ssh_only(ssh: SshSource) -> Self {
        Sources {
            access: Vec::new(),
            ..Sources::new(&Default::default(), None, None)
        }
        .with_ssh(ssh)
    }

    fn with_ssh(mut self, ssh: SshSource) -> Self {
        self.ssh = ssh;
        self
    }
}

/// The key a file's cursor is stored under: its path, as given.
pub fn source_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Something that answers [`Request`]s: [`Sources`], in process.
/// Blocking.
pub trait LogReader {
    fn read_log(&self, request: &Request) -> anyhow::Result<Reply>;

    /// The rotated copies of access log `which` that hold anything from
    /// `since` on, oldest first, a line at a time to `visit`; the bytes
    /// read. See [`read_rotated`].
    fn read_rotated(&self, which: usize, since: i64, visit: &mut dyn FnMut(&str)) -> u64;
}

impl LogReader for Sources {
    fn read_log(&self, request: &Request) -> anyhow::Result<Reply> {
        Ok(read(self, request))
    }

    fn read_rotated(&self, which: usize, since: i64, visit: &mut dyn FnMut(&str)) -> u64 {
        match self.access.get(which) {
            Some(path) => read_rotated(path, since, visit),
            None => 0,
        }
    }
}

/// Reads what `request` asks for from the log `sources` names. The one
/// implementation: see the module docs.
pub fn read(sources: &Sources, request: &Request) -> Reply {
    let budget = request.max_bytes.clamp(1, MAX_CHUNK);
    match request.log {
        Log::Access => match sources.access.get(request.which) {
            Some(path) => read_access(path, request, budget),
            None => Reply::Unavailable(format!("access log {}", request.which)),
        },
        Log::Ssh => read_located(
            sources.ssh.locate_among(&sources.search),
            &SSH_JOURNAL,
            sources,
            request,
            budget,
        ),
        Log::Kernel => read_located(
            sources.kernel.locate_among(&sources.kernel_search),
            &KERNEL_JOURNAL,
            sources,
            request,
            budget,
        ),
    }
}

fn read_access(path: &Path, request: &Request, budget: u64) -> Reply {
    let source = source_key(path);
    let stored = request.cursor_for(&source);
    let start = match (stored, request.legacy_offset) {
        (Some(stored), _) => FileCursor::decode(stored),
        (None, Some(offset)) => logread::cursor_at(path, offset).ok(),
        (None, None) => None,
    };
    let mut lines = String::new();
    match logread::read_chunk(path, start, budget, &mut |line| push(&mut lines, line)) {
        Ok(done) => Reply::Read(Chunk {
            source,
            from: stored.map(String::from),
            to: Some(done.cursor.encode()),
            resumed: start.is_some(),
            lines,
            amount: done.bytes,
            more: done.more,
        }),
        Err(_) => Reply::Unavailable(path.display().to_string()),
    }
}

/// What logrotate kept of the log at `path` from `since` on, oldest first:
/// `<path>.1`, then `<path>.2.gz` and on (each plain or compressed, as
/// `compress` and `delaycompress` leave them), up to the first that is not
/// there or was last written before `since`, since every older one was
/// too. Each line goes to `visit`; the bytes read, at most
/// [`MAX_ROTATED_BYTES`].
///
/// Only a copy's last write is checked, not each line's time: a copy that
/// reaches into the window is read whole, and the reader keeps what falls
/// inside each detector's window. A copy that cannot be read is passed
/// over, as a log rotated away before the first read always was.
pub fn read_rotated(path: &Path, since: i64, visit: &mut dyn FnMut(&str)) -> u64 {
    let mut copies = Vec::new();
    for n in 1..=MAX_ROTATED_COPIES {
        let named = |suffix: &str| {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            PathBuf::from(name)
        };
        let Some((copy, written)) = [named(&format!(".{n}")), named(&format!(".{n}.gz"))]
            .into_iter()
            .find_map(|copy| {
                let written = std::fs::metadata(&copy).ok()?.modified().ok()?;
                Some((copy, written))
            })
        else {
            break;
        };
        let written = written
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |at| at.as_secs() as i64);
        if written < since {
            break;
        }
        copies.push(copy);
    }
    let mut read = 0;
    for copy in copies.iter().rev() {
        let budget = MAX_ROTATED_BYTES - read;
        if budget == 0 {
            break;
        }
        read += logread::read_rotated_copy(copy, budget, visit).unwrap_or(0);
    }
    read
}

fn push(lines: &mut String, line: &str) {
    lines.push_str(line);
    lines.push('\n');
}

/// Reads the SSH or the kernel log from where it was found: the lines
/// `journal.keep` keeps, from a file or from the journal.
fn read_located(
    located: Located,
    journal: &JournalLog,
    sources: &Sources,
    request: &Request,
    budget: u64,
) -> Reply {
    match located {
        Located::File(path) => {
            let source = source_key(&path);
            let stored = request.cursor_for(&source);
            let start = stored.and_then(FileCursor::decode);
            let mut lines = String::new();
            match logread::read_chunk(&path, start, budget, &mut |line| {
                if (journal.keep)(line) {
                    push(&mut lines, line);
                }
            }) {
                Ok(done) => Reply::Read(Chunk {
                    source,
                    from: stored.map(String::from),
                    to: Some(done.cursor.encode()),
                    resumed: start.is_some(),
                    lines,
                    amount: done.bytes,
                    more: done.more,
                }),
                Err(_) => Reply::Unavailable(path.display().to_string()),
            }
        }
        Located::Journal => read_journal(journal, sources, request, budget),
    }
}

/// Whether `cursor` looks like one journald writes: `s=…;i=…;b=…`, of
/// letters, digits, `=` and `;`. It goes to `journalctl` as one argument
/// either way; this keeps anything else from going at all.
fn is_journal_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= 512
        && cursor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'=' || b == b';')
}

fn read_journal(journal: &JournalLog, sources: &Sources, request: &Request, budget: u64) -> Reply {
    let source = journal.source.to_string();
    let stored = request.cursor_for(&source);
    let after = stored
        .and_then(|stored| stored.strip_prefix(JOURNAL_CURSOR_PREFIX))
        .filter(|cursor| is_journal_cursor(cursor));
    let query = logread::JournalQuery {
        program: &sources.journalctl,
        units: journal.units,
        matches: journal.matches,
        after_cursor: after,
        since: request.since,
        last: None,
        max_bytes: Some(budget),
    };
    let mut lines = String::new();
    let done = match logread::read_journal(&query, &mut |line| {
        if (journal.keep)(line) {
            push(&mut lines, line);
        }
    }) {
        Ok(done) => done,
        Err(_) => return Reply::Unavailable(journal.tried.to_string()),
    };
    // A first read that found nothing since `since`: a quiet host, or a
    // journal this user cannot see. The newest entry, however old, tells
    // the two apart, and its cursor is where the next read starts.
    let cursor = match (&done.cursor, after) {
        (None, None) => newest_journal_cursor(journal, &sources.journalctl),
        (cursor, _) => cursor.clone(),
    };
    // Readable is "it answered, and has at some point had something to
    // say": an unprivileged journalctl succeeds with nothing, and that must
    // not read as a log with no logins in it.
    if cursor.is_none() && after.is_none() {
        return Reply::Unavailable(journal.tried.to_string());
    }
    Reply::Read(Chunk {
        source,
        from: stored.map(String::from),
        to: cursor.map(|cursor| format!("{JOURNAL_CURSOR_PREFIX}{cursor}")),
        // Every entry `short-iso` prints is dated, so an undated line is
        // not one journald wrote.
        resumed: false,
        lines,
        amount: done.lines as u64,
        more: done.more,
    })
}

/// The cursor of the newest entry of `journal`'s in the journal, if there
/// is one.
fn newest_journal_cursor(journal: &JournalLog, journalctl: &Path) -> Option<String> {
    let query = logread::JournalQuery {
        program: journalctl,
        units: journal.units,
        matches: journal.matches,
        after_cursor: None,
        since: None,
        last: Some(1),
        max_bytes: None,
    };
    logread::read_journal(&query, &mut |_| {}).ok()?.cursor
}

/// sshd's authentication lines since `since`, from the start of the log:
/// for the readers that want them all at once rather than what is new —
/// the lockout guard, the Firewall screens, the one-off CLI commands.
/// `None` when the log could not be read.
///
/// A file is read whole, since logrotate bounds it; the journal from
/// `since`, since nothing bounds it. A request at a time, until the log
/// says there is no more.
pub fn ssh_since(reader: &dyn LogReader, since: i64) -> Option<String> {
    log_since(reader, Log::Ssh, since)
}

/// The trap's kernel log lines since `since`, the way [`ssh_since`] reads
/// sshd's: for the one-off `run-detector port-scanners`.
pub fn kernel_since(reader: &dyn LogReader, since: i64) -> Option<String> {
    log_since(reader, Log::Kernel, since)
}

fn log_since(reader: &dyn LogReader, log: Log, since: i64) -> Option<String> {
    let mut text = String::new();
    let mut request = Request {
        since: Some(since),
        ..Request::new(log, Vec::new())
    };
    let mut source: Option<String> = None;
    loop {
        let chunk = match reader.read_log(&request).ok()? {
            Reply::Read(chunk) => chunk,
            Reply::Unavailable(_) => return source.is_some().then_some(text),
        };
        // The log moved under the read (rotated away, or the search found
        // another): what was read so far is what there is.
        if source
            .as_ref()
            .is_some_and(|source| *source != chunk.source)
        {
            return Some(text);
        }
        text.push_str(&chunk.lines);
        if !chunk.more {
            return Some(text);
        }
        request.cursors = chunk.next().into_iter().collect();
        source = Some(chunk.source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fake_journalctl, journal_entry, journalctl_calls};

    const SEP_28: i64 = 1_790_577_181;

    fn sources(dir: &Path) -> Sources {
        Sources {
            access: vec![dir.join("access.log")],
            ssh: SshSource::File(dir.join("auth.log")),
            search: vec![dir.join("no-auth.log")],
            kernel: SshSource::File(dir.join("kern.log")),
            kernel_search: vec![dir.join("no-kern.log")],
            journalctl: dir.join("journalctl"),
        }
    }

    fn chunk(reply: Reply) -> Chunk {
        match reply {
            Reply::Read(chunk) => chunk,
            Reply::Unavailable(tried) => panic!("unavailable: {tried}"),
        }
    }

    /// Of `auth.log`, sshd's authentication lines and nothing else: not
    /// sudo, not cron, not another program that mentions SSH.
    #[test]
    fn of_the_auth_log_only_sshd_s_authentication_lines_come_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("auth.log"),
            "Sep 28 06:00:00 host sudo[9]: marko : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow\n\
             Sep 28 06:00:01 host CRON[9]: pam_unix(cron:session): session opened for root\n\
             Sep 28 06:00:02 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n\
             Sep 28 06:00:03 host sshd[1]: pam_unix(sshd:session): session opened for user m\n\
             Sep 28 06:00:04 host other[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n\
             Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 port 1 ssh2\n",
        )
        .unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request::new(Log::Ssh, Vec::new()),
        ));

        assert_eq!(
            read.lines,
            "Sep 28 06:00:02 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n\
             Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
        );
    }

    /// Of the kernel log, the trap's lines and nothing else.
    #[test]
    fn of_the_kernel_log_only_the_trap_s_lines_come_back() {
        let dir = tempfile::tempdir().unwrap();
        let trap = "Oct 16 10:00:03 host kernel: [9.8] stop-bots-trap: IN=eth0 OUT= \
                    SRC=203.0.113.5 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=23 SYN URGP=0\n";
        std::fs::write(
            dir.path().join("kern.log"),
            format!(
                "Oct 16 10:00:01 host kernel: [9.7] usb 1-1: new high-speed USB device\n\
                 {trap}\
                 Oct 16 10:00:04 host kernel: [9.9] [UFW BLOCK] IN=eth0 SRC=203.0.113.6 \
                 PROTO=TCP DPT=25\n"
            ),
        )
        .unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request::new(Log::Kernel, Vec::new()),
        ));

        assert_eq!(read.lines, trap);
    }

    /// A request names a log, not a path: whatever it offers as a cursor's
    /// source, the file read is the one the reader was configured with,
    /// and a cursor offered for another file is not used.
    #[test]
    fn a_cursor_for_another_file_reads_the_configured_one_from_its_start() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("access.log"), "one\ntwo\n").unwrap();
        std::fs::write(dir.path().join("secret"), "secret\n").unwrap();
        let elsewhere = logread::cursor_at(&dir.path().join("secret"), 0).unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request::new(
                Log::Access,
                vec![Cursor {
                    source: source_key(&dir.path().join("secret")),
                    at: elsewhere.encode(),
                }],
            ),
        ));

        assert_eq!(read.lines, "one\ntwo\n");
        assert_eq!(read.from, None);
        assert_eq!(read.source, source_key(&dir.path().join("access.log")));
    }

    /// No request reads more than a chunk, whatever it asks for.
    #[test]
    fn a_request_reads_no_more_than_a_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let line = "x".repeat(1023) + "\n";
        std::fs::write(
            dir.path().join("access.log"),
            line.repeat((MAX_CHUNK / 1024) as usize + 10),
        )
        .unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request {
                max_bytes: u64::MAX,
                ..Request::new(Log::Access, Vec::new())
            },
        ));

        assert!(read.more);
        assert_eq!(read.amount, MAX_CHUNK);
        assert_eq!(read.lines.len() as u64, MAX_CHUNK);
    }

    /// From the journal: the units are sshd's, and of their entries only
    /// the authentication lines come back.
    #[test]
    fn of_the_journal_only_sshd_s_units_and_authentication_lines_are_read() {
        let dir = tempfile::tempdir().unwrap();
        fake_journalctl(
            dir.path(),
            &format!(
                "echo '{}'\necho '{}'\n",
                journal_entry("s=1", SEP_28, "Server listening on 0.0.0.0 port 22."),
                journal_entry(
                    "s=2",
                    SEP_28,
                    "Failed password for root from 203.0.113.5 port 1 ssh2"
                ),
            ),
        );
        let mut sources = sources(dir.path());
        sources.ssh = SshSource::Search;

        let read = chunk(read(
            &sources,
            &Request {
                since: Some(SEP_28 - 60),
                ..Request::new(Log::Ssh, Vec::new())
            },
        ));

        assert_eq!(read.lines.lines().count(), 1, "{}", read.lines);
        assert!(read.lines.contains("203.0.113.5"), "{}", read.lines);
        assert_eq!(read.to.as_deref(), Some("journal s=2"));
        let calls = journalctl_calls(dir.path());
        assert!(calls[0].starts_with("-u sshd -u ssh "), "{calls:?}");
        assert!(calls[0].contains("--since=@"), "{calls:?}");
    }

    /// A journal cursor that is not one journald would write is not passed
    /// on: the read starts from `since` instead.
    #[test]
    fn a_cursor_journald_did_not_write_is_not_passed_to_journalctl() {
        let dir = tempfile::tempdir().unwrap();
        fake_journalctl(dir.path(), "");
        let mut sources = sources(dir.path());
        sources.ssh = SshSource::Search;

        read(
            &sources,
            &Request {
                since: Some(SEP_28),
                ..Request::new(
                    Log::Ssh,
                    vec![Cursor {
                        source: sshlog::JOURNAL_SOURCE.to_string(),
                        at: "journal s=1 --file=/etc/shadow".to_string(),
                    }],
                )
            },
        );

        let calls = journalctl_calls(dir.path()).join("\n");
        assert!(!calls.contains("shadow"), "{calls}");
        assert!(calls.contains("--since=@"), "{calls}");
    }

    /// A reader that reads `max` bytes at a time, however much it is asked
    /// for: chunks small enough to have many in a test.
    struct Small(Sources, u64);

    impl LogReader for Small {
        fn read_log(&self, request: &Request) -> anyhow::Result<Reply> {
            let mut request = request.clone();
            request.max_bytes = self.1;
            Ok(read(&self.0, &request))
        }

        fn read_rotated(&self, which: usize, since: i64, visit: &mut dyn FnMut(&str)) -> u64 {
            self.0.read_rotated(which, since, visit)
        }
    }

    /// The whole-log readers ask until there is no more, and get the same
    /// lines as one read would have given.
    #[test]
    fn reading_since_asks_until_the_log_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let line = "Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 \
                    port 1 ssh2\n";
        std::fs::write(dir.path().join("auth.log"), line.repeat(50)).unwrap();

        let whole = ssh_since(&sources(dir.path()), 0).unwrap();
        let chunked = ssh_since(&Small(sources(dir.path()), 300), 0).unwrap();

        assert_eq!(whole.lines().count(), 50);
        assert_eq!(chunked, whole);
    }

    #[test]
    fn an_ssh_log_that_is_not_there_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ssh_since(&sources(dir.path()), 0), None);
    }

    /// Each access log is asked for by its place, and one past the last
    /// is not there rather than another file.
    #[test]
    fn an_access_log_is_read_by_its_place_in_the_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("access.log"), "main\n").unwrap();
        std::fs::write(dir.path().join("site.log"), "site\n").unwrap();
        let mut sources = sources(dir.path());
        sources.access.push(dir.path().join("site.log"));
        let asking = |which| Request {
            which,
            ..Request::new(Log::Access, Vec::new())
        };

        let main = chunk(read(&sources, &asking(0)));
        let site = chunk(read(&sources, &asking(1)));

        assert_eq!(
            (main.lines.as_str(), site.lines.as_str()),
            ("main\n", "site\n")
        );
        assert_eq!(site.source, source_key(&dir.path().join("site.log")));
        assert!(
            matches!(read(&sources, &asking(2)), Reply::Unavailable(_)),
            "there is no third log"
        );
    }

    /// Oldest first, plain and compressed, and no further back than the
    /// first copy last written before the window opened.
    #[test]
    fn the_rotated_copies_are_read_oldest_first_back_to_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        let now = crate::testing::now_secs();
        let day = 24 * 3600;
        crate::testing::write_gzip(&dir.path().join("access.log.3.gz"), "old\n", now - 30 * day);
        crate::testing::write_gzip(&dir.path().join("access.log.2.gz"), "older\n", now - day);
        std::fs::write(dir.path().join("access.log.1"), "newest\n").unwrap();

        let mut lines = Vec::new();
        let read = read_rotated(&log, now - 7 * day, &mut |line| {
            lines.push(line.to_string())
        });

        assert_eq!(lines, ["older", "newest"], "the 30-day-old copy is outside");
        assert_eq!(read, 13);
    }
}
