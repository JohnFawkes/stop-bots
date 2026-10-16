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

//! Confirm-or-revert, for a firewall apply someone is watching.
//!
//! A bad ruleset takes effect at once, and nftables (and the iptables
//! script) accept established connections, so the operator who applied it
//! only finds out when they next connect — from somewhere the rules now
//! drop. Routers and display settings solved this long ago: apply, ask
//! "keep these?", and put things back if nobody answers.
//!
//! ## The sequence
//!
//! 1. [`arm`] writes a record of the pending change beside the applied
//!    script ([`pending_path`]) and starts a timer *outside this process*
//!    that runs `stop-bots revert-firewall --token …` when it fires.
//! 2. Only then does the new script run ([`crate::firewall::execute`]).
//!    The applied script — the one the boot unit loads — is **not**
//!    replaced, so a reboot during the wait loads the previous rules too.
//! 3. The front-end asks. [`keep`] removes the record (that *is* the
//!    disarm: a revert that finds no record with its token does nothing),
//!    stops the timer, copies the old applied script to [`previous_path`]
//!    for a manual rollback, and promotes the new one. [`revert`] runs the
//!    old applied script again — or, if there was none, deletes this
//!    project's table or chains, as `uninstall` does — and leaves a note
//!    ([`reverted_path`]) that says so.
//!
//! Both take [`crate::applylock`], so a keep and the timer's revert racing
//! at the deadline settle the change exactly once.
//!
//! ## The timer
//!
//! `systemd-run --on-active=60s` first: a transient timer in PID 1's
//! manager is outside the operator's session entirely, so it survives the
//! TUI or CLI dying, the SSH connection dropping, *and* logind killing
//! every process of the session on logout (`KillUserProcesses=yes`), which
//! a detached child would not. Where there is no systemd (a container, an
//! OpenRC host) or `systemd-run` fails, a child in a session of its own
//! (`setsid`) sleeps and then reverts: no controlling terminal, so no
//! SIGHUP when the SSH session ends, and not in the shell's process group,
//! so no SIGINT from a Ctrl-C at the prompt either.
//!
//! **Only for applies someone can confirm.** Cron, `tick`, auto-apply and
//! `batch`/`render-firewall` without a terminal on stdin apply as they
//! always did: there is nobody to answer, and a revert there would undo
//! every unattended apply a minute later.

use crate::firewall::{self, FirewallBackend};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the operator has to keep a change, unless told otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long past its deadline a record is still taken for a revert about
/// to run, rather than one whose timer was lost — to a reboot, or to a
/// revert that could not run. A stale record blocks nothing.
const STALE_AFTER_SECS: i64 = 30;

/// The systemd units are named this, then the token.
pub const UNIT_PREFIX: &str = "stop-bots-revert";

/// Where the applied script that a kept change replaced is kept:
/// `firewall.prev.nft` beside `firewall.nft`.
pub fn previous_path(applied: &Path) -> PathBuf {
    firewall::sibling_path(applied, "prev")
}

/// The record of a change waiting to be kept: `firewall.nft.pending`.
pub fn pending_path(applied: &Path) -> PathBuf {
    with_suffix(applied, "pending")
}

/// The note the last revert left: `firewall.nft.reverted`.
pub fn reverted_path(applied: &Path) -> PathBuf {
    with_suffix(applied, "reverted")
}

fn with_suffix(applied: &Path, suffix: &str) -> PathBuf {
    let mut name = applied.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    applied.with_file_name(name)
}

/// What will put the rules back, and how to stop it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Timer {
    /// A transient `<unit>.timer`, stopped with `systemctl stop`.
    Systemd { unit: String },
    /// A sleeping `stop-bots revert-firewall --after` in its own session.
    /// Not killed on a keep — a pid can be reused — but it finds no record
    /// with its token when it wakes, and leaves.
    Detached { pid: u32 },
}

/// A change that has been applied and not yet kept.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pending {
    /// Which arming this is, so a revert started for an earlier one never
    /// undoes a later one.
    pub token: String,
    /// [`FirewallBackend::stored`].
    pub backend: String,
    /// The applied script: what the revert loads again, if it exists.
    pub applied_path: PathBuf,
    pub armed_at: i64,
    pub deadline: i64,
    pub timer: Timer,
}

impl Pending {
    pub fn backend(&self) -> FirewallBackend {
        FirewallBackend::from_stored(&self.backend)
    }

    /// The timeout this was armed with.
    pub fn timeout_secs(&self) -> i64 {
        self.deadline - self.armed_at
    }

    pub fn seconds_left(&self, now: i64) -> i64 {
        (self.deadline - now).max(0)
    }

    fn is_stale(&self, now: i64) -> bool {
        now > self.deadline + STALE_AFTER_SECS
    }

    /// Why another apply may not go ahead while this one waits.
    pub fn blocking_message(&self, now: i64) -> String {
        format!(
            "an earlier firewall change is still waiting to be kept, and is put back in {} s \
             unless it is; nothing was applied. Try again once it is settled",
            self.seconds_left(now)
        )
    }
}

/// The record beside `applied`, if there is one that can be read.
pub fn read_pending(applied: &Path) -> Option<Pending> {
    let text = std::fs::read_to_string(pending_path(applied)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The change waiting at `applied`, unless its deadline is long gone.
pub fn waiting(applied: &Path, now: i64) -> Option<Pending> {
    read_pending(applied).filter(|pending| !pending.is_stale(now))
}

fn write_pending(pending: &Pending) -> Result<()> {
    let path = pending_path(&pending.applied_path);
    firewall::write_script(&path, &serde_json::to_string_pretty(pending)?)
        .with_context(|| format!("could not write {}", path.display()))
}

/// The programs this drives. Fields, so a test can point every one at a
/// fake, as `uninstall::Plan` does.
#[derive(Debug, Clone)]
pub struct Tools {
    pub systemd_run: PathBuf,
    pub systemctl: PathBuf,
    /// The `stop-bots` the timer runs: this one.
    pub exe: PathBuf,
    pub nft: PathBuf,
    pub sh: PathBuf,
    /// `iptables` and `ip6tables`.
    pub iptables: Vec<PathBuf>,
}

impl Tools {
    /// This host's, found as every other program is ([`crate::host::program`]).
    pub fn host() -> Self {
        let program = crate::host::program;
        Tools {
            systemd_run: program("systemd-run"),
            systemctl: program("systemctl"),
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("stop-bots")),
            nft: program("nft"),
            sh: program("sh"),
            iptables: vec![program("iptables"), program("ip6tables")],
        }
    }

    fn loader(&self, backend: FirewallBackend) -> &Path {
        match backend {
            FirewallBackend::Nftables => &self.nft,
            FirewallBackend::Iptables => &self.sh,
        }
    }
}

/// Arms a revert of the change about to be applied at `applied`, firing
/// `timeout` from now. Refuses while another change still waits there.
pub fn arm(
    tools: &Tools,
    backend: FirewallBackend,
    applied: &Path,
    timeout: Duration,
    now: i64,
) -> Result<Pending> {
    if let Some(earlier) = waiting(applied, now) {
        anyhow::bail!("{}", earlier.blocking_message(now));
    }
    let token = new_token()?;
    let secs = timeout.as_secs().max(1);
    let unit = format!("{UNIT_PREFIX}-{token}");
    let mut pending = Pending {
        token: token.clone(),
        backend: backend.stored().to_string(),
        applied_path: applied.to_path_buf(),
        armed_at: now,
        deadline: now + secs as i64,
        timer: Timer::Systemd { unit: unit.clone() },
    };
    // The record first: a revert that fires and finds no record of its
    // own does nothing, so the record must never be the one missing.
    write_pending(&pending)?;
    let args = revert_args(applied, backend, &token);
    let systemd = start_systemd_timer(tools, &unit, secs, &args);
    let Err(systemd_err) = systemd else {
        return Ok(pending);
    };
    match spawn_detached(tools, &args, secs) {
        Ok(pid) => {
            pending.timer = Timer::Detached { pid };
            // Only what a keep stops; the sleeper matches on the token,
            // which the record already has.
            let _ = write_pending(&pending);
            Ok(pending)
        }
        Err(err) => {
            let _ = std::fs::remove_file(pending_path(applied));
            anyhow::bail!(
                "neither `systemd-run` ({systemd_err:#}) nor a detached process ({err:#}) could \
                 be started to revert it"
            )
        }
    }
}

/// `revert-firewall`'s arguments, for the timer.
fn revert_args(applied: &Path, backend: FirewallBackend, token: &str) -> Vec<std::ffi::OsString> {
    vec![
        "revert-firewall".into(),
        "--out".into(),
        applied.as_os_str().to_os_string(),
        "--backend".into(),
        backend.stored().into(),
        "--token".into(),
        token.into(),
    ]
}

fn new_token() -> Result<String> {
    use rand::TryRng;
    let mut bytes = [0u8; 8];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|err| anyhow::anyhow!("no randomness for a token: {err}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn start_systemd_timer(
    tools: &Tools,
    unit: &str,
    secs: u64,
    args: &[std::ffi::OsString],
) -> Result<()> {
    let output = std::process::Command::new(&tools.systemd_run)
        .arg("--quiet")
        .arg("--collect")
        .arg(format!("--unit={unit}"))
        .arg("--description=stop-bots: put back firewall rules nobody kept")
        .arg(format!("--on-active={secs}s"))
        .arg("--timer-property=AccuracySec=1s")
        .arg(&tools.exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .context("could not run systemd-run")?;
    if !output.status.success() {
        anyhow::bail!(
            "systemd-run exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// `exe args --after secs`, in a session of its own, with nothing of this
/// process's terminal. Waited for on a thread, so a TUI that outlives it
/// leaves no zombie; a CLI that exits first hands it to init.
fn spawn_detached(tools: &Tools, args: &[std::ffi::OsString], secs: u64) -> Result<u32> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&tools.exe);
    cmd.args(args)
        .arg("--after")
        .arg(secs.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and touches no memory.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not start {}", tools.exe.display()))?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

fn stop_timer(tools: &Tools, timer: &Timer) {
    if let Timer::Systemd { unit } = timer {
        // Best effort: the record is already gone, so a timer that cannot
        // be stopped fires into nothing.
        let _ = std::process::Command::new(&tools.systemctl)
            .args(["stop", &format!("{unit}.timer")])
            .stdin(std::process::Stdio::null())
            .output();
    }
}

/// Takes back an arming whose apply never happened (the script failed).
pub fn disarm(tools: &Tools, pending: &Pending) {
    if read_pending(&pending.applied_path).is_some_and(|current| current.token == pending.token) {
        let _ = std::fs::remove_file(pending_path(&pending.applied_path));
    }
    stop_timer(tools, &pending.timer);
}

/// How a waiting change ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// The new rules stay, and are what loads at boot.
    Kept(String),
    /// The previous rules are back.
    Reverted(String),
    /// There was nothing to do; why.
    Nothing(String),
}

impl Settled {
    pub fn message(&self) -> &str {
        match self {
            Settled::Kept(message) | Settled::Reverted(message) | Settled::Nothing(message) => {
                message
            }
        }
    }
}

/// Why a revert ran, for the line that reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The operator answered no.
    Declined,
    /// Nobody answered in time, or the front-end died.
    NoAnswer,
    /// `stop-bots revert-firewall` by hand.
    Manual,
}

/// Keeps the change `pending` describes: disarms the revert, keeps the
/// old applied script as [`previous_path`], and makes `script` — what was
/// applied — the one the boot unit loads.
pub fn keep(tools: &Tools, pending: &Pending, script: &str) -> Result<Settled> {
    let _lock = crate::applylock::hold()?;
    let applied = &pending.applied_path;
    if !read_pending(applied).is_some_and(|current| current.token == pending.token) {
        return Ok(too_late(pending));
    }
    let record = pending_path(applied);
    std::fs::remove_file(&record).with_context(|| {
        format!(
            "could not remove {}, so the revert is still armed",
            record.display()
        )
    })?;
    stop_timer(tools, &pending.timer);

    let previous = previous_path(applied);
    Ok(Settled::Kept(match promote(applied, script) {
        Ok(true) => format!(
            "Kept the new firewall rules. {} is what loads at boot; the previous rules are in {} \
             (`stop-bots revert-firewall` goes back to them)",
            applied.display(),
            previous.display()
        ),
        Ok(false) => format!(
            "Kept the new firewall rules. {} is what loads at boot",
            applied.display()
        ),
        Err(err) => {
            format!("Kept the new firewall rules, but {err:#}, so a reboot loads the previous ones")
        }
    }))
}

/// Makes `script` the applied script at `applied`, keeping the one it
/// replaces as [`previous_path`] first. Whether there was one to keep.
/// Every apply goes through this, confirmed or not, so the rules before
/// the last apply are always one `stop-bots revert-firewall` away.
pub fn promote(applied: &Path, script: &str) -> Result<bool> {
    let previous = previous_path(applied);
    let kept_previous = match std::fs::read_to_string(applied) {
        Ok(old) => {
            firewall::write_script(&previous, &old)
                .with_context(|| format!("could not keep {}", previous.display()))?;
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err).context(format!("could not read {}", applied.display())),
    };
    firewall::write_script(applied, script)
        .with_context(|| format!("could not write {}", applied.display()))?;
    Ok(kept_previous)
}

/// A keep that came after the change was settled some other way.
fn too_late(pending: &Pending) -> Settled {
    match last_reverted(&pending.applied_path) {
        Some((at, note)) if at >= pending.armed_at => {
            Settled::Reverted(format!("Too late: {note}"))
        }
        _ => Settled::Nothing("Nothing to keep: no firewall change is waiting".to_string()),
    }
}

/// Reverts the change waiting at `applied` — only the one armed with
/// `token`, when one is given, which is how the timer calls it.
///
/// With no token and nothing waiting, this is a manual rollback instead:
/// the [`previous_path`] script is loaded and swapped with the applied
/// one, so running it twice goes back again. `backend` is for that case;
/// a waiting change knows its own.
pub fn revert(
    tools: &Tools,
    applied: &Path,
    backend: FirewallBackend,
    token: Option<&str>,
    why: Why,
) -> Result<Settled> {
    let _lock = crate::applylock::hold()?;
    match (read_pending(applied), token) {
        (Some(pending), Some(token)) if pending.token != token => Ok(Settled::Nothing(
            "A later firewall change is waiting; this revert was for an earlier one".to_string(),
        )),
        (None, Some(_)) => Ok(Settled::Nothing(
            "Nothing to revert: the firewall change was kept, or already reverted".to_string(),
        )),
        (Some(pending), _) => undo(tools, &pending, why),
        (None, None) => roll_back(tools, applied, backend),
    }
}

fn undo(tools: &Tools, pending: &Pending, why: Why) -> Result<Settled> {
    let applied = &pending.applied_path;
    let _ = std::fs::remove_file(pending_path(applied));
    stop_timer(tools, &pending.timer);
    let backend = pending.backend();
    let had_previous = applied.exists();
    let result = if had_previous {
        firewall::run_script(backend, tools.loader(backend), applied)
    } else {
        crate::uninstall::remove_live_rules(backend, &tools.nft, &tools.iptables)
    };
    let why = match why {
        Why::Declined => "you said no".to_string(),
        Why::NoAnswer => format!("no confirmation within {} s", pending.timeout_secs()),
        Why::Manual => "asked for with `stop-bots revert-firewall`".to_string(),
    };
    let message = match (&result, had_previous) {
        (Ok(()), true) => format!("Reverted to the previous firewall rules ({why})"),
        (Ok(()), false) => {
            format!("Reverted to no stop-bots firewall rules, as there were none before ({why})")
        }
        (Err(err), _) => format!(
            "Could not revert the firewall rules ({why}): {err:#}. The new rules are still \
             loaded; `stop-bots uninstall firewall` takes them out"
        ),
    };
    write_note(applied, &message);
    match result {
        Ok(()) => Ok(Settled::Reverted(message)),
        Err(_) => Err(anyhow::anyhow!("{message}")),
    }
}

fn roll_back(tools: &Tools, applied: &Path, backend: FirewallBackend) -> Result<Settled> {
    let previous = previous_path(applied);
    let Ok(old) = std::fs::read_to_string(&previous) else {
        anyhow::bail!(
            "nothing to go back to: no firewall change is waiting to be kept, and there is no {}",
            previous.display()
        );
    };
    firewall::run_script(backend, tools.loader(backend), &previous)?;
    let current = std::fs::read_to_string(applied).ok();
    firewall::write_script(applied, &old)
        .with_context(|| format!("could not write {}", applied.display()))?;
    match &current {
        Some(current) => firewall::write_script(&previous, current)
            .with_context(|| format!("could not write {}", previous.display()))?,
        None => std::fs::remove_file(&previous)
            .with_context(|| format!("could not remove {}", previous.display()))?,
    }
    let message = format!(
        "Reverted to the previous firewall rules (asked for with `stop-bots revert-firewall`): \
         {} now holds what {} did{}",
        applied.display(),
        previous.display(),
        if current.is_some() {
            ", and the other way round, so running it again goes back"
        } else {
            ""
        }
    );
    write_note(applied, &message);
    Ok(Settled::Reverted(message))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Note {
    at: i64,
    message: String,
}

/// Best effort: the revert has happened whether or not this is written.
fn write_note(applied: &Path, message: &str) {
    let note = Note {
        at: now_secs(),
        message: message.to_string(),
    };
    if let Ok(text) = serde_json::to_string(&note) {
        let _ = firewall::write_script(&reverted_path(applied), &text);
    }
}

/// When the last revert at `applied` ran, and what it said.
pub fn last_reverted(applied: &Path) -> Option<(i64, String)> {
    let text = std::fs::read_to_string(reverted_path(applied)).ok()?;
    let note: Note = serde_json::from_str(&text).ok()?;
    Some((note.at, note.message))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// The operator's answer to "keep these firewall rules?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Keep,
    Revert,
    /// Nothing before the deadline, or stdin closed.
    NoAnswer,
}

/// Settles `pending` as `answer` says.
pub fn settle(tools: &Tools, pending: &Pending, script: &str, answer: Answer) -> Result<Settled> {
    let why = match answer {
        Answer::Keep => return keep(tools, pending, script),
        Answer::Revert => Why::Declined,
        Answer::NoAnswer => Why::NoAnswer,
    };
    revert(
        tools,
        &pending.applied_path,
        pending.backend(),
        Some(&pending.token),
        why,
    )
}

/// The question, with the time left.
pub fn prompt(left: Duration) -> String {
    format!(
        "Keep these firewall rules? [Y/n] Reverting in {} s",
        left.as_secs_f64().ceil() as u64
    )
}

/// Asks on the terminal: a line from `lines` (`None` once stdin closes)
/// answers, and `say` is handed the question again every `every` with the
/// time left. Enter or `y` keeps — anyone who can type an answer can still
/// reach the host, which is all the question is for — and `n` reverts.
pub fn ask(
    lines: &std::sync::mpsc::Receiver<Option<String>>,
    timeout: Duration,
    every: Duration,
    mut say: impl FnMut(String),
) -> Answer {
    use std::sync::mpsc::RecvTimeoutError;
    let deadline = Instant::now() + timeout;
    let mut next_prompt = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Answer::NoAnswer;
        }
        if now >= next_prompt {
            say(prompt(deadline - now));
            next_prompt = now + every;
        }
        match lines.recv_timeout(deadline.min(next_prompt) - now) {
            Ok(Some(line)) => match line.trim().to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => return Answer::Keep,
                "n" | "no" => return Answer::Revert,
                _ => next_prompt = Instant::now(),
            },
            Ok(None) | Err(RecvTimeoutError::Disconnected) => return Answer::NoAnswer,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// [`ask`], on this process's stdin and stdout, re-asking every ten
/// seconds.
pub fn ask_on_terminal(timeout: Duration) -> Answer {
    let (send, lines) = std::sync::mpsc::channel();
    // Left blocked in `read_line` if nobody answers; the process is about
    // to exit then anyway.
    std::thread::spawn(move || loop {
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        let line = match read {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        };
        let last = line.is_none();
        if send.send(line).is_err() || last {
            return;
        }
    });
    let answer = ask(&lines, timeout, Duration::from_secs(10), |question| {
        crate::say_inline!("\n{question}: ");
        crate::present::flush_stdout();
    });
    crate::say!();
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fake_calls, fake_revert_tools, logging_fake};

    /// An applied script's directory, with a fake of every program.
    struct Staged {
        dir: tempfile::TempDir,
        tools: Tools,
    }

    impl Staged {
        fn new() -> Staged {
            let dir = tempfile::tempdir().unwrap();
            let tools = fake_revert_tools(dir.path());
            Staged { dir, tools }
        }

        /// Replaces the fake `name` with one that runs `body` after logging.
        fn fake(&self, name: &str, body: &str) {
            logging_fake(self.dir.path(), name, body);
        }

        fn applied(&self) -> PathBuf {
            self.dir.path().join("firewall.nft")
        }

        fn calls(&self) -> Vec<String> {
            fake_calls(self.dir.path())
        }

        fn arm(&self) -> Pending {
            arm(
                &self.tools,
                FirewallBackend::Nftables,
                &self.applied(),
                DEFAULT_TIMEOUT,
                now_secs(),
            )
            .expect("arming should succeed")
        }
    }

    #[test]
    fn arming_starts_a_systemd_timer_that_runs_revert_firewall_with_the_token() {
        let staged = Staged::new();

        let pending = staged.arm();

        let calls = staged.calls();
        let expected = format!(
            "systemd-run --quiet --collect --unit={UNIT_PREFIX}-{token} \
             --description=stop-bots: put back firewall rules nobody kept --on-active=60s \
             --timer-property=AccuracySec=1s {exe} revert-firewall --out {applied} \
             --backend nftables --token {token}",
            token = pending.token,
            exe = staged.tools.exe.display(),
            applied = staged.applied().display(),
        );
        assert_eq!(calls, vec![expected], "calls were: {calls:#?}");
        assert_eq!(
            read_pending(&staged.applied()),
            Some(pending),
            "the record should be on disk for the revert to find"
        );
    }

    #[test]
    fn without_systemd_a_detached_process_sleeps_and_then_reverts() {
        let staged = Staged::new();
        staged.fake(
            "systemd-run",
            "echo 'System has not been booted with systemd' >&2; exit 1",
        );

        let pending = staged.arm();

        assert!(
            matches!(pending.timer, Timer::Detached { .. }),
            "timer was {:?}",
            pending.timer
        );
        // The child logs as it starts; it is not waited for.
        let started = Instant::now();
        let call = loop {
            if let Some(call) = staged
                .calls()
                .into_iter()
                .find(|c| c.starts_with("stop-bots"))
            {
                break call;
            }
            assert!(
                started.elapsed() < Duration::from_millis(250),
                "the detached process never started; calls: {:?}",
                staged.calls()
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(
            call.ends_with(&format!("--token {} --after 60", pending.token)),
            "the detached process was started as: {call}"
        );
    }

    #[test]
    fn a_second_change_cannot_be_armed_while_one_waits() {
        let staged = Staged::new();
        staged.arm();

        let second = arm(
            &staged.tools,
            FirewallBackend::Nftables,
            &staged.applied(),
            DEFAULT_TIMEOUT,
            now_secs(),
        );

        let err = second.expect_err("a second arming should be refused");
        assert!(
            err.to_string().contains("still waiting to be kept"),
            "error was: {err:#}"
        );
    }

    /// A record whose deadline is long gone lost its timer — a reboot,
    /// most likely, which loaded the previous rules anyway.
    #[test]
    fn a_record_long_past_its_deadline_blocks_nothing() {
        let staged = Staged::new();
        let pending = staged.arm();

        let later = pending.deadline + STALE_AFTER_SECS + 1;

        assert_eq!(waiting(&staged.applied(), later), None);
    }

    #[test]
    fn keeping_disarms_the_revert_and_keeps_the_old_script_as_prev() {
        let staged = Staged::new();
        std::fs::write(staged.applied(), "old rules\n").unwrap();
        let pending = staged.arm();

        let settled = keep(&staged.tools, &pending, "new rules\n").unwrap();

        assert!(
            matches!(settled, Settled::Kept(_)),
            "settled as {settled:?}"
        );
        let files = [
            ("the applied script", staged.applied(), Some("new rules\n")),
            (
                "the previous one",
                previous_path(&staged.applied()),
                Some("old rules\n"),
            ),
            ("the pending record", pending_path(&staged.applied()), None),
        ];
        for (what, path, expected) in files {
            assert_eq!(
                std::fs::read_to_string(&path).ok().as_deref(),
                expected,
                "{what} ({})",
                path.display()
            );
        }
        let stop = format!("systemctl stop {UNIT_PREFIX}-{}.timer", pending.token);
        assert!(
            staged.calls().contains(&stop),
            "the timer should be stopped; calls: {:#?}",
            staged.calls()
        );
    }

    #[test]
    fn the_revert_after_a_keep_does_nothing() {
        let staged = Staged::new();
        std::fs::write(staged.applied(), "old rules\n").unwrap();
        let pending = staged.arm();
        keep(&staged.tools, &pending, "new rules\n").unwrap();

        let settled = revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            Some(&pending.token),
            Why::NoAnswer,
        )
        .unwrap();

        assert!(
            matches!(settled, Settled::Nothing(_)),
            "settled as {settled:?}"
        );
        let loads: Vec<_> = staged
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("nft"))
            .collect();
        assert!(
            loads.is_empty(),
            "nothing should be loaded; nft ran: {loads:?}"
        );
    }

    #[test]
    fn an_unanswered_change_is_reverted_to_the_applied_script() {
        let staged = Staged::new();
        std::fs::write(staged.applied(), "old rules\n").unwrap();
        let pending = staged.arm();

        let settled = revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            Some(&pending.token),
            Why::NoAnswer,
        )
        .unwrap();

        assert_eq!(
            settled,
            Settled::Reverted(
                "Reverted to the previous firewall rules (no confirmation within 60 s)".into()
            )
        );
        let load = format!("nft -f {}", staged.applied().display());
        assert!(
            staged.calls().contains(&load),
            "the previous script should be loaded again; calls: {:#?}",
            staged.calls()
        );
        assert_eq!(read_pending(&staged.applied()), None, "the record is gone");
        let note = last_reverted(&staged.applied()).map(|(_, note)| note);
        assert_eq!(
            note.as_deref(),
            Some(settled.message()),
            "the revert leaves a note"
        );
    }

    #[test]
    fn with_no_previous_script_the_revert_deletes_our_table() {
        let staged = Staged::new();
        let pending = staged.arm();

        revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            Some(&pending.token),
            Why::Declined,
        )
        .unwrap();

        let nft: Vec<_> = staged
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("nft"))
            .collect();
        assert_eq!(
            nft,
            vec![
                "nft list table inet stop_bots",
                "nft delete table inet stop_bots"
            ]
        );
    }

    #[test]
    fn with_no_previous_script_an_iptables_revert_removes_our_chains() {
        let staged = Staged::new();
        for name in ["iptables", "ip6tables"] {
            staged.fake(
                name,
                "[ \"$2\" = -S ] && [ -z \"$3\" ] && echo '-A INPUT -j STOP-BOTS'\nexit 0",
            );
        }
        let pending = arm(
            &staged.tools,
            FirewallBackend::Iptables,
            &staged.applied(),
            DEFAULT_TIMEOUT,
            now_secs(),
        )
        .unwrap();

        settle(&staged.tools, &pending, "", Answer::Revert).unwrap();

        let calls = staged.calls();
        for removal in [
            "iptables -w -D INPUT -j STOP-BOTS",
            "iptables -w -X STOP-BOTS",
            "ip6tables -w -X STOP-BOTS",
        ] {
            assert!(
                calls.iter().any(|c| c == removal),
                "expected `{removal}`; calls: {calls:#?}"
            );
        }
    }

    #[test]
    fn a_revert_for_an_earlier_arming_leaves_a_later_one_alone() {
        let staged = Staged::new();
        let pending = staged.arm();

        let settled = revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            Some("someone-else"),
            Why::NoAnswer,
        )
        .unwrap();

        assert!(
            matches!(settled, Settled::Nothing(_)),
            "settled as {settled:?}"
        );
        assert_eq!(read_pending(&staged.applied()), Some(pending));
    }

    #[test]
    fn by_hand_with_nothing_waiting_it_swaps_the_previous_script_back() {
        let staged = Staged::new();
        std::fs::write(staged.applied(), "new rules\n").unwrap();
        std::fs::write(previous_path(&staged.applied()), "old rules\n").unwrap();

        let settled = revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            None,
            Why::Manual,
        )
        .unwrap();

        assert!(
            matches!(settled, Settled::Reverted(_)),
            "settled as {settled:?}"
        );
        let read = |path: PathBuf| std::fs::read_to_string(path).unwrap();
        assert_eq!(read(staged.applied()), "old rules\n");
        assert_eq!(read(previous_path(&staged.applied())), "new rules\n");
        let load = format!("nft -f {}", previous_path(&staged.applied()).display());
        assert!(
            staged.calls().contains(&load),
            "calls: {:#?}",
            staged.calls()
        );
    }

    #[test]
    fn by_hand_with_no_previous_script_there_is_nothing_to_go_back_to() {
        let staged = Staged::new();

        let err = revert(
            &staged.tools,
            &staged.applied(),
            FirewallBackend::Nftables,
            None,
            Why::Manual,
        )
        .expect_err("nothing to go back to");

        assert!(
            err.to_string().contains("nothing to go back to"),
            "error was: {err:#}"
        );
    }

    fn answered(lines: &[Option<&str>], timeout: Duration) -> (Answer, Vec<String>) {
        let (send, receive) = std::sync::mpsc::channel();
        for line in lines {
            send.send(line.map(String::from)).unwrap();
        }
        let mut said = Vec::new();
        let answer = ask(&receive, timeout, Duration::from_secs(10), |q| said.push(q));
        (answer, said)
    }

    #[test]
    fn an_answer_on_the_terminal_keeps_or_reverts() {
        let cases = [
            ("y", Answer::Keep),
            ("yes", Answer::Keep),
            ("", Answer::Keep),
            ("n", Answer::Revert),
            ("NO", Answer::Revert),
        ];
        for (typed, expected) in cases {
            let line = format!("{typed}\n");
            let (answer, _) = answered(&[Some(&line)], DEFAULT_TIMEOUT);
            assert_eq!(answer, expected, "typing {typed:?}");
        }
    }

    #[test]
    fn something_else_asks_again() {
        let (answer, said) = answered(&[Some("maybe\n"), Some("y\n")], DEFAULT_TIMEOUT);

        assert_eq!(answer, Answer::Keep);
        assert_eq!(said.len(), 2, "asked: {said:?}");
    }

    #[test]
    fn no_answer_in_time_is_no_answer_and_says_the_countdown() {
        let (send, receive) = std::sync::mpsc::channel::<Option<String>>();

        let mut said = Vec::new();
        let answer = ask(
            &receive,
            Duration::from_millis(60),
            Duration::from_millis(25),
            |q| said.push(q),
        );
        drop(send);

        assert_eq!(answer, Answer::NoAnswer);
        assert!(said.len() >= 2, "the question should be repeated: {said:?}");
        assert_eq!(said[0], "Keep these firewall rules? [Y/n] Reverting in 1 s");
    }

    #[test]
    fn a_closed_stdin_is_no_answer() {
        let (answer, _) = answered(&[None], DEFAULT_TIMEOUT);

        assert_eq!(answer, Answer::NoAnswer);
    }

    #[test]
    fn the_previous_script_and_the_records_sit_beside_the_applied_one() {
        let applied = Path::new("/etc/stop-bots/firewall.nft");
        let cases = [
            (previous_path(applied), "/etc/stop-bots/firewall.prev.nft"),
            (pending_path(applied), "/etc/stop-bots/firewall.nft.pending"),
            (
                reverted_path(applied),
                "/etc/stop-bots/firewall.nft.reverted",
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(path, Path::new(expected));
        }
    }
}
