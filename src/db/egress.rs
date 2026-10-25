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

//! The stored half of [`crate::egress`] and [`crate::contain`]: the
//! command-and-control feeds and what they hold, the outbound attempts
//! the kernel logged, and the containments made because of them.

use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension};

use super::Db;
use crate::egress::{EntryKind, Path};

/// One feed of command-and-control addresses or domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressFeed {
    pub id: String,
    pub name: String,
    /// Where it is downloaded from. A feed added by URL may carry a key
    /// in it: show [`crate::egress::masked_url`], never this.
    pub url: String,
    pub kind: EntryKind,
    pub builtin: bool,
    pub enabled: bool,
    /// Whether a hit on one of its entries may contain what made it.
    pub contain: bool,
    pub last_fetched_at: Option<i64>,
    pub entry_count: usize,
    /// How many entries the last fetch left out: see
    /// [`crate::egress::guard`].
    pub kept_off: usize,
}

/// What [`Db::register_egress_feed`] needs to know of a feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEgressFeed {
    pub id: String,
    pub name: String,
    pub url: String,
    pub kind: EntryKind,
    pub builtin: bool,
    pub contain: bool,
}

/// One outbound flow the kernel logged, as stored: every attempt from the
/// same source to the same destination, port and user is one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressHit {
    pub id: i64,
    pub path: Path,
    pub source: String,
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub uid: Option<u32>,
    pub count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// The last line the kernel logged for it.
    pub evidence: String,
    pub container_id: Option<String>,
    pub container_name: Option<String>,
    /// When a response to it was last decided. A hit seen since is
    /// unanswered.
    pub responded_at: Option<i64>,
}

impl EgressHit {
    /// Whether nothing has decided what to do about this hit since it was
    /// last seen.
    pub fn unanswered(&self) -> bool {
        self.responded_at.is_none_or(|at| at < self.last_seen)
    }
}

/// A hit as one read of the kernel log found it, not yet stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEgressHit {
    pub path: Path,
    pub source: String,
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub uid: Option<u32>,
    pub count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub evidence: String,
}

/// What was cut off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainmentKind {
    /// A container, by its full id.
    Container,
    /// A user on the host, by uid.
    User,
    /// An address, for traffic this host forwards that no container owns.
    Address,
}

impl ContainmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ContainmentKind::Container => "container",
            ContainmentKind::User => "user",
            ContainmentKind::Address => "address",
        }
    }

    pub fn parse(text: &str) -> Option<ContainmentKind> {
        match text {
            "container" => Some(ContainmentKind::Container),
            "user" => Some(ContainmentKind::User),
            "address" => Some(ContainmentKind::Address),
            _ => None,
        }
    }
}

/// One containment, open or released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Containment {
    pub id: i64,
    pub kind: ContainmentKind,
    /// A container's full id, a uid, or an address.
    pub target: String,
    /// A container's or a user's name, when known.
    pub name: Option<String>,
    /// The addresses cut off: a container's, as last seen, or the one
    /// address. Empty for a user.
    pub addresses: Vec<String>,
    /// [`crate::contain::Action::as_str`].
    pub action: String,
    /// Why: the hit that made it, or the operator's own words.
    pub reason: String,
    pub automatic: bool,
    pub created_at: i64,
    pub released_at: Option<i64>,
}

impl Containment {
    /// How it reads in a list: the name, else the target.
    pub fn label(&self) -> String {
        match (&self.name, self.kind) {
            (Some(name), ContainmentKind::User) => format!("user {name} (uid {})", self.target),
            (None, ContainmentKind::User) => format!("uid {}", self.target),
            (Some(name), ContainmentKind::Container) => format!("container {name}"),
            (None, ContainmentKind::Container) => {
                format!("container {}", short_id(&self.target))
            }
            (_, ContainmentKind::Address) => format!("address {}", self.target),
        }
    }
}

/// The first twelve characters of a container id, as `docker ps` shows it.
pub fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// What [`Db::open_containment`] records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContainment {
    pub kind: ContainmentKind,
    pub target: String,
    pub name: Option<String>,
    pub addresses: Vec<String>,
    pub action: String,
    pub reason: String,
    pub automatic: bool,
}

fn feed_from_row(row: &rusqlite::Row) -> rusqlite::Result<EgressFeed> {
    let kind: String = row.get(3)?;
    Ok(EgressFeed {
        id: row.get(0)?,
        name: row.get(1)?,
        url: row.get(2)?,
        kind: EntryKind::parse(&kind).unwrap_or(EntryKind::Ip),
        builtin: row.get(4)?,
        enabled: row.get(5)?,
        contain: row.get(6)?,
        last_fetched_at: row.get(7)?,
        entry_count: row.get::<_, i64>(8)? as usize,
        kept_off: row.get::<_, i64>(9)? as usize,
    })
}

const FEED_COLUMNS: &str =
    "id, name, url, kind, builtin, enabled, contain, last_fetched_at, entry_count, kept_off";

const HIT_COLUMNS: &str = "id, path, source, destination, port, protocol, uid, count, \
     first_seen, last_seen, evidence, container_id, container_name, responded_at";

fn hit_from_row(row: &rusqlite::Row) -> rusqlite::Result<EgressHit> {
    let path: String = row.get(1)?;
    Ok(EgressHit {
        id: row.get(0)?,
        path: Path::parse(&path).unwrap_or(Path::Host),
        source: row.get(2)?,
        destination: row.get(3)?,
        port: row.get(4)?,
        protocol: row.get(5)?,
        uid: row.get(6)?,
        count: row.get::<_, i64>(7)? as u64,
        first_seen: row.get(8)?,
        last_seen: row.get(9)?,
        evidence: row.get(10)?,
        container_id: row.get(11)?,
        container_name: row.get(12)?,
        responded_at: row.get(13)?,
    })
}

const CONTAINMENT_COLUMNS: &str =
    "id, kind, target, name, addresses, action, reason, automatic, created_at, released_at";

fn containment_from_row(row: &rusqlite::Row) -> rusqlite::Result<Containment> {
    let kind: String = row.get(1)?;
    let addresses: String = row.get(4)?;
    Ok(Containment {
        id: row.get(0)?,
        kind: ContainmentKind::parse(&kind).unwrap_or(ContainmentKind::Address),
        target: row.get(2)?,
        name: row.get(3)?,
        addresses: split_addresses(&addresses),
        action: row.get(5)?,
        reason: row.get(6)?,
        automatic: row.get(7)?,
        created_at: row.get(8)?,
        released_at: row.get(9)?,
    })
}

fn split_addresses(joined: &str) -> Vec<String> {
    joined
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect()
}

/// Only valid addresses reach a containment's row: they are rendered
/// into the firewall script and passed to `nft` and `iptables`.
fn join_addresses(addresses: &[String]) -> Result<String> {
    for address in addresses {
        if !super::is_valid_address(address) || address.contains('/') {
            bail!("not a single IP address: {address:?}");
        }
    }
    Ok(addresses.join(","))
}

impl Db {
    // ---- feeds ----

    /// Adds `feed` unless one with its id is known, keeping an existing
    /// row's switches: this runs on every start-up.
    pub fn register_egress_feed(&self, feed: &NewEgressFeed) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO egress_feeds (id, name, url, kind, builtin, enabled, contain)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                params![
                    feed.id,
                    feed.name,
                    feed.url,
                    feed.kind.as_str(),
                    feed.builtin,
                    feed.contain
                ],
            )
            .context("failed to register an egress feed")?;
        Ok(())
    }

    /// Every feed, built-in ones first, then by id.
    pub fn list_egress_feeds(&self) -> Result<Vec<EgressFeed>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {FEED_COLUMNS} FROM egress_feeds ORDER BY builtin DESC, id"
        ))?;
        let rows = stmt.query_map([], feed_from_row)?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list egress feeds")
    }

    pub fn get_egress_feed(&self, id: &str) -> Result<Option<EgressFeed>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {FEED_COLUMNS} FROM egress_feeds WHERE id = ?1"),
                params![id],
                feed_from_row,
            )
            .optional()?)
    }

    pub fn set_egress_feed_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE egress_feeds SET enabled = ?1 WHERE id = ?2",
            params![enabled, id],
        )?;
        if changed == 0 {
            bail!("no egress feed with id: {id}");
        }
        Ok(())
    }

    pub fn set_egress_feed_contain(&self, id: &str, contain: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE egress_feeds SET contain = ?1 WHERE id = ?2",
            params![contain, id],
        )?;
        if changed == 0 {
            bail!("no egress feed with id: {id}");
        }
        Ok(())
    }

    /// Removes a feed added by URL, and what it held. A built-in one can
    /// only be switched off.
    pub fn remove_egress_feed(&self, id: &str) -> Result<()> {
        let Some(feed) = self.get_egress_feed(id)? else {
            bail!("no egress feed with id: {id}");
        };
        if feed.builtin {
            bail!("{id} is built in: switch it off instead (`set-egress-feed --enabled false`)");
        }
        self.batch(|| {
            self.conn
                .execute("DELETE FROM egress_entries WHERE feed_id = ?1", params![id])?;
            self.conn
                .execute("DELETE FROM egress_feeds WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    /// Replaces what `id` holds with `entries`, and records the fetch: how
    /// many were kept, and how many the guard left out. One transaction,
    /// so a render never sees the feed half-replaced.
    pub fn replace_egress_entries(
        &self,
        id: &str,
        entries: &[String],
        kept_off: usize,
    ) -> Result<usize> {
        self.batch(|| {
            self.conn
                .execute("DELETE FROM egress_entries WHERE feed_id = ?1", params![id])?;
            let mut insert = self.conn.prepare_cached(
                "INSERT OR IGNORE INTO egress_entries (feed_id, entry) VALUES (?1, ?2)",
            )?;
            for entry in entries {
                insert.execute(params![id, entry])?;
            }
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM egress_entries WHERE feed_id = ?1",
                params![id],
                |row| row.get(0),
            )?;
            let changed = self.conn.execute(
                "UPDATE egress_feeds SET last_fetched_at = ?1, entry_count = ?2, kept_off = ?3
                 WHERE id = ?4",
                params![super::now(), count, kept_off as i64, id],
            )?;
            if changed == 0 {
                bail!("no egress feed with id: {id}");
            }
            Ok(count as usize)
        })
    }

    /// Every entry of every enabled feed of `kind`, each with its feed's
    /// id, ordered by feed and entry.
    pub fn enabled_egress_entries(&self, kind: EntryKind) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT e.feed_id, e.entry FROM egress_entries e
             JOIN egress_feeds f ON f.id = e.feed_id
             WHERE f.enabled = 1 AND f.kind = ?1
             ORDER BY e.feed_id, e.entry",
        )?;
        let rows = stmt.query_map(params![kind.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list egress entries")
    }

    // ---- hits ----

    /// Adds `hits` onto what is stored: a flow seen before has its count
    /// and times extended, and is unanswered again if it was seen since its
    /// last response.
    pub fn upsert_egress_hits(&self, hits: &[NewEgressHit]) -> Result<()> {
        let mut upsert = self.conn.prepare_cached(
            "INSERT INTO egress_hits
                 (path, source, destination, port, protocol, uid, count, first_seen,
                  last_seen, evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (path, source, destination, ifnull(port, -1), ifnull(uid, -1))
             DO UPDATE SET
                 count = count + excluded.count,
                 protocol = excluded.protocol,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen),
                 evidence = CASE WHEN excluded.last_seen >= last_seen
                                 THEN excluded.evidence ELSE evidence END",
        )?;
        for hit in hits {
            upsert.execute(params![
                hit.path.as_str(),
                hit.source,
                hit.destination,
                hit.port,
                hit.protocol,
                hit.uid,
                hit.count as i64,
                hit.first_seen,
                hit.last_seen,
                hit.evidence,
            ])?;
        }
        Ok(())
    }

    /// Every stored hit, the latest first.
    pub fn list_egress_hits(&self) -> Result<Vec<EgressHit>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {HIT_COLUMNS} FROM egress_hits ORDER BY last_seen DESC, id"
        ))?;
        let rows = stmt.query_map([], hit_from_row)?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list egress hits")
    }

    /// The hits nothing has answered since they were last seen, oldest
    /// first.
    pub fn unanswered_egress_hits(&self) -> Result<Vec<EgressHit>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {HIT_COLUMNS} FROM egress_hits
             WHERE responded_at IS NULL OR responded_at < last_seen
             ORDER BY first_seen, id"
        ))?;
        let rows = stmt.query_map([], hit_from_row)?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list unanswered egress hits")
    }

    /// Records who a hit came from and that it was answered at `now`.
    pub fn answer_egress_hit(
        &self,
        id: i64,
        container: Option<(&str, &str)>,
        now: i64,
    ) -> Result<()> {
        let (container_id, container_name) = container.unzip();
        self.conn.execute(
            "UPDATE egress_hits SET responded_at = max(?1, last_seen),
                 container_id = coalesce(?2, container_id),
                 container_name = coalesce(?3, container_name)
             WHERE id = ?4",
            params![now, container_id, container_name, id],
        )?;
        Ok(())
    }

    /// Forgets hits last seen before `before`, and every hit when `None`:
    /// what `clear-egress-hits` does once an alert has been dealt with.
    pub fn clear_egress_hits(&self, before: Option<i64>) -> Result<usize> {
        Ok(match before {
            Some(before) => self.conn.execute(
                "DELETE FROM egress_hits WHERE last_seen < ?1",
                params![before],
            )?,
            None => self.conn.execute("DELETE FROM egress_hits", [])?,
        })
    }

    // ---- containments ----

    /// Opens a containment, or returns the one already open for the same
    /// target: containing something twice changes nothing.
    pub fn open_containment(&self, new: &NewContainment) -> Result<(Containment, bool)> {
        if let Some(open) = self.open_containment_of(new.kind, &new.target)? {
            return Ok((open, false));
        }
        let addresses = join_addresses(&new.addresses)?;
        self.conn
            .execute(
                "INSERT INTO containments
                     (kind, target, name, addresses, action, reason, automatic, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    new.kind.as_str(),
                    new.target,
                    new.name,
                    addresses,
                    new.action,
                    new.reason,
                    new.automatic,
                    super::now()
                ],
            )
            .context("failed to record a containment")?;
        let id = self.conn.last_insert_rowid();
        let opened = self
            .containment(id)?
            .context("the containment just recorded is not there")?;
        Ok((opened, true))
    }

    pub fn containment(&self, id: i64) -> Result<Option<Containment>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {CONTAINMENT_COLUMNS} FROM containments WHERE id = ?1"),
                params![id],
                containment_from_row,
            )
            .optional()?)
    }

    /// The open containment of `target`, if there is one.
    pub fn open_containment_of(
        &self,
        kind: ContainmentKind,
        target: &str,
    ) -> Result<Option<Containment>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {CONTAINMENT_COLUMNS} FROM containments
                     WHERE kind = ?1 AND target = ?2 AND released_at IS NULL"
                ),
                params![kind.as_str(), target],
                containment_from_row,
            )
            .optional()?)
    }

    /// Every open containment, oldest first.
    pub fn open_containments(&self) -> Result<Vec<Containment>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {CONTAINMENT_COLUMNS} FROM containments WHERE released_at IS NULL
             ORDER BY created_at, id"
        ))?;
        let rows = stmt.query_map([], containment_from_row)?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list containments")
    }

    /// Every containment ever made, the latest first.
    pub fn list_containments(&self) -> Result<Vec<Containment>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {CONTAINMENT_COLUMNS} FROM containments ORDER BY created_at DESC, id DESC"
        ))?;
        let rows = stmt.query_map([], containment_from_row)?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list containments")
    }

    /// How many containments were opened automatically since `since`:
    /// what the circuit breaker counts.
    pub fn automatic_containments_since(&self, since: i64) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM containments WHERE automatic = 1 AND created_at >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Records the addresses a contained container has now.
    pub fn set_containment_addresses(&self, id: i64, addresses: &[String]) -> Result<()> {
        self.conn.execute(
            "UPDATE containments SET addresses = ?1 WHERE id = ?2",
            params![join_addresses(addresses)?, id],
        )?;
        Ok(())
    }

    /// Closes containment `id`.
    pub fn release_containment(&self, id: i64) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE containments SET released_at = ?1 WHERE id = ?2 AND released_at IS NULL",
            params![super::now(), id],
        )?;
        if changed == 0 {
            bail!("no open containment with id {id}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(id: &str) -> NewEgressFeed {
        NewEgressFeed {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.invalid/{id}"),
            kind: EntryKind::Ip,
            builtin: false,
            contain: false,
        }
    }

    fn hit(source: &str, destination: &str, uid: Option<u32>, at: i64) -> NewEgressHit {
        NewEgressHit {
            path: Path::Host,
            source: source.to_string(),
            destination: destination.to_string(),
            port: Some(443),
            protocol: "TCP".to_string(),
            uid,
            count: 1,
            first_seen: at,
            last_seen: at,
            evidence: format!("line at {at}"),
        }
    }

    fn container(target: &str) -> NewContainment {
        NewContainment {
            kind: ContainmentKind::Container,
            target: target.to_string(),
            name: Some("web".to_string()),
            addresses: vec!["172.18.0.5".to_string()],
            action: "pause".to_string(),
            reason: "a hit".to_string(),
            automatic: true,
        }
    }

    #[test]
    fn registering_a_feed_again_keeps_its_switches() {
        let db = Db::open_in_memory().unwrap();
        db.register_egress_feed(&feed("one")).unwrap();
        db.set_egress_feed_enabled("one", true).unwrap();
        db.register_egress_feed(&feed("one")).unwrap();
        let feeds = db.list_egress_feeds().unwrap();
        assert!(
            feeds.iter().any(|f| f.id == "one" && f.enabled),
            "{feeds:?}"
        );
    }

    #[test]
    fn only_an_enabled_feed_contributes_entries() {
        let db = Db::open_in_memory().unwrap();
        db.register_egress_feed(&feed("on")).unwrap();
        db.register_egress_feed(&feed("off")).unwrap();
        db.set_egress_feed_enabled("on", true).unwrap();
        db.replace_egress_entries("on", &["192.0.2.1".to_string()], 0)
            .unwrap();
        db.replace_egress_entries("off", &["192.0.2.2".to_string()], 0)
            .unwrap();
        assert_eq!(
            db.enabled_egress_entries(EntryKind::Ip).unwrap(),
            vec![("on".to_string(), "192.0.2.1".to_string())]
        );
    }

    #[test]
    fn refetching_a_feed_replaces_what_it_held() {
        let db = Db::open_in_memory().unwrap();
        db.register_egress_feed(&feed("one")).unwrap();
        db.set_egress_feed_enabled("one", true).unwrap();
        db.replace_egress_entries("one", &["192.0.2.1".to_string()], 0)
            .unwrap();
        let count = db
            .replace_egress_entries("one", &["192.0.2.9".to_string()], 2)
            .unwrap();
        assert_eq!(count, 1);
        let stored = db.get_egress_feed("one").unwrap().unwrap();
        assert_eq!((stored.entry_count, stored.kept_off), (1, 2), "{stored:?}");
        assert_eq!(
            db.enabled_egress_entries(EntryKind::Ip).unwrap(),
            vec![("one".to_string(), "192.0.2.9".to_string())]
        );
    }

    #[test]
    fn a_built_in_feed_cannot_be_removed() {
        let db = Db::open_in_memory().unwrap();
        db.register_egress_feed(&NewEgressFeed {
            builtin: true,
            ..feed("built-in")
        })
        .unwrap();
        let err = db.remove_egress_feed("built-in").unwrap_err();
        assert!(err.to_string().contains("built in"), "{err}");
    }

    #[test]
    fn the_same_flow_seen_twice_is_one_hit_with_both_counted() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_egress_hits(&[hit("10.0.0.2", "198.51.100.7", Some(33), 100)])
            .unwrap();
        db.upsert_egress_hits(&[hit("10.0.0.2", "198.51.100.7", Some(33), 200)])
            .unwrap();
        let hits = db.list_egress_hits().unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            (hits[0].count, hits[0].first_seen, hits[0].last_seen),
            (2, 100, 200)
        );
        assert_eq!(hits[0].evidence, "line at 200");
    }

    /// A hit without a port or a user is still one flow: a plain `UNIQUE`
    /// over the nullable columns would store each sighting apart.
    #[test]
    fn a_flow_without_a_user_is_still_one_hit() {
        let db = Db::open_in_memory().unwrap();
        for at in [100, 200] {
            db.upsert_egress_hits(&[hit("172.18.0.5", "198.51.100.7", None, at)])
                .unwrap();
        }
        assert_eq!(db.list_egress_hits().unwrap().len(), 1);
    }

    #[test]
    fn a_hit_seen_again_after_its_answer_is_unanswered_again() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_egress_hits(&[hit("10.0.0.2", "198.51.100.7", Some(33), 100)])
            .unwrap();
        let id = db.unanswered_egress_hits().unwrap()[0].id;
        db.answer_egress_hit(id, None, 150).unwrap();
        assert!(db.unanswered_egress_hits().unwrap().is_empty());

        db.upsert_egress_hits(&[hit("10.0.0.2", "198.51.100.7", Some(33), 300)])
            .unwrap();
        assert_eq!(db.unanswered_egress_hits().unwrap().len(), 1);
    }

    #[test]
    fn containing_the_same_target_twice_opens_one_containment() {
        let db = Db::open_in_memory().unwrap();
        let (first, opened) = db.open_containment(&container("abc")).unwrap();
        assert!(opened);
        let (second, opened) = db.open_containment(&container("abc")).unwrap();
        assert!(!opened, "a second containment was opened");
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn a_released_target_can_be_contained_again() {
        let db = Db::open_in_memory().unwrap();
        let (first, _) = db.open_containment(&container("abc")).unwrap();
        db.release_containment(first.id).unwrap();
        assert!(db.open_containments().unwrap().is_empty());
        let (_, opened) = db.open_containment(&container("abc")).unwrap();
        assert!(opened, "the target could not be contained again");
        assert_eq!(db.list_containments().unwrap().len(), 2);
    }

    /// The addresses go into the firewall script and onto `nft`'s command
    /// line, so only single addresses are stored.
    #[test]
    fn a_containment_refuses_what_is_not_one_address() {
        let db = Db::open_in_memory().unwrap();
        for bad in ["10.0.0.0/8", "10.0.0.1; reboot", "web"] {
            let err = db
                .open_containment(&NewContainment {
                    addresses: vec![bad.to_string()],
                    ..container("abc")
                })
                .unwrap_err();
            assert!(err.to_string().contains("single IP"), "{bad}: {err}");
        }
    }
}
