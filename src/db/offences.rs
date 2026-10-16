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

//! `offences`: how many times the detectors have blocked each address,
//! which is what makes a repeat offender's block longer (see
//! `protection::escalated_ttl_days`).
//!
//! An offence is a detector writing a *new* block, never one finding the
//! address already blocked: a scanner that keeps going while blocked has
//! not been caught twice. The count is forgotten once the address has
//! been quiet for `protection::OFFENCE_MEMORY_DAYS` after its last block
//! ended, and when an operator unblocks it by hand.

use std::collections::HashMap;

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use super::Db;
use crate::protection::{Detector, OFFENCE_MEMORY_SECONDS};

impl Db {
    /// How many offences `address` has on record as of `now`, not counting
    /// one being made: 0 for an address never blocked, or one whose last
    /// block ended more than the memory period ago.
    pub fn offences_before(&self, address: &str, now: i64) -> Result<u32> {
        let row: Option<(u32, i64)> = self
            .conn
            .query_row(
                "SELECT count, blocked_until FROM offences WHERE address = ?1",
                params![address],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((count, until)) if now <= until.saturating_add(OFFENCE_MEMORY_SECONDS) => count,
            _ => 0,
        })
    }

    /// Records that `detector` blocked `address` at `now` until
    /// `blocked_until`, as its `offence`th offence (one more than
    /// [`Self::offences_before`] said).
    pub fn record_offence(
        &self,
        address: &str,
        detector: Detector,
        offence: u32,
        now: i64,
        blocked_until: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO offences (address, source, count, last_offence_at, blocked_until)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (address) DO UPDATE SET
                     source = excluded.source,
                     count = excluded.count,
                     last_offence_at = excluded.last_offence_at,
                     blocked_until = excluded.blocked_until",
                params![address, detector.id(), offence, now, blocked_until],
            )
            .context("failed to record an offence")?;
        Ok(())
    }

    /// Every address with more than one offence still remembered as of
    /// `now`, with its count: what the Blocks views show as "3rd offence".
    /// A first offence is left out, since saying so adds nothing.
    pub fn repeat_offences(&self, now: i64) -> Result<HashMap<String, u32>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, count FROM offences WHERE count > 1 AND blocked_until >= ?1",
        )?;
        let rows = stmt.query_map(params![now.saturating_sub(OFFENCE_MEMORY_SECONDS)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        rows.collect::<rusqlite::Result<_>>()
            .context("failed to list repeat offences")
    }

    /// Forgets `address`'s offences: an operator unblocked it, which says
    /// the block was a mistake, and a mistake is not a record to hold
    /// against the next one.
    pub(super) fn forget_offences(&self, address: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM offences WHERE address = ?1", params![address])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::OFFENCE_MEMORY_DAYS;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn an_address_never_blocked_has_no_offences() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.offences_before("198.51.100.9", NOW).unwrap(), 0);
    }

    #[test]
    fn a_recorded_offence_is_counted_for_the_next_block() {
        let db = Db::open_in_memory().unwrap();
        db.record_offence("198.51.100.9", Detector::ProbePaths, 2, NOW, NOW + 10 * DAY)
            .unwrap();
        assert_eq!(
            db.offences_before("198.51.100.9", NOW + 11 * DAY).unwrap(),
            2
        );
    }

    /// Counted from when the last block ended, so a long block does not
    /// use up the memory period while it is still in force.
    #[test]
    fn offences_are_forgotten_a_quiet_period_after_the_last_block_ends() {
        let db = Db::open_in_memory().unwrap();
        let until = NOW + 90 * DAY;
        db.record_offence("198.51.100.9", Detector::Honeypot, 3, NOW, until)
            .unwrap();
        let memory = OFFENCE_MEMORY_DAYS * DAY;

        let cases = [
            ("while blocked", until - DAY, 3),
            ("on the last day remembered", until + memory, 3),
            ("the day after", until + memory + DAY, 0),
        ];
        for (when, at, expected) in cases {
            assert_eq!(
                db.offences_before("198.51.100.9", at).unwrap(),
                expected,
                "{when}"
            );
        }
        assert!(
            db.repeat_offences(until + memory + DAY).unwrap().is_empty(),
            "a forgotten address is still listed as a repeat offender"
        );
    }

    #[test]
    fn only_repeat_offenders_are_listed() {
        let db = Db::open_in_memory().unwrap();
        db.record_offence("198.51.100.1", Detector::ProbePaths, 1, NOW, NOW + DAY)
            .unwrap();
        db.record_offence("198.51.100.2", Detector::ProbePaths, 3, NOW, NOW + DAY)
            .unwrap();

        let listed = db.repeat_offences(NOW).unwrap();

        assert_eq!(
            listed,
            HashMap::from([("198.51.100.2".to_string(), 3)]),
            "listed: {listed:?}"
        );
    }
}
