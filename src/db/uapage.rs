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

//! `user_agent_stats` a page at a time, for the Firewall screens.
//!
//! [`Db::list_user_agent_stats`] reads every row, which is right for the
//! CLI's `list-access-stats` and wrong for a screen: the table's rows are
//! strings any client can choose, and twenty thousand distinct 4–8 KB user
//! agents made the web console's Firewall page (since removed) load them
//! all, classify each against every bot pattern inside the database lock,
//! and render 418 MB of HTML. A screen shows the most-seen [`crate::dynamic::UA_PAGE_ROWS`] and
//! pages through the rest.

use anyhow::{Context, Result};
use rusqlite::params;

use super::{Db, UserAgentStat};

impl Db {
    /// Up to `limit` user agents, most-seen first, skipping the first
    /// `offset`, each with its row id — the handle a console URL names it
    /// by, so that the string itself never goes into one.
    ///
    /// Ties are broken by row id, which keeps the order total, so page two
    /// starts exactly where page one stopped.
    ///
    /// **Sorted on the two integers, then joined back.** Ordering the rows
    /// themselves made SQLite's sorter carry every string it passed over:
    /// with 20,000 agents of 4–8 KB, page fifty took 0.9 s to sort 60 MB,
    /// against 0.08 s for any page this way.
    pub fn user_agent_stats_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<(i64, UserAgentStat)>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.rowid, s.user_agent, s.hit_count, s.last_seen_at
             FROM (SELECT rowid AS id, hit_count AS hits FROM user_agent_stats
                   ORDER BY hit_count DESC, rowid ASC LIMIT ?1 OFFSET ?2) AS page
             JOIN user_agent_stats AS s ON s.rowid = page.id
             ORDER BY page.hits DESC, page.id ASC",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok((
                row.get(0)?,
                UserAgentStat {
                    user_agent: row.get(1)?,
                    hit_count: row.get(2)?,
                    last_seen_at: row.get(3)?,
                },
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list a page of user agent stats")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn db_with(counts: &[(&str, u64)]) -> Db {
        let db = Db::open_in_memory().unwrap();
        let counts: HashMap<String, u64> =
            counts.iter().map(|(ua, n)| (ua.to_string(), *n)).collect();
        db.record_user_agent_hits(&counts, 1_000).unwrap();
        db
    }

    fn names(page: &[(i64, UserAgentStat)]) -> Vec<&str> {
        page.iter().map(|(_, s)| s.user_agent.as_str()).collect()
    }

    #[test]
    fn pages_run_most_seen_first_without_gaps_or_repeats() {
        let db = db_with(&[("a", 5), ("b", 9), ("c", 5), ("d", 1), ("e", 7)]);

        let mut paged = Vec::new();
        for offset in [0, 2, 4] {
            paged.extend(db.user_agent_stats_page(2, offset).unwrap());
        }

        let hits: Vec<i64> = paged.iter().map(|(_, s)| s.hit_count).collect();
        assert_eq!(hits, [9, 7, 5, 5, 1]);
        let mut seen: Vec<&str> = names(&paged);
        seen.sort_unstable();
        assert_eq!(seen, ["a", "b", "c", "d", "e"], "each agent exactly once");
        assert_eq!(names(&db.user_agent_stats_page(2, 0).unwrap()), ["b", "e"]);
    }
}
