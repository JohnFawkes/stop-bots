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

//! What one pass tallied into `user_agent_stats`: the successful requests
//! of each user agent, from the lines appended to the access log since the
//! last pass (see [`crate::logscan`], which does the reading and the
//! storing, and [`crate::accesslog::successful_user_agent_counts`] for what
//! counts).
//!
//! The tally used to keep its own byte offset into the log, measured in
//! decoded text after reading the whole file, and keyed by the default
//! path even while the internal cron read a stored one. It now shares the
//! read every detector makes, and so its cursor: a line tallied is a line
//! the detectors saw, once.

use std::collections::HashMap;

/// What one pass counted, for both the CLI to print and the cron job to
/// store as its summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessStatsOutcome {
    pub distinct_user_agents: usize,
    pub total_hits: u64,
}

impl AccessStatsOutcome {
    /// The outcome of tallying `counts`.
    pub fn of(counts: &HashMap<String, u64>) -> AccessStatsOutcome {
        AccessStatsOutcome {
            distinct_user_agents: counts.len(),
            total_hits: counts.values().sum(),
        }
    }

    /// The outcome of tallying every one of `counts` together: an agent in
    /// two of them is one agent. A pass reads each access log on its own.
    pub fn of_all<'a>(
        counts: impl IntoIterator<Item = &'a HashMap<String, u64>>,
    ) -> AccessStatsOutcome {
        let mut agents = std::collections::HashSet::new();
        let mut total_hits = 0;
        for counts in counts {
            agents.extend(counts.keys());
            total_hits += counts.values().sum::<u64>();
        }
        AccessStatsOutcome {
            distinct_user_agents: agents.len(),
            total_hits,
        }
    }

    /// Both outcomes' hits and agents, added up.
    pub fn plus(self, other: AccessStatsOutcome) -> AccessStatsOutcome {
        AccessStatsOutcome {
            distinct_user_agents: self.distinct_user_agents + other.distinct_user_agents,
            total_hits: self.total_hits + other.total_hits,
        }
    }

    /// A one-line summary suitable for a status display (the Dashboard's
    /// "Scheduled tasks" panel, `Db::set_cron_last_run`'s `summary`
    /// argument), mirroring `ScanBlockOutcome::summary`'s role.
    pub fn summary(&self) -> String {
        if self.total_hits == 0 {
            return "no successful requests found".to_string();
        }
        format!(
            "recorded {} hit(s) across {} distinct user agent(s)",
            self.total_hits, self.distinct_user_agents
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_outcome_counts_hits_and_distinct_agents() {
        let counts = HashMap::from([("Mozilla/5.0".to_string(), 2), ("curl/8.0".to_string(), 1)]);
        let outcome = AccessStatsOutcome::of(&counts);
        assert_eq!(
            outcome,
            AccessStatsOutcome {
                distinct_user_agents: 2,
                total_hits: 3
            }
        );
        assert_eq!(
            outcome.summary(),
            "recorded 3 hit(s) across 2 distinct user agent(s)"
        );
    }

    /// Read from two logs, an agent seen in both is still one agent.
    #[test]
    fn an_agent_in_two_logs_is_one_agent() {
        let main = HashMap::from([("Mozilla/5.0".to_string(), 2), ("curl/8.0".to_string(), 1)]);
        let site = HashMap::from([("Mozilla/5.0".to_string(), 4)]);

        assert_eq!(
            AccessStatsOutcome::of_all([&main, &site]),
            AccessStatsOutcome {
                distinct_user_agents: 2,
                total_hits: 7
            }
        );
    }

    #[test]
    fn nothing_new_says_so() {
        assert_eq!(
            AccessStatsOutcome::default().summary(),
            "no successful requests found"
        );
    }
}
