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

//! "Keep these firewall rules?": the TUI's half of confirm-or-revert (see
//! [`crate::revert`]), over whichever screen is open, with the seconds
//! left counting down.
//!
//! Owned by `App`, not by a screen: an apply can finish while the operator
//! is anywhere, and until it is answered no other key may do anything
//! else. Enter or `y` keeps; Esc or `n` reverts now; nothing at all, by
//! the deadline, reverts — and so does the timer outside this process if
//! the TUI or the SSH session dies first.

use crate::revert::{Answer, Pending};
use crate::tui::Theme;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Clear, Paragraph, Wrap};
use std::time::{Duration, Instant};

/// An apply that is loaded and waiting for an answer.
#[derive(Debug, Clone)]
pub struct KeepFirewall {
    pub pending: Pending,
    /// What was applied: what a keep makes the boot script.
    pub script: String,
    /// Recorded as the applied signature once kept.
    pub signature: String,
    deadline: Instant,
}

impl KeepFirewall {
    /// Waiting for `left` more, by this process's clock — the timer
    /// outside it has its own, for the same moment.
    pub fn new(pending: Pending, script: String, signature: String, left: Duration) -> Self {
        KeepFirewall {
            pending,
            script,
            signature,
            deadline: Instant::now() + left,
        }
    }

    pub fn seconds_left(&self) -> u64 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64()
            .ceil() as u64
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// What `key` answers, if anything. Every other key is swallowed: this
    /// question comes first.
    pub fn answer(key: KeyEvent) -> Option<Answer> {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y' | 'Y') => Some(Answer::Keep),
            KeyCode::Esc | KeyCode::Char('n' | 'N') => Some(Answer::Revert),
            _ => None,
        }
    }

    /// Over `area`. `settling` once an answer is being carried out.
    pub fn render(&self, frame: &mut Frame, area: Rect, theme: Theme, settling: bool) {
        let popup_area = crate::tui::centered_rect(64, 9, area);
        frame.render_widget(Clear, popup_area);
        let block = crate::tui::popup("Keep these firewall rules?", theme);
        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);

        let countdown = if settling {
            Line::from("Settling\u{2026}".fg(theme.live()))
        } else {
            Line::from(vec![
                "Reverting in ".into(),
                format!("{} s", self.seconds_left())
                    .fg(theme.accent())
                    .bold(),
            ])
        };
        let lines = vec![
            Line::from(
                "The new rules are loaded. If you can still reach this server, keep them; \
                 if nobody answers, the previous rules come back.",
            ),
            Line::from(""),
            countdown,
            Line::from(""),
            Line::from("Enter/y keep   Esc/n revert now".fg(theme.dim())),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    #[test]
    fn enter_and_y_keep_esc_and_n_revert_and_the_rest_answer_nothing() {
        let cases = [
            (KeyCode::Enter, Some(Answer::Keep)),
            (KeyCode::Char('y'), Some(Answer::Keep)),
            (KeyCode::Esc, Some(Answer::Revert)),
            (KeyCode::Char('n'), Some(Answer::Revert)),
            (KeyCode::Char('q'), None),
            (KeyCode::Tab, None),
        ];
        for (code, expected) in cases {
            let key = KeyEvent::new(code, KeyModifiers::NONE);
            assert_eq!(KeepFirewall::answer(key), expected, "pressing {code:?}");
        }
    }
}
