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

//! `?`: what the row under the cursor is, beside the keys that act on it.
//!
//! Every screen answers "what is this" with an `explain()` beside its
//! `hints()`, and `App` draws the answer over whatever screen is open, the
//! way it draws the command palette. The keys come from the same `hints()`
//! the footer shows, so the two cannot disagree; what this adds is the
//! text, which the footer has no room for. `?` again opens the full key
//! reference, which is what `?` alone used to do.

use crate::tui::{Hints, Theme};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};

/// What a screen says about the row under its cursor: a title and a few
/// short paragraphs. Built with the methods below, so the screens write
/// sentences rather than `Line`s.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Explanation {
    pub title: String,
    pub body: Vec<Line<'static>>,
}

impl Explanation {
    pub fn new(title: impl Into<String>) -> Self {
        Explanation {
            title: title.into(),
            body: Vec::new(),
        }
    }

    /// A paragraph of plain text.
    pub fn para(self, text: impl Into<String>) -> Self {
        self.push(Line::from(text.into()))
    }

    /// The row's current state: "Now: on, blocking for 7 days."
    pub fn now(self, text: impl Into<String>) -> Self {
        self.push(Line::from(vec![
            Span::from("Now: ").bold(),
            Span::from(text.into()),
        ]))
    }

    /// Something that can go wrong, set apart in yellow.
    pub fn warn(self, text: impl Into<String>) -> Self {
        // Capitalised here: some warnings are shared with places that
        // put them mid-sentence.
        let text = text.into();
        let mut chars = text.chars();
        let text: String = chars
            .next()
            .map(|first| first.to_uppercase().chain(chars).collect())
            .unwrap_or_default();
        self.push(Line::from(format!("\u{26a0} {text}")).yellow())
    }

    /// [`Self::warn`] when there is a warning.
    pub fn warn_if(self, text: Option<impl Into<String>>) -> Self {
        match text {
            Some(text) => self.warn(text),
            None => self,
        }
    }

    /// When a change here reaches the host: the sentence that answers
    /// "did that just do something?", which every setting raises.
    pub fn takes_effect(self, auto_apply: bool) -> Self {
        self.push(
            Line::from(if auto_apply {
                "Auto-apply is on: a change here reaches the firewall within minutes."
            } else {
                "A change here reaches the host when you apply (a on the Dashboard)."
            })
            .italic(),
        )
    }

    fn push(mut self, line: Line<'static>) -> Self {
        if !self.body.is_empty() {
            self.body.push(Line::default());
        }
        self.body.push(line);
        self
    }
}

/// The open popup: the explanation, the keys for the panel it was opened
/// on, and how far the text is scrolled.
#[derive(Debug, Clone)]
pub struct Explain {
    explanation: Explanation,
    panel: &'static str,
    keys: Vec<(&'static str, &'static str)>,
    scroll: u16,
}

/// What a key in the popup asks of `App`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainKey {
    Stay,
    Close,
    /// `?` again: close, and open the full key reference.
    AllKeys,
}

/// The keys that work on every screen, below the panel's own.
const EVERYWHERE: [(&str, &str); 5] = [
    ("1-5", "go to a screen"),
    ("v", "simple / all screens"),
    (":", "every action by name"),
    ("t", "light / dark theme"),
    ("Esc", "back, or quit"),
];

/// The key column's width, border included.
const KEYS_WIDTH: u16 = 30;

/// Below this many columns the keys go under the text instead of beside it.
const SIDE_BY_SIDE_MIN: u16 = 90;

impl Explain {
    /// `hints` is the screen's footer hints for the focused panel.
    pub fn new(explanation: Explanation, hints: Hints) -> Self {
        Explain {
            explanation,
            panel: hints.0,
            keys: hints.1,
            scroll: 0,
        }
    }

    pub fn handle_key(&mut self, code: KeyCode) -> ExplainKey {
        match code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => return ExplainKey::Close,
            KeyCode::Char('?') => return ExplainKey::AllKeys,
            KeyCode::Down | KeyCode::Char('j') => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            _ => {}
        }
        ExplainKey::Stay
    }

    pub fn hints(&self) -> Hints {
        (
            "Explain",
            vec![
                ("\u{2191}\u{2193}", "scroll"),
                ("?", "every key"),
                ("Esc", "close"),
            ],
        )
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: Theme) {
        let side_by_side = area.width >= SIDE_BY_SIDE_MIN;
        let width = area.width.saturating_sub(4).min(110);
        // Less the popup's borders and the text's own one-cell margins.
        let text_width = if side_by_side {
            width.saturating_sub(KEYS_WIDTH + 4)
        } else {
            width.saturating_sub(4)
        }
        .max(1);
        let keys = self.key_lines(theme);
        let text_height = wrapped_height(&self.explanation.body, text_width);
        // The keys' panel title takes a row of its own.
        let keys_height = keys.len() as u16 + 1;
        let body_height = if side_by_side {
            text_height.max(keys_height)
        } else {
            text_height + 1 + keys_height
        };
        let popup_area = crate::tui::centered_rect(width, body_height + 2, area);
        frame.render_widget(Clear, popup_area);
        let block = crate::tui::popup(self.explanation.title.clone(), theme);
        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);

        let (text_area, keys_area) = if side_by_side {
            let [text, keys] =
                Layout::horizontal([Constraint::Min(1), Constraint::Length(KEYS_WIDTH)])
                    .areas(inner);
            (text, keys)
        } else {
            let [text, keys] =
                Layout::vertical([Constraint::Min(1), Constraint::Length(keys_height)])
                    .areas(inner);
            (text, keys)
        };
        // Scrolled no further than the last line, so a long press of Down
        // does not leave a blank box.
        let scroll = self
            .scroll
            .min(text_height.saturating_sub(text_area.height));
        frame.render_widget(
            Paragraph::new(self.explanation.body.clone())
                .block(Block::new().padding(Padding::horizontal(1)))
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0)),
            text_area,
        );
        let edge = if side_by_side {
            Borders::LEFT
        } else {
            Borders::TOP
        };
        frame.render_widget(
            Paragraph::new(keys).block(
                Block::new()
                    .borders(edge)
                    .border_style(theme.dim())
                    .title(format!(" {} ", self.panel).fg(theme.accent())),
            ),
            keys_area,
        );
    }

    /// The panel's keys, then the ones that work everywhere.
    fn key_lines(&self, theme: Theme) -> Vec<Line<'static>> {
        let key_width = self
            .keys
            .iter()
            .chain(&EVERYWHERE)
            .map(|(key, _)| key.chars().count())
            .max()
            .unwrap_or(0);
        let line = |(key, label): &(&'static str, &'static str)| -> Line<'static> {
            Line::from(vec![
                Span::from(format!(" {key:<key_width$} ")).fg(theme.accent()),
                Span::from(*label),
            ])
        };
        self.keys
            .iter()
            .map(line)
            .chain(std::iter::once(Line::from(" anywhere").fg(theme.dim())))
            .chain(EVERYWHERE.iter().map(line))
            .collect()
    }

    #[cfg(test)]
    pub fn explanation(&self) -> &Explanation {
        &self.explanation
    }
}

/// How many rows `lines` take wrapped to `width`, roughly as `Paragraph`
/// wraps them: by width, not by word, which can only overcount.
fn wrapped_height(lines: &[Line<'_>], width: u16) -> u16 {
    let width = width.max(1) as usize;
    lines
        .iter()
        .map(|line| line.width().div_ceil(width).max(1) as u16)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn screen(width: u16, height: u16, explain: &Explain) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| explain.render(frame, frame.area(), Theme::Dark))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                let row: String = (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
                row + "\n"
            })
            .collect()
    }

    fn sample() -> Explain {
        Explain::new(
            Explanation::new("Rotating user agent")
                .para("Blocks an address that sends many different user agents.")
                .now("off.")
                .warn("Can catch real people.")
                .takes_effect(false),
            ("Automatic", vec![("Space", "on/off"), ("Enter", "change")]),
        )
    }

    /// On a wide terminal the keys sit beside the text: both are on the
    /// first row of the body.
    #[test]
    fn the_keys_sit_beside_the_text_on_a_wide_terminal() {
        let drawn = screen(120, 30, &sample());

        let row = drawn
            .lines()
            .find(|row| row.contains("Blocks an address"))
            .unwrap_or_else(|| panic!("no text:\n{drawn}"));
        assert!(
            row.contains("Automatic"),
            "keys not beside the text:\n{drawn}"
        );
        for needle in [
            "Rotating user agent",
            "Now:",
            "Can catch",
            "Space",
            "anywhere",
            "Esc",
        ] {
            assert!(drawn.contains(needle), "{needle:?} missing:\n{drawn}");
        }
    }

    #[test]
    fn the_keys_go_under_the_text_on_a_narrow_terminal() {
        let drawn = screen(70, 30, &sample());

        let text_row = drawn.lines().position(|row| row.contains("Blocks an"));
        let key_row = drawn.lines().position(|row| row.contains("Space"));
        assert!(
            matches!((text_row, key_row), (Some(text), Some(key)) if key > text),
            "keys should be below the text:\n{drawn}"
        );
    }

    #[test]
    fn question_mark_again_asks_for_every_key_and_esc_closes() {
        let mut explain = sample();
        assert_eq!(explain.handle_key(KeyCode::Down), ExplainKey::Stay);
        assert_eq!(explain.handle_key(KeyCode::Char('?')), ExplainKey::AllKeys);
        assert_eq!(explain.handle_key(KeyCode::Esc), ExplainKey::Close);
    }
}
