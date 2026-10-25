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

//! `site_waf`: each site's own choice about the web application firewall,
//! where it has made one. See `crate::exploits` and `crate::modsecurity`.

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use super::Db;

/// One site's choices. `None` everywhere is a site that follows the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteWaf {
    pub exploit_rules: Option<bool>,
    /// `modsecurity::Mode::as_str`.
    pub modsecurity: Option<String>,
    pub paranoia: Option<u8>,
}

impl Db {
    pub fn site_waf(&self, site_id: i64) -> Result<SiteWaf> {
        Ok(self
            .conn
            .query_row(
                "SELECT exploit_rules, modsecurity, paranoia FROM site_waf WHERE site_id = ?1",
                params![site_id],
                |row| {
                    Ok(SiteWaf {
                        exploit_rules: row.get(0)?,
                        modsecurity: row.get(1)?,
                        paranoia: row.get(2)?,
                    })
                },
            )
            .optional()
            .context("failed to read a site's firewall choices")?
            .unwrap_or_default())
    }

    fn write_site_waf(&self, site_id: i64, waf: &SiteWaf) -> Result<()> {
        if *waf == SiteWaf::default() {
            self.conn
                .execute("DELETE FROM site_waf WHERE site_id = ?1", params![site_id])?;
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO site_waf (site_id, exploit_rules, modsecurity, paranoia)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (site_id) DO UPDATE SET
                 exploit_rules = excluded.exploit_rules,
                 modsecurity = excluded.modsecurity,
                 paranoia = excluded.paranoia",
            params![site_id, waf.exploit_rules, waf.modsecurity, waf.paranoia],
        )?;
        Ok(())
    }

    /// Sets `site_id`'s own choice of exploit rules; `None` follows the
    /// host again.
    pub fn set_site_exploit_rules(&self, site_id: i64, enabled: Option<bool>) -> Result<()> {
        let mut waf = self.site_waf(site_id)?;
        waf.exploit_rules = enabled;
        self.write_site_waf(site_id, &waf)
    }

    /// Sets `site_id`'s own ModSecurity mode; `None` follows the host.
    pub fn set_site_modsecurity(&self, site_id: i64, mode: Option<&str>) -> Result<()> {
        let mut waf = self.site_waf(site_id)?;
        waf.modsecurity = mode.map(str::to_string);
        self.write_site_waf(site_id, &waf)
    }

    /// Sets `site_id`'s own paranoia level; `None` follows the host.
    pub fn set_site_paranoia(&self, site_id: i64, level: Option<u8>) -> Result<()> {
        let mut waf = self.site_waf(site_id)?;
        waf.paranoia = level;
        self.write_site_waf(site_id, &waf)
    }
}

/// One CRS rule switched off for one site, under one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModsecExclusion {
    pub site_id: i64,
    pub rule_id: u32,
    /// The path prefix, which starts with `/`.
    pub path: String,
}

/// Whether `path` may go into a ModSecurity rule as an operand: a path,
/// with nothing that would end the quoted argument or the line.
pub fn is_exclusion_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 512
        && !path
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '\''))
}

impl Db {
    /// Adds an exclusion; one already there is no change.
    pub fn add_modsec_exclusion(&self, site_id: i64, rule_id: u32, path: &str) -> Result<()> {
        if !is_exclusion_path(path) {
            anyhow::bail!("not a path that can be excluded: {path:?}");
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO modsecurity_exclusions (site_id, rule_id, path, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![site_id, rule_id, path, super::now()],
        )?;
        Ok(())
    }

    pub fn remove_modsec_exclusion(&self, site_id: i64, rule_id: u32, path: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM modsecurity_exclusions WHERE site_id = ?1 AND rule_id = ?2 AND path = ?3",
            params![site_id, rule_id, path],
        )? > 0)
    }

    /// Every exclusion, by site, rule and path. A row whose path would not
    /// be accepted now is left out: it goes into a file NGINX loads.
    pub fn modsec_exclusions(&self) -> Result<Vec<ModsecExclusion>> {
        let mut stmt = self.conn.prepare(
            "SELECT site_id, rule_id, path FROM modsecurity_exclusions
             ORDER BY site_id, rule_id, path",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ModsecExclusion {
                site_id: row.get(0)?,
                rule_id: row.get(1)?,
                path: row.get(2)?,
            })
        })?;
        let all: Vec<ModsecExclusion> = rows
            .collect::<rusqlite::Result<_>>()
            .context("failed to list ModSecurity exclusions")?;
        Ok(all
            .into_iter()
            .filter(|e| is_exclusion_path(&e.path))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_that_chose_nothing_has_no_row_and_follows_the_host() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("a.example", "/etc/nginx/sites-enabled/a")
            .unwrap();
        let site = db.list_sites().unwrap()[0].id;
        assert_eq!(db.site_waf(site).unwrap(), SiteWaf::default());
        db.set_site_exploit_rules(site, Some(true)).unwrap();
        db.set_site_paranoia(site, Some(2)).unwrap();
        assert_eq!(
            db.site_waf(site).unwrap(),
            SiteWaf {
                exploit_rules: Some(true),
                modsecurity: None,
                paranoia: Some(2),
            }
        );
        db.set_site_exploit_rules(site, None).unwrap();
        db.set_site_paranoia(site, None).unwrap();
        let rows: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM site_waf", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "a row was left for a site that follows the host");
    }

    /// The path goes into a rule NGINX loads, inside quotes.
    #[test]
    fn an_exclusion_path_that_could_break_out_of_its_rule_is_refused() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("a.example", "/etc/nginx/sites-enabled/a")
            .unwrap();
        let site = db.list_sites().unwrap()[0].id;
        for bad in ["wp-admin", "/a b", "/a\"x", "/a\nSecRuleEngine Off"] {
            assert!(
                db.add_modsec_exclusion(site, 942100, bad).is_err(),
                "{bad:?} was taken"
            );
        }
        db.add_modsec_exclusion(site, 942100, "/wp-admin/admin-ajax.php")
            .unwrap();
        db.add_modsec_exclusion(site, 942100, "/wp-admin/admin-ajax.php")
            .unwrap();
        assert_eq!(db.modsec_exclusions().unwrap().len(), 1);
    }
}
