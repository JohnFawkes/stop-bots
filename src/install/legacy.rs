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

//! The firewall units 0.0.x releases wrote, so that one of them can be
//! recognised as unedited.
//!
//! Units from 0.1 on carry the hash of their own text (see
//! [`super::TEMPLATE_MARKER`]), and that answers "has anybody edited
//! this?" for good. A unit written before then has no hash. The only way
//! to tell one that is exactly as a release wrote it from one somebody
//! changed is to know every text a release could have written — which is
//! what this module holds, recovered from the release tags. The firewall
//! unit has no variable part: 0.0.5 to 0.0.12 wrote the nftables one, and
//! 0.0.13 added the iptables one beside it.
//!
//! **Frozen.** These are the bytes on real hosts; they never change.

const FIREWALL_NFT: &str = include_str!("legacy/firewall-nftables-0.0.5-to-0.0.15.service");
const FIREWALL_IPTABLES: &str = include_str!("legacy/firewall-iptables-0.0.13-to-0.0.15.service");

/// The release range that wrote `text`, if it is a firewall unit exactly
/// as a 0.0.x release wrote it.
pub fn firewall_unit(text: &str) -> Option<&'static str> {
    if text == FIREWALL_NFT {
        Some("0.0.5 to 0.0.15")
    } else if text == FIREWALL_IPTABLES {
        Some("0.0.13 to 0.0.15")
    } else {
        None
    }
}
