// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;

/// Compare two sets of PCRs to check if they match
pub fn compare_pcrs(actual: &[Pcr], expected: &[Pcr]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }

    for (a, e) in actual.iter().zip(expected.iter()) {
        if a.id != e.id || a.value != e.value {
            return false;
        }

        if a.parts.len() != e.parts.len() {
            return false;
        }

        for (ap, ep) in a.parts.iter().zip(e.parts.iter()) {
            if ap.name != ep.name || ap.hash != ep.hash {
                return false;
            }
        }
    }

    true
}
