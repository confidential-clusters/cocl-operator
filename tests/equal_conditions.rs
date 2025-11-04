// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use regex::Regex;
use std::collections::HashSet;

fn get_quoted_substrings(text: &str) -> HashSet<String> {
    Regex::new(r#""([^"]*)""#)
        .unwrap()
        .captures_iter(text)
        .map(|cap| cap[1].to_string())
        .collect()
}

#[test]
fn conditions_assert_same_quoted() {
    let go_set = get_quoted_substrings(include_str!("../api/v1alpha1/conditions.go"));
    let rust_set = get_quoted_substrings(include_str!("../lib/src/conditions.rs"));
    assert_eq!(go_set, rust_set);
}
