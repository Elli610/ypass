//! Interactive domain and username selection with autocomplete

use crate::state::{State, add_username};
use crate::utils::normalize_domain;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper};
use std::borrow::Cow;

/// Autocomplete helper for domain/username selection
struct StringCompleter {
    candidates: Vec<String>,
}

impl StringCompleter {
    fn new(candidates: Vec<String>) -> Self {
        Self { candidates }
    }
}

impl Completer for StringCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let input = &line[..pos].to_lowercase();
        let matches: Vec<Pair> = self
            .candidates
            .iter()
            .filter(|c| c.to_lowercase().starts_with(input))
            .map(|c| Pair {
                display: c.clone(),
                replacement: c.clone(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for StringCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() {
            return None;
        }
        let input = line.to_lowercase();
        self.candidates
            .iter()
            .find(|c| c.to_lowercase().starts_with(&input) && c.len() > line.len())
            .map(|c| c[line.len()..].to_string())
    }
}

impl Highlighter for StringCompleter {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Gray color for hints
        Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
    }
}

impl Validator for StringCompleter {}
impl Helper for StringCompleter {}

/// Interactive domain selection with autocomplete
pub fn select_domain(state: &State) -> Result<String, Box<dyn std::error::Error>> {
    let mut domains: Vec<String> = state.domains.keys().cloned().collect();
    domains.sort();

    let completer = StringCompleter::new(domains.clone());
    let mut rl = Editor::new()?;
    rl.set_helper(Some(completer));

    let input = match rl.readline("Domain: ") {
        Ok(line) => line.trim().to_string(),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            return Err("Cancelled".into());
        }
        Err(e) => return Err(e.into()),
    };

    if input.is_empty() {
        return Err("No domain selected".into());
    }

    // Check if it's an exact match
    if domains
        .iter()
        .any(|d| d.to_lowercase() == input.to_lowercase())
    {
        return Ok(normalize_domain(&input));
    }

    // Check for prefix match
    let matches: Vec<_> = domains
        .iter()
        .filter(|d| d.to_lowercase().starts_with(&input.to_lowercase()))
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    // Treat as new domain
    Ok(normalize_domain(&input))
}

/// Interactive username selection with autocomplete
pub fn select_username(
    usernames: &[String],
    domain: &str,
    state: &mut State,
    state_modified: &mut bool,
) -> Result<String, Box<dyn std::error::Error>> {
    const MAX_DISPLAY: usize = 10;

    eprintln!();
    eprintln!("Usernames for '{}':", domain);

    if usernames.is_empty() {
        eprintln!("  (no saved usernames)");
    } else {
        let display_count = usernames.len().min(MAX_DISPLAY);
        for (i, u) in usernames.iter().take(display_count).enumerate() {
            eprintln!("  [{}] {}", i + 1, u);
        }
        if usernames.len() > MAX_DISPLAY {
            eprintln!(
                "  ... +{} more (Tab to complete)",
                usernames.len() - MAX_DISPLAY
            );
        }
    }
    eprintln!("  [d] domain-only mode (or press Enter with empty input)");
    eprintln!();

    let completer = StringCompleter::new(usernames.to_vec());
    let mut rl = Editor::new()?;
    rl.set_helper(Some(completer));

    let input = match rl.readline("Username: ") {
        Ok(line) => line.trim().to_string(),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            return Err("Cancelled".into());
        }
        Err(e) => return Err(e.into()),
    };

    // Empty input = domain-only mode
    if input.is_empty() {
        return Ok(String::new());
    }

    // Domain-only mode
    if input == "d" || input == "D" {
        return Ok(String::new());
    }

    // Try to parse as number
    if let Ok(n) = input.parse::<usize>() {
        if n >= 1 && n <= usernames.len() {
            return Ok(usernames[n - 1].clone());
        }
    }

    // Exact match (case-insensitive)
    if let Some(matched) = usernames
        .iter()
        .find(|u| u.to_lowercase() == input.to_lowercase())
    {
        return Ok(matched.clone());
    }

    // Prefix match
    let matches: Vec<_> = usernames
        .iter()
        .filter(|u| u.to_lowercase().starts_with(&input.to_lowercase()))
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    // No match - treat as new username
    add_username(state, domain, &input);
    *state_modified = true;
    Ok(input)
}
