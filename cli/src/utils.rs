//! Utility functions

/// Normalize domain for consistent password generation
pub fn normalize_domain(input: &str) -> String {
    let mut domain = input.trim().to_lowercase();

    // Remove protocol prefixes
    if let Some(rest) = domain.strip_prefix("https://") {
        domain = rest.to_string();
    } else if let Some(rest) = domain.strip_prefix("http://") {
        domain = rest.to_string();
    }

    // Remove www prefix
    if let Some(rest) = domain.strip_prefix("www.") {
        domain = rest.to_string();
    }

    // Remove trailing slashes, paths, query strings, and fragments
    // Find the first occurrence of /, ?, or # and truncate
    if let Some(pos) = domain.find(['/', '?', '#']) {
        domain.truncate(pos);
    }

    // Remove port numbers (e.g., localhost:3000 -> localhost)
    if let Some(pos) = domain.rfind(':') {
        // Only remove if what follows looks like a port number
        let potential_port = &domain[pos + 1..];
        if !potential_port.is_empty() && potential_port.chars().all(|c| c.is_ascii_digit()) {
            domain.truncate(pos);
        }
    }

    domain
}

/// Decode hex string to bytes
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length".into());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)?;
        bytes.push(byte);
    }

    Ok(bytes)
}
