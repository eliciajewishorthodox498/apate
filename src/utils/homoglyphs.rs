/// Bidirectional ASCII ↔ Cyrillic homoglyph mapping.
///
/// These characters are visually identical but have different Unicode codepoints,
/// making grep/search/copy-paste fail silently.
const MAPPINGS: &[(char, char)] = &[
    ('a', '\u{0430}'), // Cyrillic Small A
    ('c', '\u{0441}'), // Cyrillic Small ES
    ('e', '\u{0435}'), // Cyrillic Small IE
    ('o', '\u{043E}'), // Cyrillic Small O
    ('p', '\u{0440}'), // Cyrillic Small ER
    ('x', '\u{0445}'), // Cyrillic Small HA
    ('y', '\u{0443}'), // Cyrillic Small U
    ('s', '\u{0455}'), // Cyrillic Small DZE
    ('i', '\u{0456}'), // Cyrillic Small Byelorussian-Ukrainian I
    ('B', '\u{0412}'), // Cyrillic Capital VE
    ('H', '\u{041D}'), // Cyrillic Capital EN
    ('K', '\u{041A}'), // Cyrillic Capital KA
    ('M', '\u{041C}'), // Cyrillic Capital EM
    ('T', '\u{0422}'), // Cyrillic Capital TE
];

/// Look up the Cyrillic homoglyph for an ASCII character.
pub fn ascii_to_homoglyph(c: char) -> Option<char> {
    MAPPINGS.iter().find(|(a, _)| *a == c).map(|(_, h)| *h)
}

/// Look up the original ASCII character for a Cyrillic homoglyph.
pub fn homoglyph_to_ascii(c: char) -> Option<char> {
    MAPPINGS.iter().find(|(_, h)| *h == c).map(|(a, _)| *a)
}

/// Check if a character has a homoglyph replacement available.
pub fn has_homoglyph(c: char) -> bool {
    MAPPINGS.iter().any(|(a, _)| *a == c)
}

/// Return indices of characters in `ident` that have homoglyph replacements.
pub fn eligible_positions(ident: &str) -> Vec<usize> {
    ident
        .char_indices()
        .filter(|(_, c)| has_homoglyph(*c))
        .map(|(i, _)| i)
        .collect()
}
