/**
 * Description and tool-name sanitizers shared across loaders.
 *
 * Both OpenAPI/GraphQL/HAR loaders and the upstream MCP linker (`connect.js`)
 * accept tool definitions whose `description` field is rendered into the LLM
 * tool list verbatim. Adversarial review confirmed that:
 *
 *  - Spec-supplied descriptions are an unauthenticated prompt-injection
 *    channel (loader scan HB-1, linking scan H1).
 *  - Tool names produced by the loader pipeline are not Unicode-normalized,
 *    so a HAR/spec entry with a homoglyph or zero-width space can register a
 *    visually-identical tool that shadows a legitimate one (loader scan H6).
 *
 * @module core/sanitize
 */

/**
 * Patterns indicative of prompt-injection attempts embedded in human-readable
 * fields (tool descriptions, summary, parameter docs, etc.) that flow into
 * the LLM context window. Mirrors the list previously inlined in connect.js
 * so all loaders apply the same policy.
 */
export const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /system\s+override/i,
  /forget\s+(all\s+)?(previous|prior|your)\s+instructions?/i,
  /disregard\s+(all\s+)?(previous|prior)\s+instructions?/i,
  /you\s+are\s+now\b/i,
  /new\s+instructions?:/i,
  /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, // Chat template injection
  /exfiltrate|send\s+to\s+https?:\/\//i,
];

/**
 * Homoglyph map for Cyrillic and Greek characters that are visually identical
 * (or near-identical) to Latin letters. An attacker could embed a "Cyrillic
 * word" that renders as an English trigger word. Only letters commonly
 * exploited in injection strings are listed; the map is intentionally narrow
 * to avoid false positives on legitimate Cyrillic content.
 *
 * The map covers both Cyrillic and Greek confusables. Greek homoglyphs (e.g.
 * ο U+03BF OMICRON) are visually identical to Latin letters but are NOT
 * normalized to Latin by NFKC, so they bypassed earlier injection-detection
 * strategies. Greek letters added are visual twins of ASCII letters used in
 * common injection trigger words (ignore, forget, disregard, system,
 * exfiltrate).
 */
const HOMOGLYPHS = {
  // ── Cyrillic ───────────────────────────────────────────────────────────
  '\u0410': 'A', '\u0430': 'a', // А/а → A/a
  '\u0412': 'B',                // В → B (uppercase)
  '\u0421': 'C', '\u0441': 'c', // С/с → C/c
  '\u0415': 'E', '\u0435': 'e', // Е/е → E/e
  '\u041D': 'H',                // Н → H
  '\u0406': 'I', '\u0456': 'i', // І/і → I/i
  '\u0408': 'J',                // Ј → J
  '\u041A': 'K',                // К → K
  '\u041C': 'M',                // М → M
  '\u041E': 'O', '\u043E': 'o', // О/о → O/o
  '\u0420': 'P', '\u0440': 'p', // Р/р → P/p
  '\u0422': 'T',                // Т → T
  '\u0443': 'y',                // у → y
  '\u0425': 'X', '\u0445': 'x', // Х/х → X/x
  // Additional visually-confusable Cyrillic codepoints.
  '\u043B': 'l', // л → l  (U+043B CYRILLIC SMALL LETTER EL)
  '\u0432': 'v', // в → v  (U+0432 CYRILLIC SMALL LETTER VE)
  '\u0433': 'r', // г → r  (U+0433 CYRILLIC SMALL LETTER GHE)
  '\u0434': 'd', // д → d  (U+0434 CYRILLIC SMALL LETTER DE)
  '\u0446': 'u', // ц → u  (U+0446 CYRILLIC SMALL LETTER TSE)
  '\u0455': 's', // ѕ → s  (U+0455 CYRILLIC SMALL LETTER DZE)
  '\u0457': 'i', // ї → i  (U+0457 CYRILLIC SMALL LETTER YI)
  '\u0458': 'j', // ј → j  (U+0458 CYRILLIC SMALL LETTER JE)
  // ── Greek ──────────────────────────────────────────────────────────────
  // NFKC does NOT map Greek letters to their Latin visual twins.
  // Source: Unicode Confusables data
  '\u0391': 'A', '\u03B1': 'a', // Α/α → A/a  (Alpha)
  '\u0395': 'E', '\u03B5': 'e', // Ε/ε → E/e  (Epsilon)
  '\u0397': 'H',                // Η → H       (Eta uppercase)
  '\u0399': 'I', '\u03B9': 'i', // Ι/ι → I/i  (Iota)
  '\u039A': 'K', '\u03BA': 'k', // Κ/κ → K/k  (Kappa)
  '\u039C': 'M',                // Μ → M       (Mu uppercase)
  '\u039D': 'N',                // Ν → N       (Nu uppercase)
  '\u03BD': 'v',                // ν → v       (Nu lowercase — looks like v)
  '\u039F': 'O', '\u03BF': 'o', // Ο/ο → O/o  (Omicron)
  '\u03A1': 'P', '\u03C1': 'p', // Ρ/ρ → P/p  (Rho)
  '\u03A4': 'T', '\u03C4': 't', // Τ/τ → T/t  (Tau)
  '\u03A5': 'Y', '\u03C5': 'u', // Υ/υ → Y/u  (Upsilon)
  '\u03A7': 'X', '\u03C7': 'x', // Χ/χ → X/x  (Chi)
  '\u0396': 'Z', '\u03B6': 'z', // Ζ/ζ → Z/z  (Zeta)
};
const HOMOGLYPH_RE = new RegExp(Object.keys(HOMOGLYPHS).join('|'), 'g');

/**
 * Produce a set of candidate strings that cover common Unicode bypass
 * techniques. The injection check passes if ANY candidate matches a
 * pattern — conservative, but correct: a string that looks like an
 * injection attempt from any normalization angle IS an attempt.
 *
 * Three strategies applied after NFKC (which folds full-width digits,
 * ligatures, and compatibility forms):
 *  1. Zero-width chars stripped to empty — defeats in-word splitting
 *     ("Ign\u200Bore" → "Ignore").
 *  2. Zero-width chars replaced with space — defeats between-word
 *     splitting ("Ignore\u200Call" → "Ignore all").
 *  3. Cyrillic homoglyphs transliterated to Latin, then stripped —
 *     defeats visual spoofing ("Ign\u043Ere" → "Ignore").
 *
 * @param {string} text Raw input string
 * @returns {string[]} Candidate strings for pattern matching
 */
function injectionCandidates(text) {
  const nfkc = text.normalize('NFKC');
  // Strategy 1: strip zero-width chars (U+200B ZWSP, U+200C ZWNJ,
  // U+200D ZWJ, U+FEFF BOM/ZWNBSP) to empty.
  const stripped = nfkc.replace(/[\u200B-\u200D\uFEFF]/g, '');
  // Strategy 2: replace zero-width chars with a space.
  const spaced = nfkc.replace(/[\u200B-\u200D\uFEFF]/g, ' ');
  // Strategy 3: transliterate homoglyphs (Cyrillic + Greek) then strip zero-width.
  const homoglyphed = stripped.replace(HOMOGLYPH_RE, (ch) => HOMOGLYPHS[ch]);
  // Strategy 4: NFD decomposition strips combining marks differently than NFKC —
  // defeats injection via Unicode combining diacritics (e.g. i̊g̈ṅo̊r̈e̊).
  // Also strips RTL/LTR marks and zero-width characters after NFD.
  const nfdStripped = text.normalize('NFD').replace(/[\u0300-\u036f\u200b-\u200f\u202a-\u202e]/gu, '');
  // Strategy 5: strip RTL/LTR marks and zero-width characters from the raw text —
  // defeats bidi-override injection that visually reorders visible characters.
  const rtlStripped = text.replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu, '');
  // Strategy 6: strip Unicode Tag characters (U+E0000–U+E01FF).
  // These invisible codepoints (e.g. U+E006F TAG LATIN SMALL LETTER O) are not
  // removed by NFKC, NFD, or any bidi-strip strategy. An attacker can embed
  // them inside trigger words to evade pattern matching while the string renders
  // identically to a human reviewer. Apply to both NFKC and raw text.
  const tagStripped = nfkc.replace(/[\u{E0000}-\u{E01FF}]/gu, '');
  const tagStrippedRaw = text.replace(/[\u{E0000}-\u{E01FF}]/gu, '');
  return [stripped, spaced, homoglyphed, nfdStripped, rtlStripped, tagStripped, tagStrippedRaw];
}

/**
 * Test whether a string contains any prompt-injection signal.
 *
 * Test multiple normalized candidates to defeat Unicode bypass techniques:
 *  - zero-width chars stripped to empty (in-word split defeat)
 *  - zero-width chars replaced with space (between-word split defeat)
 *  - Cyrillic and Greek homoglyphs transliterated to Latin equivalents
 *  - NFD decomposition and RTL/LTR mark stripping
 *  - Unicode Tag character removal
 *
 * @param {string} text
 * @returns {boolean}
 */
export function hasPromptInjection(text) {
  if (typeof text !== 'string') return false;
  return injectionCandidates(text).some(
    (candidate) => PROMPT_INJECTION_PATTERNS.some((re) => re.test(candidate)),
  );
}

/**
 * Maximum byte length for a sanitized tool description.
 *
 * A legitimate, expressive description is typically 100–1 000 chars.
 * 4 KiB gives operators plenty of headroom while bounding the per-tool
 * LLM context cost. A bridge with 100 tools × 4 KiB ≈ 400 KiB of tool
 * list (~100 k tokens) — large, but at least bounded and predictable.
 *
 * Without this cap an adversarial spec could ship 50 MiB of
 * description text per session start, filling the LLM context window,
 * inflating API costs, and bloating bridge memory.
 */
export const MAX_DESCRIPTION_BYTES = 4096;

/**
 * Sanitize a description string for safe inclusion in the LLM tool list.
 *
 * Processing order (each short-circuits if triggered):
 *  1. Prompt-injection check — redacts the whole description on match.
 *  2. Size cap — truncates to MAX_DESCRIPTION_BYTES and appends a marker
 *     so the LLM (and operator logs) can see that truncation occurred.
 *
 * The injection check runs first so a redacted placeholder (~60 bytes) is
 * never itself subject to the size check — the placeholder is always safe.
 *
 * Descriptions exceeding MAX_DESCRIPTION_BYTES are truncated and a trailing
 * marker is appended so operators notice the cap was hit.
 *
 * @param {string} text Raw description from the spec/HAR/upstream
 * @param {object} [opts]
 * @param {string} [opts.label] Provenance label for the placeholder
 * @returns {string}
 */
export function sanitizeDescription(text, opts = {}) {
  if (typeof text !== 'string') return '';
  // Strip NUL bytes (\u0000) — they can smuggle hidden content past naive
  // length checks and confuse downstream LLM tokenizers / JSON parsers.
  const clean = text.replace(/\u0000/g, '');
  if (hasPromptInjection(clean)) {
    const where = opts.label ? ` (${opts.label})` : '';
    return `[description redacted${where} — prompt-injection pattern detected]`;
  }
  if (clean.length > MAX_DESCRIPTION_BYTES) {
    const overflow = clean.length - MAX_DESCRIPTION_BYTES;
    const label = opts.label ? ` [${opts.label}]` : '';
    process.stderr.write(
      `[40mcp] WARNING: tool description${label} truncated — ${overflow} chars over ${MAX_DESCRIPTION_BYTES}-char limit.\n`,
    );
    // Compute marker length first so the total output is exactly
    // MAX_DESCRIPTION_BYTES and never exceeds the cap. The previous code
    // sliced to MAX_DESCRIPTION_BYTES then APPENDED the marker, producing
    // output ~30 bytes over the limit.
    const marker = ` … [truncated: ${overflow} chars]`;
    return clean.slice(0, MAX_DESCRIPTION_BYTES - marker.length) + marker;
  }
  return clean;
}

/**
 * Sanitize a tool description that originates from an external MCP connection
 * or upstream spec before it is included in this server's LLM tool list.
 *
 * Single identifiable function ensures all data paths that surface tool
 * descriptions to the LLM apply consistent sanitization policy.
 *
 * @param {string} raw   Raw description string from the upstream source
 * @param {object} [opts]
 * @param {string} [opts.label] Provenance label forwarded to sanitizeDescription
 * @returns {string}
 */
export function sanitizeMcpToolDescription(raw, opts = {}) {
  return sanitizeDescription(typeof raw === 'string' ? raw : '', opts);
}

/**
 * Normalize a tool name with NFKC (compatibility decomposition + canonical
 * composition) and strip any character outside [a-zA-Z0-9_-]. This defeats
 * homoglyph and zero-width-space shadowing attacks where two tools render
 * identically to a human/LLM but have distinct underlying string identity.
 *
 * Returns null when the result would be empty so the caller can drop the
 * malformed entry rather than register a tool with no usable name.
 *
 * @param {string} name
 * @returns {string|null}
 */
export function sanitizeToolName(name) {
  if (typeof name !== 'string' || name.length === 0) return null;
  // NFKC folds compatibility forms (full-width digits, ligatures, etc.) and
  // composes combining marks so visually-identical inputs produce identical
  // strings.
  const normalized = name.normalize('NFKC');
  // Strip anything outside the MCP-safe character set. Zero-width characters
  // (U+200B-U+200D, U+FEFF) and other invisibles are removed by this filter.
  const cleaned = normalized.replace(/[^a-zA-Z0-9_-]/g, '');
  return cleaned.length > 0 ? cleaned : null;
}
