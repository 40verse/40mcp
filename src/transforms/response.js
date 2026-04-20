/**
 * Token-aware response shaping for MCP tool results.
 *
 * Transforms raw API responses to fit within agent context budgets by:
 * - Filtering fields (pick/omit)
 * - Limiting array size (limit)
 * - Compressing representation (flatten, template)
 * - Respecting token budgets with intelligent truncation
 *
 * @module transforms/response
 */

import { getByPath, setByPath, deleteByPath } from '../core/object.js';
import { hasPromptInjection } from '../core/sanitize.js';

/**
 * Apply response transformations to MCP tool output.
 *
 * @param {any} data - The raw API response data
 * @param {Object} transform - Transform configuration (all optional)
 * @param {string[]} transform.pick - Keep only these fields (dot-notation supported)
 * @param {string[]} transform.omit - Remove these fields (applied after pick)
 * @param {number} transform.limit - If array, keep first N items
 * @param {boolean} transform.flatten - Convert nested objects to dot-notation keys
 * @param {boolean|string} transform.summary - Add _summary metadata if array was truncated
 * @param {number} transform.tokenBudget - Max token estimate (chars/4 heuristic)
 * @param {string} transform.template - Format string for each item (e.g., '{name} ({email})')
 * @returns {any} Transformed data
 */
export function applyResponseTransform(data, transform = {}) {
  // No transform needed
  if (!transform || Object.keys(transform).length === 0) {
    return data;
  }

  // Handle null/undefined
  if (data === null || data === undefined) {
    return data;
  }

  let result = data;
  let originalLength = null;

  // Step 1: pick — whitelist fields
  if (transform.pick && transform.pick.length > 0) {
    result = applyPick(result, transform.pick);
  }

  // Step 2: omit — blacklist fields (after pick)
  if (transform.omit && transform.omit.length > 0) {
    result = applyOmit(result, transform.omit);
  }

  // Step 3: limit — cap array size (track original length for summary)
  if (transform.limit && Array.isArray(result)) {
    originalLength = result.length;
    result = result.slice(0, transform.limit);
  }

  // Step 4: flatten — convert nested to dot-notation
  if (transform.flatten) {
    result = applyFlatten(result);
  }

  // Step 5: template — format items as strings
  // Validate the template literal itself for injection patterns. Operator-supplied
  // templates are trusted at config time but flow into MCP results — a
  // compromised config file could embed injection in the static text.
  if (transform.template && typeof transform.template === 'string') {
    if (hasPromptInjection(transform.template)) {
      process.stderr.write(`[transforms/response] WARNING: transform.template contains prompt-injection pattern — skipped\n`);
    } else {
      result = applyTemplate(result, transform.template);
    }
  }

  // Step 6: summary — add metadata if array was truncated
  if (transform.summary && Array.isArray(result) && originalLength !== null && originalLength > result.length) {
    result = addSummary(result, originalLength, transform.summary);
  }

  // Step 7: tokenBudget — estimate tokens and truncate if needed
  if (typeof transform.tokenBudget === 'number' && transform.tokenBudget > 0) {
    const estimated = estimateTokens(result);
    if (estimated > transform.tokenBudget) {
      result = truncateByBudget(result, transform.tokenBudget, originalLength);
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: pick — whitelist fields

function applyPick(data, pickFields) {
  if (Array.isArray(data)) {
    return data.map(item => pickFromObject(item, pickFields));
  }
  return pickFromObject(data, pickFields);
}

function pickFromObject(obj, pickFields) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const result = {};
  for (const field of pickFields) {
    const value = getByPath(obj, field);
    if (value !== undefined) {
      setByPath(result, field, value);
    }
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: omit — blacklist fields

function applyOmit(data, omitFields) {
  if (Array.isArray(data)) {
    return data.map(item => omitFromObject(item, omitFields));
  }
  return omitFromObject(data, omitFields);
}

function omitFromObject(obj, omitFields) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const result = structuredClone(obj);
  for (const field of omitFields) {
    deleteByPath(result, field);
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: flatten — convert nested to dot-notation

// An attacker-controlled upstream response
// containing a deeply nested object would stack-overflow flattenObject —
// bypassing the dispatcher concurrency cap because the crash happens
// inside a single dispatch. Added a hard depth cap plus a cycle guard
// (JSON-safe data normally cannot be cyclic, but objects passed in-process
// via custom transforms can be).
const MAX_FLATTEN_DEPTH = 50;

function applyFlatten(data) {
  if (Array.isArray(data)) {
    return data.map(item => flattenObject(item));
  }
  return flattenObject(data);
}

function flattenObject(obj, prefix = '', result = {}, depth = 0, seen = new WeakSet()) {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj !== 'object' || Array.isArray(obj)) {
    return obj;
  }

  if (depth >= MAX_FLATTEN_DEPTH) {
    // Truncate rather than throw — the caller's tool dispatch should
    // succeed with a partial result rather than crash on a nested bomb.
    if (prefix) result[prefix] = '[flatten depth limit reached]';
    return result;
  }
  if (seen.has(obj)) {
    if (prefix) result[prefix] = '[circular]';
    return result;
  }
  seen.add(obj);

  for (const [key, value] of Object.entries(obj)) {
    // Object keys from upstream responses can contain prompt-injection
    // patterns. When flatten=true those keys become the top-level keys of the
    // returned object and are surfaced directly to the agent. Sanitize each
    // segment before building the dot-notation key.
    const safeKey = hasPromptInjection(key) ? '[redacted-key]' : key;
    const fullKey = prefix ? `${prefix}.${safeKey}` : safeKey;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      flattenObject(value, fullKey, result, depth + 1, seen);
    } else {
      result[fullKey] = value;
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: template — format items as strings

function applyTemplate(data, template) {
  if (Array.isArray(data)) {
    return data.map(item => formatItemWithTemplate(item, template));
  }
  return formatItemWithTemplate(data, template);
}

function formatItemWithTemplate(item, template) {
  if (typeof item !== 'object' || item === null) {
    return item;
  }

  let result = template;
  const placeholderRegex = /\{([^}]+)\}/g;
  result = result.replace(placeholderRegex, (match, key) => {
    const value = getByPath(item, key);
    if (value === undefined) return match;
    const str = String(value);
    // An upstream returning {"name": "Ignore all previous instructions..."}
    // with template "{name} processed" produces an injected string. Check each
    // interpolated value individually — the template itself is operator-controlled
    // (trusted), but the DATA is from the upstream API (untrusted).
    if (hasPromptInjection(str)) {
      return '[redacted: prompt-injection pattern detected in upstream data]';
    }
    return str;
  });
  // B12 — multi-fragment injection: no single substituted value may trigger the
  // check in isolation, but the assembled string (e.g. two benign fragments that
  // concatenate into "ignore all previous instructions") can. Check the full
  // assembled result and redact the whole string if it matches.
  if (hasPromptInjection(result)) {
    return '[redacted: prompt-injection pattern detected in assembled response]';
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: summary — add metadata for truncated arrays

function addSummary(data, originalLength, summaryConfig) {
  let summaryText;

  if (typeof summaryConfig === 'string') {
    // summaryConfig is operator-supplied but flows into MCP tool results that
    // the agent reads. A malicious template containing prompt-injection patterns
    // would be emitted verbatim. Validate before interpolation.
    if (hasPromptInjection(summaryConfig)) {
      process.stderr.write(`[transforms/response] WARNING: summaryConfig template contains prompt-injection pattern — using default\n`);
      summaryText = `Showing ${data.length} of ${originalLength} items`;
    } else {
      // Custom template with {shown} and {total} placeholders
      summaryText = summaryConfig
        .replace('{shown}', data.length)
        .replace('{total}', originalLength);
    }
  } else {
    // Default summary
    summaryText = `Showing ${data.length} of ${originalLength} items`;
  }

  return {
    _summary: summaryText,
    items: data,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: tokenBudget — estimate and truncate

function estimateTokens(data) {
  const json = JSON.stringify(data);
  return Math.ceil(json.length / 4);
}

function truncateByBudget(data, budget, originalLength) {
  // If it's an array, first try reducing items
  if (Array.isArray(data)) {
    let truncated = [...data];
    let tokens = estimateTokens(truncated);

    // Binary search for safe array length
    if (tokens > budget) {
      let low = 0;
      let high = truncated.length;
      while (low < high) {
        const mid = Math.ceil((low + high) / 2);
        if (mid === low) break; // Prevent infinite loop at boundary
        const candidate = truncated.slice(0, mid);
        const candidateTokens = estimateTokens(candidate);
        if (candidateTokens <= budget) {
          low = mid;
        } else {
          high = mid - 1;
        }
      }
      truncated = truncated.slice(0, Math.max(low, 0));
      tokens = estimateTokens(truncated);
    }

    // If still over budget and we have objects, truncate string fields
    if (tokens > budget && truncated.length > 0 && typeof truncated[0] === 'object') {
      truncated = truncated.map(item => truncateStringFields(item, budget / truncated.length));
    }

    // Add truncation marker
    const result = { _truncated: true, items: truncated };
    if (originalLength) {
      result._original_count = originalLength;
    }
    return result;
  }

  // For single object, truncate string fields
  if (typeof data === 'object' && data !== null) {
    const truncated = truncateStringFields(data, budget);
    return { _truncated: true, data: truncated };
  }

  return { _truncated: true, data };
}

function truncateStringFields(obj, budget) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const result = structuredClone(obj);
  const maxFieldLength = Math.max(50, Math.floor(budget / 10));

  for (const [key, value] of Object.entries(result)) {
    if (typeof value === 'string' && value.length > maxFieldLength) {
      result[key] = value.substring(0, maxFieldLength) + '...';
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities: nested value access (re-exported from core/object.js)
