const MAX_JSON_PARSE_BYTES = 10 * 1024 * 1024; // 10 MB

export function exceedsJsonParseByteLimit(text) {
  return typeof text === 'string' && Buffer.byteLength(text, 'utf8') > MAX_JSON_PARSE_BYTES;
}

export { MAX_JSON_PARSE_BYTES };
