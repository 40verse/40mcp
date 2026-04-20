import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { exceedsJsonParseByteLimit, MAX_JSON_PARSE_BYTES } from './connect-size.js';

describe('exceedsJsonParseByteLimit', () => {
  it('treats multibyte UTF-8 text as oversized when its byte length exceeds 10 MB', () => {
    const multibyte = '\u20AC';
    const oversized = multibyte.repeat(Math.floor(MAX_JSON_PARSE_BYTES / Buffer.byteLength(multibyte, 'utf8')) + 1);
    assert.equal(exceedsJsonParseByteLimit(oversized), true);
  });

  it('allows text at or under the byte limit', () => {
    const withinLimit = 'a'.repeat(MAX_JSON_PARSE_BYTES);
    assert.equal(exceedsJsonParseByteLimit(withinLimit), false);
  });
});
