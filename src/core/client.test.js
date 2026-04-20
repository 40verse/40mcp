import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { createApiClient } from './client.js';

// ─────────────────────────────────────────────────────────────────────────────
// Mock fetch
// ─────────────────────────────────────────────────────────────────────────────

let originalFetch;

beforeEach(() => {
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// ─────────────────────────────────────────────────────────────────────────────
// createApiClient() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('createApiClient', () => {
  it('returns a function', () => {
    const client = createApiClient('https://api.example.com');
    assert.equal(typeof client, 'function');
  });

  it('throws on invalid scheme (not http/https)', () => {
    assert.throws(
      () => {
        createApiClient('ftp://api.example.com');
      },
      (err) => {
        return err.message.includes('Invalid baseUrl scheme');
      }
    );
  });

  it('throws on invalid custom header name', () => {
    assert.throws(
      () => {
        createApiClient('https://api.example.com', {
          type: 'header',
          header: 'Invalid-Header@Name',
          envVar: 'AUTH',
        });
      },
      (err) => {
        return err.message.includes('Invalid auth header name');
      }
    );
  });

  it('warns when static credential without envVar', () => {
    const stderrWrite = process.stderr.write;
    const warnings = [];

    process.stderr.write = (msg) => {
      warnings.push(msg);
    };

    try {
      createApiClient('https://api.example.com', {
        type: 'bearer',
        value: 'secret_token',
      });

      assert(warnings.some((w) => w.includes('auth.value is set without auth.envVar')));
    } finally {
      process.stderr.write = stderrWrite;
    }
  });

  it('warns when credentials sent over HTTP (non-localhost)', () => {
    const stderrWrite = process.stderr.write;
    const warnings = [];

    process.stderr.write = (msg) => {
      warnings.push(msg);
    };

    try {
      createApiClient('http://api.example.com', {
        type: 'bearer',
        value: 'token',
      });

      assert(warnings.some((w) => w.includes('Credentials will be sent over plaintext HTTP')));
    } finally {
      process.stderr.write = stderrWrite;
    }
  });

  it('does not warn for HTTP on localhost', () => {
    const stderrWrite = process.stderr.write;
    const warnings = [];

    process.stderr.write = (msg) => {
      warnings.push(msg);
    };

    try {
      createApiClient('http://localhost:3000', {
        type: 'bearer',
        value: 'token',
      });

      assert(!warnings.some((w) => w.includes('Credentials will be sent over plaintext HTTP')));
    } finally {
      process.stderr.write = stderrWrite;
    }
  });

  // Cloud-metadata hosts must be refused at client-construction time
  // regardless of `allowPrivate`. A scheme-only check would accept
  // `baseUrl: "http://169.254.169.254"` and send every outbound call to
  // AWS IMDS — trivial credential exfil under an adversarial config.
  it('rejects cloud metadata host (AWS IMDS) in baseUrl even with allowPrivate', () => {
    assert.throws(
      () => createApiClient('http://169.254.169.254/latest/meta-data', null, { allowPrivate: true }),
      (err) => /metadata|link-local|169\.254/i.test(err.message),
    );
  });

  it('rejects cloud metadata host (AWS ECS) in baseUrl', () => {
    assert.throws(
      () => createApiClient('http://169.254.170.2/', null, { allowPrivate: true }),
      (err) => /metadata|link-local|169\.254/i.test(err.message),
    );
  });

  it('rejects loopback baseUrl when allowPrivate:false (strict production mode)', () => {
    assert.throws(
      () => createApiClient('http://127.0.0.1:8080', null, { allowPrivate: false }),
      (err) => /loopback|private|allowPrivate/i.test(err.message),
    );
  });

  it('permits loopback baseUrl by default (legacy dev ergonomics)', () => {
    // Default `allowPrivate` is truthy to match createRestBridge's default;
    // loopback baseUrl must not throw. Metadata hosts are still blocked
    // unconditionally (see the two tests above).
    assert.doesNotThrow(() => createApiClient('http://127.0.0.1:8080'));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// API client function tests (GET, POST, headers)
// ─────────────────────────────────────────────────────────────────────────────

describe('API client (created by createApiClient)', () => {
  it('makes GET request with correct URL and headers', async () => {
    let capturedInit = null;
    let capturedUrl = null;

    globalThis.fetch = async (url, init) => {
      capturedUrl = url;
      capturedInit = init;
      return {
        ok: true,
        status: 200,
        text: async () => '{"id":1,"name":"test"}',
      };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('GET', '/users/1');

    assert.equal(capturedUrl, 'https://api.example.com/users/1');
    assert.equal(capturedInit.method, 'GET');
    assert.equal(capturedInit.headers['Content-Type'], 'application/json');
    assert.deepEqual(result, { id: 1, name: 'test' });
  });

  it('makes POST request with JSON body', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return {
        ok: true,
        status: 200,
        text: async () => '{"id":1,"created":true}',
      };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('POST', '/users', { name: 'alice', email: 'alice@example.com' });

    assert.equal(capturedInit.method, 'POST');
    assert.equal(capturedInit.body, JSON.stringify({ name: 'alice', email: 'alice@example.com' }));
    assert.deepEqual(result, { id: 1, created: true });
  });

  it('injects custom header from env var', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    process.env.CUSTOM_AUTH = 'my-custom-value';

    try {
      const client = createApiClient('https://api.example.com', {
        type: 'header',
        header: 'X-Custom-Auth',
        envVar: 'CUSTOM_AUTH',
      });

      await client('GET', '/users');

      assert.equal(capturedInit.headers['X-Custom-Auth'], 'my-custom-value');
    } finally {
      delete process.env.CUSTOM_AUTH;
    }
  });

  it('injects Bearer token from env var', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    process.env.AUTH_TOKEN = 'my-bearer-token';

    try {
      const client = createApiClient('https://api.example.com', {
        type: 'bearer',
        envVar: 'AUTH_TOKEN',
      });

      await client('GET', '/users');

      assert.equal(capturedInit.headers['Authorization'], 'Bearer my-bearer-token');
    } finally {
      delete process.env.AUTH_TOKEN;
    }
  });

  it('injects Basic auth header with base64 encoding', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    process.env.BASIC_CREDS = 'user:password';

    try {
      const client = createApiClient('https://api.example.com', {
        type: 'basic',
        envVar: 'BASIC_CREDS',
      });

      await client('GET', '/users');

      const expected = `Basic ${Buffer.from('user:password').toString('base64')}`;
      assert.equal(capturedInit.headers['Authorization'], expected);
    } finally {
      delete process.env.BASIC_CREDS;
    }
  });

  it('returns { success: true } for 204 No Content', async () => {
    globalThis.fetch = async () => {
      return { ok: true, status: 204 };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('DELETE', '/users/1');

    assert.deepEqual(result, { success: true });
  });

  it('throws McpError for non-2xx response', async () => {
    globalThis.fetch = async () => {
      return {
        ok: false,
        status: 404,
        text: async () => 'Not found',
      };
    };

    const client = createApiClient('https://api.example.com');

    await assert.rejects(
      async () => {
        await client('GET', '/users/999');
      },
      (err) => {
        return (
          err instanceof McpError &&
          err.code === ErrorCode.InternalError &&
          err.message.includes('/users/999')
        );
      }
    );
  });

  it('throws McpError for 401/403 with InvalidRequest code', async () => {
    globalThis.fetch = async () => {
      return {
        ok: false,
        status: 403,
        text: async () => 'Forbidden',
      };
    };

    const client = createApiClient('https://api.example.com');

    await assert.rejects(
      async () => {
        await client('GET', '/admin');
      },
      (err) => {
        return err instanceof McpError && err.code === ErrorCode.InvalidRequest;
      }
    );
  });

  it('throws McpError for network error', async () => {
    globalThis.fetch = async () => {
      throw new Error('Network timeout');
    };

    const client = createApiClient('https://api.example.com');

    await assert.rejects(
      async () => {
        await client('GET', '/users');
      },
      (err) => {
        return (
          err instanceof McpError &&
          err.code === ErrorCode.InternalError &&
          err.message.includes('Network error')
        );
      }
    );
  });

  it('catches AbortError and throws McpError with timeout message', async () => {
    globalThis.fetch = async () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    };

    const client = createApiClient('https://api.example.com', null, { timeoutMs: 5000 });

    await assert.rejects(
      async () => {
        await client('GET', '/users');
      },
      (err) => {
        return (
          err instanceof McpError &&
          err.code === ErrorCode.InternalError &&
          err.message.includes('Request timeout')
        );
      }
    );
  });

  it('removes trailing slash from baseUrl', async () => {
    let capturedUrl = null;

    globalThis.fetch = async (url) => {
      capturedUrl = url;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com/');
    await client('GET', '/users');

    assert.equal(capturedUrl, 'https://api.example.com/users');
  });

  it('returns parsed JSON response', async () => {
    globalThis.fetch = async () => {
      return {
        ok: true,
        status: 200,
        text: async () => '{"id":1,"name":"Alice"}',
      };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('GET', '/users/1');

    assert.deepEqual(result, { id: 1, name: 'Alice' });
  });

  it('returns { success: true } for empty non-JSON body', async () => {
    globalThis.fetch = async () => {
      return { ok: true, status: 200, text: async () => '' };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('DELETE', '/users/1');

    assert.deepEqual(result, { success: true });
  });

  it('returns { success: true, body } for non-JSON text body', async () => {
    globalThis.fetch = async () => {
      return { ok: true, status: 200, text: async () => 'OK' };
    };

    const client = createApiClient('https://api.example.com');
    const result = await client('GET', '/health');

    assert.deepEqual(result, { success: true, body: 'OK' });
  });

  it('calls beforeRequest hook and merges headers', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async (_req) => {
        return {
          headers: { 'X-Custom': 'from-hook' },
        };
      },
    });

    await client('GET', '/users');

    assert.equal(capturedInit.headers['X-Custom'], 'from-hook');
    assert.equal(capturedInit.headers['Content-Type'], 'application/json');
  });

  // ─── OAuth2 backoff test ──────────────────────────────────────────────

  it('enters backoff after OAuth2 token refresh failure and blocks retry', async () => {
    let tokenFetchCount = 0;
    globalThis.fetch = async (url) => {
      if (url.includes('token')) {
        tokenFetchCount++;
        return { ok: false, status: 401, json: async () => ({}) };
      }
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com', {
      type: 'oauth2',
      tokenUrl: 'https://auth.example.com/token',
      clientId: 'client',
      clientSecret: 'secret',
      retryDelayMs: 60_000, // long window so the second call definitely hits backoff
    });

    // First request — token refresh fails
    await assert.rejects(
      () => client('GET', '/data'),
      (err) => err.message.includes('OAuth2 token refresh failed'),
    );
    assert.equal(tokenFetchCount, 1, 'Token endpoint should be called once');

    // Second request — must get backoff error without retrying the token endpoint
    await assert.rejects(
      () => client('GET', '/data'),
      (err) => err.message.includes('backoff'),
    );
    assert.equal(tokenFetchCount, 1, 'Token endpoint must NOT be retried during backoff window');
  });

  // ─── CRLF injection guard for beforeRequest hook values ────────────────

  it('accepts normal printable header values from beforeRequest hook', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async () => ({
        headers: { 'X-Trace-Id': 'abc-123_normal value' },
      }),
    });

    await client('GET', '/users');
    assert.equal(capturedInit.headers['X-Trace-Id'], 'abc-123_normal value');
  });

  it('rejects CRLF injection in beforeRequest hook header value', async () => {
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => '{}' });

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async () => ({
        headers: { 'X-Foo': 'a\r\nX-Inj: 1' },
      }),
    });

    await assert.rejects(
      () => client('GET', '/users'),
      (err) =>
        err.message.includes('invalid header value for "X-Foo"') &&
        err.message.includes('control characters are not permitted'),
    );
  });

  it('rejects bare \\n in beforeRequest hook header value', async () => {
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => '{}' });

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async () => ({
        headers: { 'X-Foo': 'value\nmore' },
      }),
    });

    await assert.rejects(
      () => client('GET', '/users'),
      (err) => err.message.includes('invalid header value'),
    );
  });

  it('rejects NUL byte in beforeRequest hook header value', async () => {
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => '{}' });

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async () => ({
        headers: { 'X-Foo': 'val\x00ue' },
      }),
    });

    await assert.rejects(
      () => client('GET', '/users'),
      (err) => err.message.includes('invalid header value'),
    );
  });

  it('allows extended-ASCII / UTF-8 in beforeRequest hook header value', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async () => ({
        // UTF-8 (e.g. u-umlaut + currency sign) should pass — we only block
        // control chars, not extended bytes.
        headers: { 'X-Label': 'cafe\u00e9 \u20ac' },
      }),
    });

    await client('GET', '/users');
    assert.equal(capturedInit.headers['X-Label'], 'cafe\u00e9 \u20ac');
  });

  it('beforeRequest hook can modify body', async () => {
    let capturedInit = null;

    globalThis.fetch = async (url, init) => {
      capturedInit = init;
      return { ok: true, status: 200, text: async () => '{}' };
    };

    const client = createApiClient('https://api.example.com', null, {
      beforeRequest: async (_req) => {
        return {
          body: { modified: true },
        };
      },
    });

    await client('POST', '/users', { original: true });

    assert.equal(capturedInit.body, JSON.stringify({ modified: true }));
  });
});
