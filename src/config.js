import { readFile, open, writeFile, unlink, stat } from 'node:fs/promises';
import { delimiter, dirname, isAbsolute, relative, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir, tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';

/** Installed-package root — resolved once at module load. Used by
 *  `loadConfig` as a fallback search path so `npx 40mcp serve configs/foo.json`
 *  works from any CWD, not just a repo checkout. */
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Allowed config file extensions. JS files execute with full process privileges —
 * only load config files from trusted sources (A08-1: trust boundary).
 */
const ALLOWED_EXTENSIONS = /\.(json|js|mjs|cjs)$/;
const JS_EXTENSIONS = /\.(js|mjs|cjs)$/;

/** Hard ceiling for JSON/JS config file size. */
const MAX_CONFIG_FILE_BYTES = 16 * 1024 * 1024;

/**
 * Best-effort heuristic: true when the loaded config object *looks like*
 * it embeds a literal credential in one of the fields the bridge
 * historically accepts one. Drives the world-readable mode warning in
 * `loadConfig` so shipped community configs (which only hold `${ENV}`
 * references) don't trip a false positive on every invocation.
 *
 * THIS IS NOT A GENERAL SECRET SCANNER. It checks a targeted allowlist
 * of credential-bearing fields:
 *
 *   - selected `auth.*` fields: `value`, `token`, `password`,
 *     `passphrase`, `clientSecret`
 *   - selected `vault.*` fields: `passphrase`, `recoveryKey`,
 *     `daemonSecret`
 *   - literal sensitive headers on tools: `Authorization`, `X-API-Key`,
 *     `X-Auth-Token`
 *
 * A string qualifies as "literal" when it is non-empty and contains no
 * `${VAR}` / `$VAR` env reference. Empty strings are ignored — configs
 * often ship with `"auth.value": ""` and expect the env var to populate.
 *
 * What this *does not* do:
 *   - scan arbitrary string leaves for high-entropy blobs
 *   - understand nested `auth.credentials.apiKey` or custom schemas
 *   - detect secrets in comment strings, unused keys, or chain steps
 *
 * A `false` return means "no warning-worthy literal found in the
 * fields 40mcp's own bridge reads credentials from" — it is not a
 * clean bill of health for the file. Treat the warning's absence as
 * the absence of a warning, not as proof the file carries no secret.
 */
function configHasLikelyLiteralSecret(cfg) {
  if (!cfg || typeof cfg !== 'object') return false;
  const hasEnvRef = (v) =>
    typeof v === 'string' && v.length > 0 && /\$\{?[A-Z_][A-Z0-9_]*\}?/.test(v);
  const isSet = (v) => typeof v === 'string' && v.length > 0;

  // Top-level auth block — `value`, `token`, `password`, `passphrase` are
  // the fields that historically carried a secret literal.
  const auth = cfg.auth;
  if (auth && typeof auth === 'object') {
    for (const key of ['value', 'token', 'password', 'passphrase', 'clientSecret']) {
      if (isSet(auth[key]) && !hasEnvRef(auth[key])) return true;
    }
  }

  // Vault block — a literal passphrase here is the exact case the original
  // warning was written for.
  const vault = cfg.vault;
  if (vault && typeof vault === 'object') {
    for (const key of ['passphrase', 'recoveryKey', 'daemonSecret']) {
      if (isSet(vault[key]) && !hasEnvRef(vault[key])) return true;
    }
  }

  // Tool-level header literals — sensitive headers with no env ref.
  if (Array.isArray(cfg.tools)) {
    for (const tool of cfg.tools) {
      const headers = tool && tool.headers;
      if (!headers || typeof headers !== 'object') continue;
      for (const [hdr, val] of Object.entries(headers)) {
        if (!/^authorization$|^x-api-key$|^x-auth-token$/i.test(hdr)) continue;
        if (isSet(val) && !hasEnvRef(val)) return true;
      }
    }
  }

  return false;
}

/**
 * Load a bridge config from a JSON or JS file.
 *
 * JSON files are parsed directly. JS files are dynamically imported
 * and expected to export a default config object.
 *
 * SECURITY: JS config files execute arbitrary code with the full privileges
 * of the Node.js process. The executable-config
 * surface is a high-impact supply chain vector. The loader now applies three
 * defenses for JS configs (JSON files are unaffected):
 *
 *   1. Path allowlist — by default JS configs must live under CWD or
 *      ~/.40mcp/. Operators can extend the allowlist via FOURDMCP_CONFIG_DIRS
 *      (path-delimited absolute paths) for advanced deployments.
 *   2. Mode check — refuse JS configs that are world- or group-writable. A
 *      rogue user on a shared host could otherwise drop a backdoored config.
 *   3. Hard kill switch — set FOURDMCP_NO_JS_CONFIG=1 (or pass
 *      `{ jsConfig: false }`) to disable JS configs entirely. Recommended
 *      default for production / daemon deployments.
 *
 * @param {string} filePath - Path to config file (.json, .js, .mjs, .cjs)
 * @param {object} [options]
 * @param {boolean} [options.jsConfig=true] - Allow JS configs (overrides env)
 * @param {string[]} [options.allowedDirs] - Additional absolute dirs to allow
 * @returns {Promise<object>} Bridge config
 */
export async function loadConfig(filePath, options = {}) {
  let abs = resolve(filePath);

  // A05-3: Extension allowlist to prevent loading unexpected file types
  if (!ALLOWED_EXTENSIONS.test(abs)) {
    throw new Error(`Unsupported config file type: "${filePath}". Use .json, .js, .mjs, or .cjs`);
  }

  // Package-relative fallback: if the path doesn't exist in CWD, try the
  // installed package root so `npx 40mcp serve configs/github.json` works
  // from any directory, not just a repo checkout. CWD is always preferred —
  // the fallback only fires on ENOENT.
  //
  // Scoped to the shipped `configs/` subdirectory so the fallback can't
  // be used to load arbitrary package source files (e.g. `src/version.js`)
  // as a config. A caller's `..` segments are resolved here — we check the
  // POST-resolve path, not the raw input, to prevent `configs/../src/foo.js`
  // style traversal.
  try {
    await stat(abs);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    const packagePath = resolve(PACKAGE_ROOT, filePath);
    const configsRoot = resolve(PACKAGE_ROOT, 'configs');
    const rel = relative(configsRoot, packagePath);
    const inConfigs = rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
    if (!inConfigs) {
      // Path resolves outside the shipped configs/ directory. Fall through
      // to the original ENOENT rather than a package-scoped lookup.
      const notFound = new Error(`ENOENT: no such file or directory, "${filePath}"`);
      notFound.code = 'ENOENT';
      throw notFound;
    }
    try {
      await stat(packagePath);
      abs = packagePath;
    } catch (err2) {
      if (err2.code !== 'ENOENT') throw err2;
      // Preserve the `ENOENT` code on the surfaced error so callers who
      // `catch (err) { if (err.code === 'ENOENT') ... }` keep working.
      const notFound = new Error(
        `Config not found: "${filePath}"\n  Tried: ${resolve(filePath)}\n  Tried: ${packagePath}`,
      );
      notFound.code = 'ENOENT';
      throw notFound;
    }
  }

  if (abs.endsWith('.json')) {
    // Size cap first — pointing `--config /dev/zero` would OOM JSON.parse.
    const st = await stat(abs);
    if (st.size > MAX_CONFIG_FILE_BYTES) {
      throw new Error(
        `Config file too large: ${st.size} bytes > ${MAX_CONFIG_FILE_BYTES} limit.`,
      );
    }
    const raw = await readFile(abs, 'utf-8');
    const parsed = JSON.parse(raw);
    // Group/world-readable warning: fire only when our targeted
    // credential-field heuristic turns up a literal. Shipped community
    // configs under `configs/` use `${ENV_VAR}` references everywhere,
    // so a 0644 on one of those is not worth yelling about on every
    // `doctor` / `serve` run (the original false-positive complaint).
    // The heuristic checks a small allowlist of credential-bearing
    // fields — it is not a general secret scanner, so absence of the
    // warning does not prove the file is clean. See
    // `configHasLikelyLiteralSecret` JSDoc for the exact scope.
    if ((st.mode & 0o077) !== 0 && configHasLikelyLiteralSecret(parsed)) {
      process.stderr.write(
        `[config] WARNING: config file "${abs}" is group- or world-readable ` +
        `(mode: ${(st.mode & 0o777).toString(8)}) and appears to contain a literal credential ` +
        `in a known auth / vault / header field. Run: chmod 600 "${abs}"\n`,
      );
    }
    return parsed;
  }

  // JS/MJS/CJS — apply defenses before executing untrusted code.
  if (JS_EXTENSIONS.test(abs)) {
    const jsAllowed = options.jsConfig !== false && process.env.FOURDMCP_NO_JS_CONFIG !== '1';
    if (!jsAllowed) {
      throw new Error(
        `JS config loading is disabled. Convert "${filePath}" to JSON, or unset FOURDMCP_NO_JS_CONFIG.`,
      );
    }

    // Path allowlist: CWD + ~/.40mcp + caller-supplied dirs + env-supplied
    // dirs. The installed-package root is deliberately NOT in this list —
    // the package-relative fallback above is scoped to `configs/*.json`
    // and 40mcp ships no JS configs, so JS execution stays limited to
    // user-controlled directories.
    const allowedDirs = [
      process.cwd(),
      `${homedir()}/.40mcp`,
      ...(Array.isArray(options.allowedDirs) ? options.allowedDirs : []),
      ...(process.env.FOURDMCP_CONFIG_DIRS
        ? process.env.FOURDMCP_CONFIG_DIRS.split(delimiter).filter(Boolean)
        : []),
    ].map((d) => resolve(d));
    const inAllowed = allowedDirs.some((dir) => {
      const rel = relative(dir, abs);
      return rel === '' || (rel && !rel.startsWith('..') && !isAbsolute(rel));
    });
    if (!inAllowed) {
      throw new Error(
        `JS config "${filePath}" is outside the allowed directories. ` +
        `Move it under CWD or ~/.40mcp, or extend the allowlist via FOURDMCP_CONFIG_DIRS.`,
      );
    }

    // Close the TOCTOU window between the mode check and the module import.
    // Previously we called `stat(abs)` then `import(pathToFileURL(abs))`, which
    // is two path-based operations with an await gap between them. An attacker
    // with write access to the parent directory could swap the file via rename()
    // during the gap so the mode check saw a safe file but the import loaded a
    // backdoor. Now we open the file once, fstat() on the held fd for the mode
    // check, read the content via the same fd, and evaluate it via a data: URL
    // so the dynamic import loader never re-reads from the path. The file
    // descriptor pins the inode — a rename/swap after open() affects only
    // the path, not our fd.
    let fh;
    try {
      fh = await open(abs, 'r');
    } catch (err) {
      throw new Error(`Cannot open config file "${filePath}": ${err.message}`);
    }
    try {
      const st = await fh.stat();
      if (process.platform !== 'win32' && (st.mode & 0o022) !== 0) {
        throw new Error(
          `JS config "${filePath}" is group- or world-writable (mode ${(st.mode & 0o777).toString(8)}). ` +
          `Run: chmod 600 "${filePath}"`,
        );
      }
      const MAX_CONFIG_BYTES = 2 * 1024 * 1024; // 2 MB — no legitimate config is larger
      if (st.size > MAX_CONFIG_BYTES) {
        throw new Error(
          `JS config "${filePath}" exceeds ${MAX_CONFIG_BYTES} bytes (${st.size}). ` +
          `Refuse to load oversized configs.`,
        );
      }
      const content = await fh.readFile('utf-8');

      // Evaluate without re-reading from the original path. For ESM (.js,
      // .mjs) we use a data: URL so the ESM loader has no filesystem round
      // trip. CJS (.cjs) does not support data: URL import, so we stage the
      // already-read content in a process-private temp file we control.
      // Either way, the attacker's post-open rename of the original path
      // has no effect on what we execute. Relative imports inside the
      // config will NOT resolve under the data:/temp approach — that's an
      // intentional tradeoff; configs with relative imports should be
      // flattened or rewritten to JSON.
      if (abs.endsWith('.cjs')) {
        const tmpName = join(tmpdir(), `40mcp-cfg-${randomBytes(16).toString('hex')}.cjs`);
        await writeFile(tmpName, content, { mode: 0o600 });
        try {
          const mod = await import(pathToFileURL(tmpName).href);
          process.stderr.write(`[40mcp] WARNING: loaded executable JS config "${abs}" — treat this file as trusted code\n`);
          return mod.default || mod;
        } finally {
          unlink(tmpName).catch(() => {});
        }
      }
      const dataUrl = `data:text/javascript;base64,${Buffer.from(content).toString('base64')}`;
      const mod = await import(dataUrl);
      process.stderr.write(`[40mcp] WARNING: loaded executable JS config "${abs}" — treat this file as trusted code\n`);
      return mod.default || mod;
    } finally {
      await fh.close().catch(() => {});
    }
  }

  // Fallback (shouldn't reach here due to extension allowlist): plain import.
  const mod = await import(pathToFileURL(abs).href);
  return mod.default || mod;
}
