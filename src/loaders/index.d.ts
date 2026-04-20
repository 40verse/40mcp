/**
 * 40mcp/loaders — TypeScript declarations for the `./loaders` subpath export.
 *
 * Public entry point: `import { ... } from '40mcp/loaders'`.
 * Canonical declarations live in `../index.d.ts`; re-exported here to keep
 * a single source of truth.
 */

export {
  LoaderResult,
  OpenApiLoaderOptions,
  loadOpenApiSpec,
  GraphqlLoaderOptions,
  loadGraphqlSchema,
  HarLoaderOptions,
  HarToolDef,
  HarLoaderResult,
  loadHarFile,
  LoaderPlugin,
  registerLoader,
  loadFromAny,
  listLoaders,
} from '../index.js';
