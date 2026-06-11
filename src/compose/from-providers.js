/**
 * Provider → bridge composition.
 *
 * `createRestBridge` is synchronous and takes a resolved `tools` array;
 * Providers resolve their components asynchronously. This module is the
 * additive wiring between the two (SPEC §2 "Architectural interfaces"):
 * gather `{ tools }` from a provider list, build the bridge, and tie
 * provider `close()` into the bridge lifecycle so callers don't have to
 * track which provider kinds hold network handles.
 *
 * Legacy loader flows (`loadOpenApiSpec` → `createRestBridge({ tools })`)
 * are unchanged and remain the stable surface.
 *
 * @module compose/from-providers
 */

import { createRestBridge } from '../bridge.js';
import { componentsFromProviders } from '../providers/index.js';

/**
 * Build a REST bridge from one or more Providers.
 *
 * Usage:
 *
 *   import { createBridgeFromProviders, providers } from '40mcp';
 *
 *   const bridge = await createBridgeFromProviders({
 *     name: 'petstore',
 *     baseUrl: 'https://petstore.example.com',
 *     providers: [providers.openapi('./petstore.json')],
 *   });
 *   await bridge.start();
 *
 * Provider tools are gathered first (collision rules per SPEC §2 — see
 * `componentsFromProviders`), then any literal `config.tools` are appended;
 * a name collision between the two sets fails bridge construction the same
 * way duplicate provider tools do. `bridge.close()` additionally awaits
 * every provider's `close()` (when present), in list order, after the
 * bridge itself has drained.
 *
 * @param {object} config - `createRestBridge` config plus `providers`.
 * @param {Array<{ name: string, components: Function, close?: Function }>} config.providers
 * @returns {Promise<object>} A bridge with the same surface as `createRestBridge`.
 */
export async function createBridgeFromProviders(config) {
  if (config == null || typeof config !== 'object') {
    throw new TypeError('createBridgeFromProviders(config) requires an object config.');
  }
  const { providers: providerList, tools: literalTools = [], ...bridgeConfig } = config;

  const { tools: providerTools } = await componentsFromProviders(providerList);

  // Literal config.tools compose with provider tools under the same
  // fail-loud collision rule.
  const seen = new Set(providerTools.map((t) => t.name));
  for (const tool of literalTools) {
    if (seen.has(tool.name)) {
      throw new Error(
        `[${bridgeConfig.name || 'rest-bridge'}] Duplicate tool name "${tool.name}": ` +
        'declared in config.tools and also emitted by a provider.',
      );
    }
    seen.add(tool.name);
  }

  const bridge = createRestBridge({
    ...bridgeConfig,
    tools: [...providerTools, ...literalTools],
  });

  const bridgeClose = bridge.close;
  return {
    ...bridge,
    async close() {
      await bridgeClose.call(bridge);
      for (const provider of providerList) {
        if (typeof provider.close === 'function') {
          await provider.close();
        }
      }
    },
  };
}
