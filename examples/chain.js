/**
 * Example: Compound tool chain — combine 3 API calls into one.
 *
 * Demonstrates: get_user → get_posts → get_comments, merged into one result.
 * Shows how steps reference each other with $stepName.field syntax.
 *
 * Run:   node examples/chain.js
 */

import { createRestBridge } from '../src/index.js';

await createRestBridge({
  name: 'chain-example',
  version: '1.0.0',
  baseUrl: 'https://jsonplaceholder.typicode.com',

  tools: [
    {
      name: 'get_user_activity',
      description: 'Get user, their posts, and comments in one call.',
      chain: [
        {
          call: 'get_user',
          as: 'user',
          args: { user_id: '$args.user_id' },
        },
        {
          call: 'get_user_posts',
          as: 'posts',
          args: { user_id: '$args.user_id' },
        },
        {
          call: 'get_user_comments',
          as: 'comments',
          args: { user_id: '$args.user_id' },
        },
      ],
      inputSchema: {
        type: 'object',
        properties: {
          user_id: { type: 'integer', description: 'User ID' },
        },
        required: ['user_id'],
      },
    },
    {
      name: 'get_user',
      description: 'Fetch a user by ID.',
      method: 'GET',
      path: '/users/:user_id',
      inputSchema: {
        type: 'object',
        properties: {
          user_id: { type: 'integer', description: 'User ID' },
        },
        required: ['user_id'],
      },
    },
    {
      name: 'get_user_posts',
      description: 'Get all posts by a user.',
      method: 'GET',
      path: '/posts',
      queryMap: { user_id: 'userId' },
      inputSchema: {
        type: 'object',
        properties: {
          user_id: { type: 'integer', description: 'User ID' },
        },
        required: ['user_id'],
      },
    },
    {
      name: 'get_user_comments',
      description: 'Get all comments by a user.',
      method: 'GET',
      path: '/comments',
      queryMap: { user_id: 'name' },
      inputSchema: {
        type: 'object',
        properties: {
          user_id: { type: 'integer', description: 'User ID' },
        },
        required: ['user_id'],
      },
    },
  ],
}).start();
