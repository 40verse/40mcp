/**
 * Example: Mix two APIs into one MCP server with prefix namespacing.
 *
 * Demonstrates combining Petstore and JSONPlaceholder into a single server.
 * Tools are prefixed: 'pets.list_pets', 'todos.list_todos'
 *
 * Run:   node examples/mixer.js
 */

import { createMixer } from '../src/index.js';

const mixer = createMixer({
  name: 'mixed-api',
  version: '1.0.0',
  servers: [
    {
      prefix: 'pets',
      name: 'petstore',
      baseUrl: 'https://petstore3.swagger.io/api/v3',
      tools: [
        {
          name: 'list_pets',
          description: 'List pets by status.',
          method: 'GET',
          path: '/pet/findByStatus',
          queryMap: { pet_status: 'status' },
          inputSchema: {
            type: 'object',
            properties: {
              pet_status: {
                type: 'string',
                enum: ['available', 'pending', 'sold'],
              },
            },
            required: ['pet_status'],
          },
        },
        {
          name: 'get_pet',
          description: 'Get a pet by ID.',
          method: 'GET',
          path: '/pet/:pet_id',
          inputSchema: {
            type: 'object',
            properties: {
              pet_id: { type: 'integer' },
            },
            required: ['pet_id'],
          },
        },
      ],
    },
    {
      prefix: 'todos',
      name: 'jsonplaceholder',
      baseUrl: 'https://jsonplaceholder.typicode.com',
      tools: [
        {
          name: 'list_todos',
          description: 'List all todos.',
          method: 'GET',
          path: '/todos',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_todo',
          description: 'Get a todo by ID.',
          method: 'GET',
          path: '/todos/:todo_id',
          inputSchema: {
            type: 'object',
            properties: {
              todo_id: { type: 'integer' },
            },
            required: ['todo_id'],
          },
        },
      ],
    },
  ],
});

await mixer.start();
