// Run the rookery Cloudflare Worker via Miniflare on Fly.io
// Emulates D1 (SQLite), R2 (filesystem), and Durable Objects
import { Miniflare } from 'miniflare';

const mf = new Miniflare({
  scriptPath: './dist/worker.js',
  modules: true,
  compatibilityDate: '2025-01-01',
  compatibilityFlags: ['nodejs_compat'],

  // D1 database (SQLite file)
  d1Databases: ['DIRECTORY'],
  d1Persist: '/data/d1',

  // R2 bucket (filesystem)
  r2Buckets: ['BLOBS'],
  r2Persist: '/data/r2',

  // Durable Objects (with SQLite storage enabled)
  durableObjects: {
    ACCOUNT: {
      className: 'AccountDurableObject',
      enableSql: true,
    },
    SEQUENCER: {
      className: 'SequencerDurableObject',
      enableSql: true,
    },
  },
  durableObjectsPersist: '/data/do',

  // Environment variables (set via Fly.io secrets)
  bindings: {
    ROOKERY_HOSTNAME: process.env.ROOKERY_HOSTNAME || 'rookery-pds.fly.dev',
    ROOKERY_HANDLE_DOMAIN: process.env.ROOKERY_HANDLE_DOMAIN || '.fly.dev',
    ROOKERY_PLC_URL: 'https://plc.directory',
    ROOKERY_RELAY_HOSTS: 'bsky.network',
  },

  // KV for OAuth (if needed)
  kvNamespaces: ['OAUTH'],
  kvPersist: '/data/kv',

  port: 8787,
  host: '0.0.0.0',
});

await mf.ready;
console.log('Rookery PDS running on http://0.0.0.0:8787');

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await mf.dispose();
  process.exit(0);
});
