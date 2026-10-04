import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { configDefaults } from "vitest/config";

const atcuteMultibaseShim = new URL("./test/shims/atcute-multibase.ts", import.meta.url)
  .pathname;
const atcuteTimeMsShim = new URL("./test/shims/atcute-time-ms.ts", import.meta.url)
  .pathname;
const atcuteUtilTextShim = new URL(
  "./test/shims/atcute-util-text.ts",
  import.meta.url,
).pathname;
const nodeProcessShim = new URL("./test/shims/node-process.ts", import.meta.url)
  .pathname;

type RookeryWorkersConfigOptions = {
  include?: string[];
  exclude?: string[];
  bindings?: Record<string, string>;
};

export function defineRookeryWorkersConfig(options: RookeryWorkersConfigOptions = {}) {
  return defineWorkersConfig({
    resolve: {
      conditions: ["worker", "browser", "require"],
      alias: {
        "@atcute/multibase": atcuteMultibaseShim,
        "@atcute/time-ms": atcuteTimeMsShim,
        "@atcute/util-text": atcuteUtilTextShim,
        "node:process": nodeProcessShim,
        pino: "pino/browser.js",
      },
    },
    test: {
      ...(options.include ? { include: options.include } : {}),
      ...(options.exclude ? { exclude: options.exclude } : {}),
      globals: true,
      maxWorkers: 1,
      isolate: false,
      deps: {
        optimizer: {
          ssr: {
            include: [
              "@atcute/cbor",
              "@atcute/cid",
              "@atcute/multibase",
              "@atcute/tid",
              "@atcute/time-ms",
              "@atcute/util-text",
              "@atproto/common",
              "@atproto/repo",
              "@atproto/crypto",
              "@atproto/lex-cbor",
              "multiformats",
            ],
          },
        },
      },
      poolOptions: {
        workers: {
          main: "./test/fixtures/worker/index.ts",
          singleWorker: true,
          wrangler: { configPath: "./test/fixtures/worker/wrangler.jsonc" },
          miniflare: {
            bindings: {
              ROOKERY_HOSTNAME: "rookery.test",
              ROOKERY_HANDLE_DOMAIN: ".rookery.test",
              ROOKERY_PLC_URL: "https://plc.directory",
              OAUTH_NONCE_SECRET: "test-oauth-nonce-secret",
              ...options.bindings,
            },
          },
        },
      },
    },
  });
}

export default defineRookeryWorkersConfig({
  exclude: [...configDefaults.exclude, "test/commons.test.ts", "test/commons-noaccess.test.ts"],
});
