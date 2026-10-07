import type { AccountDurableObject } from "./account-do";
import type { SequencerDurableObject } from "./sequencer-do";

/**
 * Environment bindings for the rookery Worker.
 * Multi-tenant PDS - per-account keys live in DO SQL, not here.
 */
export interface Env {
  /** Durable Object namespace for account storage */
  ACCOUNT: DurableObjectNamespace<AccountDurableObject>;
  /** Durable Object namespace for firehose sequencing */
  SEQUENCER: DurableObjectNamespace<SequencerDurableObject>;
  /** D1 account directory for cross-account queries */
  DIRECTORY: D1Database;
  /** R2 bucket for blob storage */
  BLOBS: R2Bucket;
  /** Public hostname of the PDS */
  ROOKERY_HOSTNAME: string;
  /** Handle domain suffix (e.g. ".pds.example.com") */
  ROOKERY_HANDLE_DOMAIN: string;
  /** PLC directory URL */
  ROOKERY_PLC_URL: string;
  /** Deployment variant: "commons" enables invite-gated enrollment; unset/other = reference (unchanged). */
  ROOKERY_VARIANT?: string;
  /** Cloudflare Access team domain for admin JWT validation. */
  CF_ACCESS_TEAM_DOMAIN?: string;
  /** Cloudflare Access application audience tag for admin JWT validation. */
  CF_ACCESS_AUD?: string;
  /** Comma-separated relay hostnames for requestCrawl fanout */
  ROOKERY_RELAY_HOSTS?: string;
  /** Cloudflare API token (Zone DNS Edit) for publishing _atproto handle TXT records; unset skips them. */
  CLOUDFLARE_DNS_TOKEN?: string;
  /** Cloudflare zone holding ROOKERY_HANDLE_DOMAIN. */
  CLOUDFLARE_ZONE_ID?: string;
  /** Bearer token for /operator/* routes; unset disables them. */
  ROOKERY_OPERATOR_TOKEN?: string;
  /** HMAC secret for stateless rotating DPoP nonces. */
  OAUTH_NONCE_SECRET?: string;
  /** Optional knot admin endpoint for auto-adding newly enrolled rooks as members. */
  ROOKERY_KNOT_ADMIN_ADD_MEMBER_URL?: string;
  /** Secret paired with the knot admin endpoint; configured as a Worker secret. */
  ROOKERY_KNOT_ADMIN_SECRET?: string;
  /** The operator's alert endpoint for security events; configured as a Worker secret. */
  HUB_WEBHOOK_URL?: string;
  /** Shared secret sent as X-Hub-Secret with each alert; configured as a Worker secret. */
  HUB_WEBHOOK_SECRET?: string;
}
