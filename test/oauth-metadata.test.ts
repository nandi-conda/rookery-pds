import { worker } from "./helpers";

describe("OAuth discovery metadata", () => {
  const issuer = "https://rookery.test";

  it("serves exact authorization server metadata", async () => {
    const response = await worker.fetch(
      "http://localhost/.well-known/oauth-authorization-server",
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
      require_pushed_authorization_requests: true,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
      token_endpoint_auth_signing_alg_values_supported: ["ES256"],
      scopes_supported: ["atproto"],
      dpop_signing_alg_values_supported: ["ES256"],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      revocation_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
      revocation_endpoint_auth_signing_alg_values_supported: ["ES256"],
    });
  });

  it("serves exact protected resource metadata", async () => {
    const response = await worker.fetch(
      "http://localhost/.well-known/oauth-protected-resource",
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      resource: issuer,
      authorization_servers: [issuer],
    });
  });
});
