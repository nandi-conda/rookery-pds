// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { defineRookeryWorkersConfig } from "./vitest.config";

export default defineRookeryWorkersConfig({
  include: ["test/commons.test.ts"],
  bindings: {
    ROOKERY_VARIANT: "commons",
    CF_ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com",
    CF_ACCESS_AUD: "test-access-aud",
  },
});
