// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { defineRookeryWorkersConfig } from "./vitest.config";

export default defineRookeryWorkersConfig({
  include: ["test/commons-noaccess.test.ts"],
  bindings: {
    ROOKERY_VARIANT: "commons",
  },
});
