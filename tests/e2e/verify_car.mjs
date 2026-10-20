// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc
// Verify a repo CAR from the Python rookery with the reference @atproto/repo:
// commit signature, MST structure, and every record decodes.
import { readFileSync } from "node:fs";
import { readCarWithRoot, verifyRepo } from "@atproto/repo";

const [carPath] = process.argv.slice(2);
const { did, signingKey } = JSON.parse(readFileSync(`${carPath}.json`, "utf8"));
const { root, blocks } = await readCarWithRoot(new Uint8Array(readFileSync(carPath)));
const verified = await verifyRepo(blocks, root, did, signingKey);
console.log(JSON.stringify({ ok: true, commit: verified.commit.rev, records: verified.creates.length }));
