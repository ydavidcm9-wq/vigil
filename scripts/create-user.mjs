#!/usr/bin/env node

/**
 * Vigil — Create or update a local user in the JSON-backed auth store.
 *
 * Supported env vars:
 *   VIGIL_USER / ADMIN_EMAIL      Username to create or update
 *   VIGIL_PASS / ADMIN_PASSWORD   Password to set
 *   VIGIL_ROLE                    admin | analyst | viewer (default: admin)
 *
 * Usage:
 *   node scripts/create-user.mjs
 *   VIGIL_USER=alice VIGIL_PASS='correct horse battery staple' node scripts/create-user.mjs
 *   node scripts/create-user.mjs --update-password
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { getUser, createUser, updateUser } = require("../lib/users");

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

function loadEnvFile(fileName) {
  const envPath = resolve(ROOT, fileName);
  try {
    const content = readFileSync(envPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.substring(0, eqIdx).trim();
      const value = trimmed.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
      if (!process.env[key]) {
        process.env[key] = value;
      }
    }
  } catch {
    // Optional env file.
  }
}

loadEnvFile(".env");
loadEnvFile(".env.local");

const username = (process.env.VIGIL_USER || process.env.ADMIN_EMAIL || "admin").trim();
const password = process.env.VIGIL_PASS || process.env.ADMIN_PASSWORD || "";
const role = (process.env.VIGIL_ROLE || "admin").trim().toLowerCase();
const updatePasswordOnly = process.argv.includes("--update-password");

function fail(message) {
  console.error(`CREATE_USER_FAIL: ${message}`);
  process.exit(1);
}

if (!username) fail("VIGIL_USER (or ADMIN_EMAIL) is required.");
if (!password) fail("VIGIL_PASS (or ADMIN_PASSWORD) is required.");
if (password.length < 8) fail("Password must be at least 8 characters.");
if (!["admin", "analyst", "viewer"].includes(role)) {
  fail("VIGIL_ROLE must be one of: admin, analyst, viewer.");
}

const existing = getUser(username);

if (existing) {
  if (!updatePasswordOnly) {
    console.log(`User already exists: ${username} (${existing.role})`);
    console.log("Use --update-password to rotate the password for an existing account.");
    process.exit(0);
  }

  const updated = updateUser(username, { password, role });
  console.log(JSON.stringify({ ok: true, action: "updated", user: updated }, null, 2));
  process.exit(0);
}

const created = createUser(username, password, role);
console.log(JSON.stringify({ ok: true, action: "created", user: created }, null, 2));
