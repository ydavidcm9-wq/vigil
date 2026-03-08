#!/usr/bin/env node

/**
 * Vigil — Create Admin User
 *
 * Reads ADMIN_EMAIL and ADMIN_PASSWORD from env or .env.local.
 * Connects to DATABASE_URL and inserts an admin user with bcrypt-hashed password.
 *
 * Usage:
 *   node scripts/create-user.mjs
 *   ADMIN_EMAIL=admin@test.com ADMIN_PASSWORD=secret node scripts/create-user.mjs
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// ── Load .env.local ───────────────────────────────────────────────
function loadEnvFile() {
  const envPath = resolve(ROOT, ".env.local");
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
    // .env.local is optional — env vars can be set directly
  }
}

loadEnvFile();

// ── Validate required config ──────────────────────────────────────
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is required.");
  console.error("Set it in .env.local or as an environment variable.");
  process.exit(1);
}

if (!ADMIN_EMAIL) {
  console.error("ERROR: ADMIN_EMAIL is required.");
  console.error("Set it in .env.local or as an environment variable.");
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error("ERROR: ADMIN_PASSWORD is required.");
  console.error("Set it in .env.local or as an environment variable.");
  process.exit(1);
}

if (ADMIN_PASSWORD.length < 8) {
  console.error("ERROR: ADMIN_PASSWORD must be at least 8 characters.");
  process.exit(1);
}

// ── Create user ───────────────────────────────────────────────────
async function createUser() {
  const pool = new pg.Pool({ connectionString: DATABASE_URL });

  try {
    console.log(`Connecting to database...`);
    const client = await pool.connect();

    try {
      // Check if user already exists
      const existing = await client.query(
        "SELECT id, email, role FROM users WHERE email = $1",
        [ADMIN_EMAIL]
      );

      if (existing.rows.length > 0) {
        const user = existing.rows[0];
        console.log(`User already exists: ${user.email} (role: ${user.role}, id: ${user.id})`);

        // Update password if requested
        const updatePassword = process.argv.includes("--update-password");
        if (updatePassword) {
          const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
          await client.query(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
            [hash, user.id]
          );
          console.log("Password updated successfully.");
        } else {
          console.log("Use --update-password flag to update the password.");
        }

        return;
      }

      // Hash password with bcrypt (cost factor 12)
      const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      // Insert admin user
      const result = await client.query(
        `INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, 'admin', NOW(), NOW())
         RETURNING id, email, role, created_at`,
        [crypto.randomUUID(), ADMIN_EMAIL, passwordHash]
      );

      const user = result.rows[0];
      console.log("");
      console.log("Admin user created successfully:");
      console.log(`  ID:      ${user.id}`);
      console.log(`  Email:   ${user.email}`);
      console.log(`  Role:    ${user.role}`);
      console.log(`  Created: ${user.created_at}`);
      console.log("");
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Failed to create user:", err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

createUser();
