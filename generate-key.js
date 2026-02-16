#!/usr/bin/env node
// Generate API Key — Run: node generate-key.js --email user@example.com --tier starter
// Requires SUPABASE_URL and SUPABASE_SERVICE_KEY in .env

import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const args = process.argv.slice(2);
const flags = {};
for (let i = 0; i < args.length; i += 2) {
  flags[args[i].replace(/^--/, "")] = args[i + 1];
}

if (!flags.email) {
  console.error("Usage: node generate-key.js --email user@example.com --tier starter|pro|unlimited");
  process.exit(1);
}

const tier = flags.tier || "starter";
const validTiers = ["starter", "pro", "unlimited"];
if (!validTiers.includes(tier)) {
  console.error(`Invalid tier "${tier}". Must be one of: ${validTiers.join(", ")}`);
  process.exit(1);
}

const LIMITS = { starter: 500, pro: 5000, unlimited: null };

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables.");
  console.error("Set them in your shell or .env file.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const apiKey = "dk_live_" + crypto.randomBytes(16).toString("hex");

const { data, error } = await supabase.from("api_keys").insert({
  api_key: apiKey,
  email: flags.email,
  tier,
  monthly_limit: LIMITS[tier],
  requests_used: 0,
  billing_cycle_start: new Date().toISOString(),
}).select().single();

if (error) {
  console.error("Failed to create API key:", error.message);
  process.exit(1);
}

console.log("═".repeat(50));
console.log("  API Key Generated Successfully");
console.log("═".repeat(50));
console.log(`  Email:     ${flags.email}`);
console.log(`  Tier:      ${tier}`);
console.log(`  Limit:     ${LIMITS[tier] ?? "Unlimited"} requests/month`);
console.log(`  API Key:   ${apiKey}`);
console.log(`  ID:        ${data.id}`);
console.log("═".repeat(50));
console.log("\nSend this key to the user. They add it as x-api-key header.");
