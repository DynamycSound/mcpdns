#!/usr/bin/env node
// Admin tool for managing API keys
// Requires SUPABASE_URL and SUPABASE_SERVICE_KEY in environment
//
// Usage:
//   node manage-keys.js list
//   node manage-keys.js deactivate dk_live_abc123
//   node manage-keys.js activate dk_live_abc123
//   node manage-keys.js upgrade dk_live_abc123 pro
//   node manage-keys.js usage dk_live_abc123
//   node manage-keys.js reset dk_live_abc123

import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const [command, arg1, arg2] = process.argv.slice(2);

const LIMITS = { starter: 500, pro: 5000, unlimited: null };

function mask(key) {
  return key ? key.slice(0, 16) + "..." : "N/A";
}

async function list() {
  const { data, error } = await supabase
    .from("api_keys")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) { console.error("Error:", error.message); process.exit(1); }

  if (!data || data.length === 0) {
    console.log("No API keys found.");
    return;
  }

  console.log(`\n${"═".repeat(90)}`);
  console.log(` API Keys (${data.length} total)`);
  console.log(`${"═".repeat(90)}`);

  const pad = (s, n) => String(s).padEnd(n);
  console.log(`${pad("Key", 22)} ${pad("Email", 28)} ${pad("Tier", 12)} ${pad("Used/Limit", 14)} ${pad("Active", 8)}`);
  console.log(`${"─".repeat(90)}`);

  for (const k of data) {
    const limit = k.monthly_limit === null ? "∞" : k.monthly_limit;
    console.log(
      `${pad(mask(k.api_key), 22)} ${pad(k.email, 28)} ${pad(k.tier, 12)} ${pad(`${k.requests_used}/${limit}`, 14)} ${pad(k.is_active ? "✅" : "❌", 8)}`
    );
  }
  console.log(`${"═".repeat(90)}\n`);
}

async function deactivate(key) {
  const { data, error } = await supabase
    .from("api_keys")
    .update({ is_active: false })
    .eq("api_key", key)
    .select()
    .single();

  if (error) { console.error("Error:", error.message); process.exit(1); }
  console.log(`✅ Deactivated key ${mask(key)} (${data.email})`);
}

async function activate(key) {
  const { data, error } = await supabase
    .from("api_keys")
    .update({ is_active: true })
    .eq("api_key", key)
    .select()
    .single();

  if (error) { console.error("Error:", error.message); process.exit(1); }
  console.log(`✅ Activated key ${mask(key)} (${data.email})`);
}

async function upgrade(key, tier) {
  if (!LIMITS.hasOwnProperty(tier)) {
    console.error(`Invalid tier "${tier}". Must be: starter, pro, unlimited`);
    process.exit(1);
  }

  const { data, error } = await supabase
    .from("api_keys")
    .update({ tier, monthly_limit: LIMITS[tier] })
    .eq("api_key", key)
    .select()
    .single();

  if (error) { console.error("Error:", error.message); process.exit(1); }
  console.log(`✅ Upgraded ${mask(key)} (${data.email}) to ${tier} (${LIMITS[tier] ?? "unlimited"} requests/month)`);
}

async function usage(key) {
  const { data: keyData, error: keyErr } = await supabase
    .from("api_keys")
    .select("*")
    .eq("api_key", key)
    .single();

  if (keyErr) { console.error("Error:", keyErr.message); process.exit(1); }

  // Get recent logs
  const { data: logs } = await supabase
    .from("request_logs")
    .select("tool_name, created_at")
    .eq("api_key_id", keyData.id)
    .order("created_at", { ascending: false })
    .limit(100);

  const limit = keyData.monthly_limit === null ? "Unlimited" : keyData.monthly_limit;
  const remaining = keyData.monthly_limit === null ? "∞" : Math.max(0, keyData.monthly_limit - keyData.requests_used);
  const cycleEnd = new Date(new Date(keyData.billing_cycle_start).getTime() + 30 * 24 * 60 * 60 * 1000);

  console.log(`\n${"═".repeat(50)}`);
  console.log(` Usage Report: ${mask(key)}`);
  console.log(`${"═".repeat(50)}`);
  console.log(` Email:          ${keyData.email}`);
  console.log(` Tier:           ${keyData.tier}`);
  console.log(` Active:         ${keyData.is_active ? "Yes" : "No"}`);
  console.log(` Requests Used:  ${keyData.requests_used} / ${limit}`);
  console.log(` Remaining:      ${remaining}`);
  console.log(` Cycle Start:    ${new Date(keyData.billing_cycle_start).toISOString().split("T")[0]}`);
  console.log(` Cycle End:      ${cycleEnd.toISOString().split("T")[0]}`);
  console.log(` Created:        ${new Date(keyData.created_at).toISOString().split("T")[0]}`);

  if (logs && logs.length > 0) {
    const toolCounts = {};
    for (const l of logs) {
      toolCounts[l.tool_name] = (toolCounts[l.tool_name] || 0) + 1;
    }
    console.log(`\n Top Tools (last 100 requests):`);
    const sorted = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]);
    for (const [tool, count] of sorted) {
      console.log(`   ${tool.padEnd(25)} ${count} calls`);
    }
  }

  console.log(`${"═".repeat(50)}\n`);
}

async function reset(key) {
  const { data, error } = await supabase
    .from("api_keys")
    .update({ requests_used: 0, billing_cycle_start: new Date().toISOString() })
    .eq("api_key", key)
    .select()
    .single();

  if (error) { console.error("Error:", error.message); process.exit(1); }
  console.log(`✅ Reset usage for ${mask(key)} (${data.email}) — now 0/${data.monthly_limit ?? "∞"}`);
}

// Dispatch
switch (command) {
  case "list": await list(); break;
  case "deactivate": await deactivate(arg1); break;
  case "activate": await activate(arg1); break;
  case "upgrade": await upgrade(arg1, arg2); break;
  case "usage": await usage(arg1); break;
  case "reset": await reset(arg1); break;
  default:
    console.log(`Usage:
  node manage-keys.js list
  node manage-keys.js deactivate <api_key>
  node manage-keys.js activate <api_key>
  node manage-keys.js upgrade <api_key> <tier>
  node manage-keys.js usage <api_key>
  node manage-keys.js reset <api_key>`);
}
