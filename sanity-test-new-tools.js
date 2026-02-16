// Sanity test for all 10 new tools + verify 15 tools registered
// Run with: node sanity-test-new-tools.js

const BASE = "http://localhost:3000";
const TIMEOUT_MS = 30000;

let sessionId = null;
let rpcId = 300;
let passed = 0;
let failed = 0;
const failures = [];

async function rpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: controller.signal,
    });

    const sid = res.headers.get("mcp-session-id");
    if (sid) sessionId = sid;

    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream")) {
      const text = await res.text();
      for (const line of text.split("\n")) {
        if (line.startsWith("data: ")) {
          const data = JSON.parse(line.slice(6));
          if (data.id === id) return data;
        }
      }
      throw new Error("No matching response in SSE stream");
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function initialize() {
  const res = await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "sanity-test", version: "1.0.0" },
  }, 1);
  if (!res.result) throw new Error("Initialize failed");
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
}

async function callTool(name, args) {
  const id = ++rpcId;
  const res = await rpc("tools/call", { name, arguments: args }, id);
  if (res.error) return { text: null, error: res.error.message };
  return { text: res.result?.content?.[0]?.text || "", error: null };
}

async function test(label, toolName, args, validate) {
  const start = Date.now();
  try {
    const { text, error } = await callTool(toolName, args);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);

    if (error) {
      console.log(`  ❌ ${label} — ERROR (${elapsed}s): ${error}`);
      failed++;
      failures.push({ label, reason: error });
      return;
    }

    const result = validate(text);
    if (result === true) {
      console.log(`  ✅ ${label} — PASS (${elapsed}s)`);
      passed++;
    } else {
      console.log(`  ❌ ${label} — FAIL (${elapsed}s): ${result}`);
      console.log(`     First 300 chars: ${text.slice(0, 300)}`);
      failed++;
      failures.push({ label, reason: result });
    }
  } catch (err) {
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    console.log(`  💥 ${label} — EXCEPTION (${elapsed}s): ${err.message}`);
    failed++;
    failures.push({ label, reason: err.message });
  }
}

async function main() {
  console.log("=".repeat(60));
  console.log(" SANITY TEST: 10 New Tools + 15 Tool Verification");
  console.log("=".repeat(60));

  // Health check
  const health = await (await fetch(`${BASE}/health`)).json();
  console.log(`\nHealth: ${JSON.stringify(health)}`);
  if (health.tools !== 15) {
    console.log(`❌ Expected 15 tools, got ${health.tools}`);
    process.exit(1);
  }
  console.log(`✅ Health reports 15 tools\n`);

  // Initialize
  await initialize();
  console.log(`✅ Session initialized: ${sessionId}\n`);

  // Verify tools/list returns 15
  const listRes = await rpc("tools/list", {}, ++rpcId);
  const toolNames = listRes.result.tools.map(t => t.name);
  console.log(`Tools registered: ${toolNames.length}`);
  console.log(`  ${toolNames.join(", ")}\n`);
  if (toolNames.length !== 15) {
    console.log(`❌ Expected 15 tools, got ${toolNames.length}`);
    process.exit(1);
  }
  console.log(`✅ All 15 tools registered\n`);

  // ─── Test each new tool ───

  console.log("─".repeat(60));
  console.log(" TOOL 7: reverse_dns");
  console.log("─".repeat(60));
  await test(
    'reverse_dns "8.8.8.8"',
    "reverse_dns",
    { target: "8.8.8.8" },
    (t) => t.includes("dns.google") ? true : `Expected "dns.google" in output`
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 8: dns_propagation");
  console.log("─".repeat(60));
  await test(
    'dns_propagation "github.com"',
    "dns_propagation",
    { domain: "github.com" },
    (t) => {
      if (!t.includes("Google")) return `Missing "Google" resolver`;
      if (!t.includes("Cloudflare")) return `Missing "Cloudflare" resolver`;
      if (!t.includes("PROPAGATED")) return `Missing propagation verdict`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 9: subdomain_finder");
  console.log("─".repeat(60));
  await test(
    'subdomain_finder "google.com"',
    "subdomain_finder",
    { domain: "google.com" },
    (t) => {
      if (!t.includes("www.google.com")) return `Missing www.google.com`;
      if (!t.includes("mail.google.com")) return `Missing mail.google.com`;
      if (!t.includes("Found")) return `Missing "Found" count`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 10: http_headers_check");
  console.log("─".repeat(60));
  await test(
    'http_headers_check "stripe.com"',
    "http_headers_check",
    { domain: "stripe.com" },
    (t) => {
      if (!t.includes("Grade")) return `Missing "Grade"`;
      if (!t.includes("CRITICAL")) return `Missing "CRITICAL HEADERS" section`;
      if (!t.includes("Score")) return `Missing "Score"`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 11: redirect_chain");
  console.log("─".repeat(60));
  await test(
    'redirect_chain "http://github.com"',
    "redirect_chain",
    { url: "http://github.com" },
    (t) => {
      if (!t.includes("Hop")) return `Missing "Hop"`;
      if (!t.includes("Total Hops")) return `Missing hop count`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 12: tech_stack_detect");
  console.log("─".repeat(60));
  await test(
    'tech_stack_detect "vercel.com"',
    "tech_stack_detect",
    { domain: "vercel.com" },
    (t) => {
      if (!t.includes("Tech Stack Detection")) return `Missing header`;
      // Should detect something — at minimum raw headers
      if (!t.includes("Raw Headers")) return `Missing "Raw Headers" section`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 13: domain_age");
  console.log("─".repeat(60));
  await test(
    'domain_age "google.com"',
    "domain_age",
    { domain: "google.com" },
    (t) => {
      if (!t.includes("Age:")) return `Missing "Age:"`;
      if (!t.includes("1997")) return `Missing creation year 1997`;
      if (!t.includes("veteran") && !t.includes("established") && !t.includes("Well")) return `Missing age context`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 14: dns_compare");
  console.log("─".repeat(60));
  await test(
    'dns_compare "google.com" vs "bing.com"',
    "dns_compare",
    { domain1: "google.com", domain2: "bing.com" },
    (t) => {
      if (!t.includes("google.com")) return `Missing domain1`;
      if (!t.includes("bing.com")) return `Missing domain2`;
      if (!t.includes("Record Type")) return `Missing table header`;
      if (!t.includes("Differences") && !t.includes("differ") && !t.includes("identical")) return `Missing comparison verdict`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 15: port_check");
  console.log("─".repeat(60));
  await test(
    'port_check "google.com"',
    "port_check",
    { domain: "google.com", ports: "80,443" },
    (t) => {
      if (!t.includes("80")) return `Missing port 80`;
      if (!t.includes("443")) return `Missing port 443`;
      if (!t.includes("Results:")) return `Missing results summary`;
      if (!t.includes("Open")) return `Expected at least one open port`;
      return true;
    }
  );

  console.log("\n" + "─".repeat(60));
  console.log(" TOOL 6: domain_report (flagship mega report)");
  console.log("─".repeat(60));
  await test(
    'domain_report "stripe.com"',
    "domain_report",
    { domain: "stripe.com" },
    (t) => {
      if (!t.includes("COMPLETE DOMAIN INTELLIGENCE REPORT")) return `Missing report header`;
      if (!t.includes("DNS Records")) return `Missing DNS section`;
      if (!t.includes("WHOIS")) return `Missing WHOIS section`;
      if (!t.includes("Email Security")) return `Missing email section`;
      if (!t.includes("SSL Certificate")) return `Missing SSL section`;
      if (!t.includes("HTTP Security Headers")) return `Missing headers section`;
      if (!t.includes("Technology Stack")) return `Missing tech section`;
      if (!t.includes("Domain Age")) return `Missing age section`;
      if (!t.includes("QUICK SUMMARY")) return `Missing quick summary`;
      if (!t.includes("Report generated in")) return `Missing timing`;
      return true;
    }
  );

  // ─── Summary ───
  console.log("\n" + "=".repeat(60));
  console.log(" SANITY TEST RESULTS");
  console.log("=".repeat(60));
  console.log(` Passed: ${passed}`);
  console.log(` Failed: ${failed}`);
  console.log("=".repeat(60));

  if (failures.length > 0) {
    console.log("\n FAILURES:");
    for (const f of failures) console.log(`  - ${f.label}: ${f.reason}`);
    console.log("=".repeat(60));
  }

  if (failed === 0) {
    console.log("\n🎉 ALL 10 NEW TOOLS PASS! 15 tools total — ready to publish!\n");
  } else {
    console.log("\n❌ Some tests failed — fix before publishing\n");
  }

  process.exit(failed > 0 ? 1 : 0);
}

main();
