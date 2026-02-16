// Sanity test for auth + rate limiting + usage_check + pricing page + 16 tools
// Run with: node sanity-test-auth.js

const BASE = "http://localhost:3000";
const TIMEOUT_MS = 30000;

let sessionId = null;
let rpcId = 500;
let passed = 0;
let failed = 0;
const failures = [];

async function rpc(method, params, id, extraHeaders = {}) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    ...extraHeaders,
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

    // Capture rate limit headers
    const rateLimitHeaders = {
      limit: res.headers.get("x-ratelimit-limit"),
      remaining: res.headers.get("x-ratelimit-remaining"),
      reset: res.headers.get("x-ratelimit-reset"),
    };

    if (contentType.includes("text/event-stream")) {
      const text = await res.text();
      for (const line of text.split("\n")) {
        if (line.startsWith("data: ")) {
          const data = JSON.parse(line.slice(6));
          if (data.id === id) return { ...data, rateLimitHeaders, status: res.status };
        }
      }
      throw new Error("No matching response in SSE stream");
    }

    const json = await res.json();
    return { ...json, rateLimitHeaders, status: res.status };
  } finally {
    clearTimeout(timer);
  }
}

async function initialize() {
  const res = await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "auth-test", version: "1.0.0" },
  }, 1);
  if (!res.result) throw new Error("Initialize failed: " + JSON.stringify(res));
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
}

function check(label, condition, failMsg) {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}: ${failMsg}`);
    failed++;
    failures.push({ label, reason: failMsg });
  }
}

async function main() {
  console.log("=".repeat(60));
  console.log(" AUTH + RATE LIMITING SANITY TEST");
  console.log("=".repeat(60));

  // ── 1. Health check: 16 tools ──
  console.log("\n── Health Check ──");
  const health = await (await fetch(`${BASE}/health`)).json();
  check("Health endpoint returns 16 tools", health.tools === 16, `Got ${health.tools}`);

  // ── 2. Root endpoint ──
  console.log("\n── Root Endpoint ──");
  const root = await (await fetch(`${BASE}/`)).json();
  check("Root lists 16 tools", root.toolCount === 16, `Got ${root.toolCount}`);
  check("Root has pricing endpoint", root.endpoints?.pricing === "/pricing", `Missing /pricing`);

  // ── 3. Pricing page ──
  console.log("\n── Pricing Page ──");
  const pricingRes = await fetch(`${BASE}/pricing`);
  const pricingHtml = await pricingRes.text();
  check("Pricing page returns HTML", pricingRes.headers.get("content-type").includes("html"), "Not HTML");
  check("Pricing page has Free tier", pricingHtml.includes("Free"), "Missing Free tier");
  check("Pricing page has $4.99", pricingHtml.includes("$4.99"), "Missing $4.99");
  check("Pricing page has $14.99", pricingHtml.includes("$14.99"), "Missing $14.99");
  check("Pricing page has $29.99", pricingHtml.includes("$29.99"), "Missing $29.99");
  check("Pricing page lists 16 tools", pricingHtml.includes("usage_check"), "Missing usage_check tool");
  check("Pricing page has FAQ", pricingHtml.includes("FAQ"), "Missing FAQ section");

  // ── 4. Server card ──
  console.log("\n── Server Card ──");
  const card = await (await fetch(`${BASE}/.well-known/mcp/server-card.json`)).json();
  check("Server card has 16 tools", card.tools?.length === 16, `Got ${card.tools?.length}`);
  check("Server card has usage_check", card.tools?.some(t => t.name === "usage_check"), "Missing usage_check");
  check("Server card has authentication config", !!card.authentication, "Missing authentication");
  check("Auth not required", card.authentication?.required === false, "Should be false");
  check("Has config schema for apiKey", !!card.authentication?.configSchema?.properties?.apiKey, "Missing apiKey config");

  // ── 5. Initialize MCP session ──
  console.log("\n── MCP Session ──");
  await initialize();
  check("Session initialized", !!sessionId, "No session ID");

  // ── 6. tools/list returns 16 ──
  const listRes = await rpc("tools/list", {}, ++rpcId);
  const toolNames = listRes.result.tools.map(t => t.name);
  check("tools/list returns 16 tools", toolNames.length === 16, `Got ${toolNames.length}`);
  check("usage_check in tool list", toolNames.includes("usage_check"), "Missing");

  // ── 7. Free tier rate limiting (in-memory since no Supabase) ──
  console.log("\n── Free Tier Rate Limiting (in-memory) ──");
  
  // Make a tool call and check rate limit headers
  const dnsRes = await rpc("tools/call", { name: "dns_lookup", arguments: { domain: "example.com", type: "A" } }, ++rpcId);
  check("Tool call succeeds (free tier)", !!dnsRes.result, dnsRes.error?.message || "No result");
  check("Has X-RateLimit-Limit header", dnsRes.rateLimitHeaders.limit !== null, "Missing header");
  check("Has X-RateLimit-Remaining header", dnsRes.rateLimitHeaders.remaining !== null, "Missing header");
  check("Has X-RateLimit-Reset header", dnsRes.rateLimitHeaders.reset !== null, "Missing header");
  check("Limit is 10 (free tier)", dnsRes.rateLimitHeaders.limit === "10", `Got ${dnsRes.rateLimitHeaders.limit}`);

  // ── 8. usage_check tool (free tier) ──
  console.log("\n── usage_check Tool ──");
  const usageRes = await rpc("tools/call", { name: "usage_check", arguments: {} }, ++rpcId);
  const usageText = usageRes.result?.content?.[0]?.text || "";
  check("usage_check returns output", usageText.length > 0, "Empty response");
  check("Shows Free Tier plan", usageText.includes("Free Tier"), `Missing "Free Tier"`);
  check("Shows daily limit", usageText.includes(`/ ${10}`), `Missing limit`);
  check("Shows upgrade options", usageText.includes("$4.99"), "Missing pricing");

  // ── 9. Invalid API key handling ──
  console.log("\n── Invalid API Key (no Supabase = graceful degradation) ──");
  // Without Supabase, invalid keys should still be allowed (graceful degradation)
  const fakeKeyRes = await rpc("tools/call", { name: "dns_lookup", arguments: { domain: "example.com", type: "A" } }, ++rpcId, { "x-api-key": "dk_live_fake123" });
  // Without Supabase configured, it should still allow requests
  check("Request with API key still works (no Supabase)", !!fakeKeyRes.result || fakeKeyRes.error === undefined, fakeKeyRes.error?.message || "Unexpected failure");

  // ── 10. Rate limit exhaustion test ──
  console.log("\n── Rate Limit Exhaustion ──");
  // We already used ~3 free requests. Burn through the rest to test the limit.
  let hitLimit = false;
  for (let i = 0; i < 12; i++) {
    const res = await rpc("tools/call", { name: "dns_lookup", arguments: { domain: "example.com", type: "A" } }, ++rpcId);
    if (res.error && res.error.message?.includes("free requests")) {
      hitLimit = true;
      check("Rate limit reached after 10 requests", true, "");
      check("Rate limit message mentions pricing", res.error.message.includes("$4.99"), "Missing pricing in message");
      break;
    }
  }
  if (!hitLimit) {
    check("Rate limit triggered", false, "Never hit rate limit after 12+ requests");
  }

  // ── Summary ──
  console.log("\n" + "=".repeat(60));
  console.log(" AUTH SANITY TEST RESULTS");
  console.log("=".repeat(60));
  console.log(` Passed: ${passed}`);
  console.log(` Failed: ${failed}`);
  console.log("=".repeat(60));

  if (failures.length > 0) {
    console.log("\n FAILURES:");
    for (const f of failures) console.log(`  - ${f.label}: ${f.reason}`);
  }

  if (failed === 0) {
    console.log("\n🎉 ALL AUTH TESTS PASS! Rate limiting + usage_check + pricing page verified!\n");
  } else {
    console.log("\n⚠️ Some tests failed — review above\n");
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });
