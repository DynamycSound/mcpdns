// MCP Domain Lookup — Integration Test
// Run with: node test.js
// Requires server running on http://localhost:3000

const BASE = "http://localhost:3000";
let sessionId = null;
let passed = 0;
let failed = 0;

async function rpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const res = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });

  // Capture session ID from response headers
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;

  const contentType = res.headers.get("content-type") || "";

  if (contentType.includes("text/event-stream")) {
    // Parse SSE response
    const text = await res.text();
    const lines = text.split("\n");
    for (const line of lines) {
      if (line.startsWith("data: ")) {
        const data = JSON.parse(line.slice(6));
        if (data.id === id) return data;
      }
    }
    throw new Error("No matching response found in SSE stream");
  }

  return res.json();
}

function report(name, success, detail) {
  if (success) {
    passed++;
    console.log(`  ✅ PASS: ${name}`);
  } else {
    failed++;
    console.log(`  ❌ FAIL: ${name}`);
    if (detail) console.log(`          ${detail}`);
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function testInitialize() {
  console.log("\n🔌 Step 1: Initialize session");
  const res = await rpc(
    "initialize",
    {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0.0" },
    },
    1
  );

  const ok =
    res.result &&
    res.result.protocolVersion === "2025-03-26" &&
    res.result.serverInfo?.name === "mcp-domain-lookup";

  report("Initialize handshake", ok, ok ? null : JSON.stringify(res));
  report("Session ID received", !!sessionId, sessionId ? `Session: ${sessionId}` : "No mcp-session-id header");

  // Send initialized notification (required by protocol)
  await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "mcp-session-id": sessionId,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
}

async function testToolsList() {
  console.log("\n📋 Step 2: List tools");
  const res = await rpc("tools/list", {}, 2);
  const tools = res.result?.tools || [];
  const names = tools.map((t) => t.name).sort();
  const expected = ["dns_lookup", "domain_available", "email_config_check", "ssl_check", "whois_lookup"];

  report(`Found ${tools.length} tools`, tools.length === 5);
  report("All 5 tools registered", JSON.stringify(names) === JSON.stringify(expected), `Got: ${names.join(", ")}`);
}

async function testToolCall(name, args, validator, id) {
  const res = await rpc("tools/call", { name, arguments: args }, id);

  if (res.error) {
    report(name, false, `RPC error: ${res.error.message}`);
    return;
  }

  const text = res.result?.content?.[0]?.text || "";
  if (!text) {
    report(name, false, "Empty response text");
    return;
  }

  const ok = validator(text);
  report(name, ok);
  // Show first 200 chars of output
  const preview = text.slice(0, 200).replace(/\n/g, " | ");
  console.log(`          Preview: ${preview}...`);
}

async function testDnsLookup() {
  console.log("\n🔍 Step 3: Test dns_lookup (google.com, ALL)");
  await testToolCall(
    "dns_lookup",
    { domain: "google.com", record_type: "ALL" },
    (text) => text.includes("google.com") && text.includes("Records"),
    10
  );
}

async function testWhoisLookup() {
  console.log("\n🔍 Step 4: Test whois_lookup (google.com)");
  await testToolCall(
    "whois_lookup",
    { domain: "google.com" },
    (text) => text.includes("google.com") && (text.includes("Registrar") || text.includes("WHOIS")),
    20
  );
}

async function testDomainAvailable() {
  console.log("\n🔍 Step 5: Test domain_available (thisisaprobablynotregistered12345xyz.com)");
  await testToolCall(
    "domain_available",
    { domain: "thisisaprobablynotregistered12345xyz.com" },
    (text) => text.includes("AVAILABLE") || text.includes("TAKEN"),
    30
  );
}

async function testEmailConfigCheck() {
  console.log("\n🔍 Step 6: Test email_config_check (google.com)");
  await testToolCall(
    "email_config_check",
    { domain: "google.com" },
    (text) => text.includes("google.com") && text.includes("Grade"),
    40
  );
}

async function testSslCheck() {
  console.log("\n🔍 Step 7: Test ssl_check (google.com)");
  await testToolCall(
    "ssl_check",
    { domain: "google.com" },
    (text) => text.includes("google.com") && (text.includes("Certificate") || text.includes("SSL")),
    50
  );
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(60));
  console.log(" MCP Domain Lookup — Integration Test Suite");
  console.log("=".repeat(60));

  try {
    // Quick health check first
    const health = await fetch(`${BASE}/health`);
    if (!health.ok) throw new Error("Server not responding on /health");
    console.log("✅ Server is reachable\n");
  } catch (err) {
    console.error(`❌ Cannot reach server at ${BASE}: ${err.message}`);
    console.error("   Make sure the server is running: npm start");
    process.exit(1);
  }

  try {
    await testInitialize();
    await testToolsList();
    await testDnsLookup();
    await testWhoisLookup();
    await testDomainAvailable();
    await testEmailConfigCheck();
    await testSslCheck();
  } catch (err) {
    console.error(`\n💥 Unexpected error: ${err.message}`);
    failed++;
  }

  console.log("\n" + "=".repeat(60));
  console.log(` Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log("=".repeat(60));

  process.exit(failed > 0 ? 1 : 0);
}

main();
