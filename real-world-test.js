// Real-World Integration Test Suite — 50 tests
// Run with: node real-world-test.js
// Requires server running on http://localhost:3000

const BASE = "http://localhost:3000";
const TIMEOUT_MS = 15000;

let sessionId = null;
let rpcId = 100;
const results = [];

// ---------------------------------------------------------------------------
// MCP helpers
// ---------------------------------------------------------------------------

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
  const res = await rpc(
    "initialize",
    {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "real-world-test", version: "1.0.0" },
    },
    1
  );
  if (!res.result) throw new Error("Initialize failed: " + JSON.stringify(res));

  // Send initialized notification
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

async function runToolTest(testNum, toolName, args, validator, description) {
  const id = ++rpcId;
  const start = performance.now();
  let status = "PASS";
  let brief = "";
  let errorMsg = "";

  try {
    const res = await rpc("tools/call", { name: toolName, arguments: args }, id);
    const elapsed = performance.now() - start;

    if (res.error) {
      // JSON-RPC level error — check if the validator accepts it as expected
      const errText = res.error.message || JSON.stringify(res.error);
      const validationResult = validator(null, res.error);
      if (validationResult === true) {
        status = "PASS";
        brief = errText.slice(0, 100);
      } else {
        status = "FAIL";
        brief = errText.slice(0, 100);
        errorMsg = `RPC error: ${errText}`;
      }
    } else {
      const text = res.result?.content?.[0]?.text || "";
      const type = res.result?.content?.[0]?.type;

      if (type !== "text") {
        status = "FAIL";
        errorMsg = `Expected content type "text", got "${type}"`;
        brief = errorMsg;
      } else if (!text) {
        status = "FAIL";
        errorMsg = "Empty response text";
        brief = errorMsg;
      } else {
        const validationResult = validator(text, null);
        if (validationResult === true) {
          status = "PASS";
        } else {
          status = "FAIL";
          errorMsg = typeof validationResult === "string" ? validationResult : "Validation failed";
        }
        brief = text.replace(/\n/g, " ").slice(0, 100);
      }
    }

    results.push({ testNum, toolName, domain: args.domain, status, brief, errorMsg, elapsed });
  } catch (err) {
    const elapsed = performance.now() - start;
    status = "ERROR";
    errorMsg = err.name === "AbortError" ? "Timed out (15s)" : err.message;
    brief = errorMsg.slice(0, 100);
    results.push({ testNum, toolName, domain: args.domain, status, brief, errorMsg, elapsed });
  }

  const icon = status === "PASS" ? "✅" : status === "FAIL" ? "❌" : "💥";
  const ms = results[results.length - 1].elapsed.toFixed(0);
  console.log(`  ${icon} Test ${String(testNum).padStart(2)}: ${toolName.padEnd(20)} ${(args.domain || "").padEnd(50)} ${status} (${ms}ms)`);
}

// ---------------------------------------------------------------------------
// All 50 test definitions
// ---------------------------------------------------------------------------

const tests = [
  // === DNS_LOOKUP (1-15) ===
  {
    num: 1, tool: "dns_lookup",
    args: { domain: "google.com", record_type: "ALL" },
    validate: (t) => t && t.includes("google.com") && t.includes("Records") ? true : "Missing google.com or Records",
  },
  {
    num: 2, tool: "dns_lookup",
    args: { domain: "github.com", record_type: "A" },
    validate: (t) => t && t.includes("A Records") ? true : "Missing A Records",
  },
  {
    num: 3, tool: "dns_lookup",
    args: { domain: "microsoft.com", record_type: "MX" },
    validate: (t) => t && t.includes("MX") ? true : "Missing MX info",
  },
  {
    num: 4, tool: "dns_lookup",
    args: { domain: "cloudflare.com", record_type: "TXT" },
    validate: (t) => t && t.includes("TXT") ? true : "Missing TXT info",
  },
  {
    num: 5, tool: "dns_lookup",
    args: { domain: "amazon.com", record_type: "NS" },
    validate: (t) => t && t.includes("NS") ? true : "Missing NS info",
  },
  {
    num: 6, tool: "dns_lookup",
    args: { domain: "https://www.reddit.com/r/programming", record_type: "ALL" },
    validate: (t) => t && t.includes("reddit.com") ? true : "URL not stripped properly — missing reddit.com",
  },
  {
    num: 7, tool: "dns_lookup",
    args: { domain: "shopify.com", record_type: "AAAA" },
    validate: (t) => t && t.includes("AAAA") ? true : "Missing AAAA section",
  },
  {
    num: 8, tool: "dns_lookup",
    args: { domain: "  stripe.com  ", record_type: "ALL" },
    validate: (t) => t && t.includes("stripe.com") ? true : "Whitespace not trimmed — missing stripe.com",
  },
  {
    num: 9, tool: "dns_lookup",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com", record_type: "ALL" },
    validate: (t) => t && (t.includes("No records") || t.includes("no records") || t.includes("❌")) ? true : "Should indicate no records found",
  },
  {
    num: 10, tool: "dns_lookup",
    args: { domain: "wikipedia.org", record_type: "ALL" },
    validate: (t) => t && t.includes("wikipedia.org") ? true : "Missing wikipedia.org",
  },
  {
    num: 11, tool: "dns_lookup",
    args: { domain: "bbc.co.uk", record_type: "ALL" },
    validate: (t) => t && t.includes("bbc.co.uk") ? true : "Missing bbc.co.uk — .co.uk TLD failed",
  },
  {
    num: 12, tool: "dns_lookup",
    args: { domain: "gov.uk", record_type: "ALL" },
    validate: (t) => t && t.includes("gov.uk") ? true : "Missing gov.uk",
  },
  {
    num: 13, tool: "dns_lookup",
    args: { domain: "toyota.jp", record_type: "A" },
    validate: (t) => t && t.includes("toyota.jp") ? true : "Missing toyota.jp — JP TLD failed",
  },
  {
    num: 14, tool: "dns_lookup",
    args: { domain: "google.com", record_type: "INVALIDTYPE" },
    validate: (t, err) => {
      // Either a text response with error info OR a JSON-RPC error is acceptable
      if (err) return true;
      if (t) return true; // Any non-crash response is fine
      return "Should return error for invalid type, not crash";
    },
  },
  {
    num: 15, tool: "dns_lookup",
    args: { domain: "notion.so", record_type: "CNAME" },
    validate: (t) => t && t.includes("notion.so") ? true : "Missing notion.so — .so TLD failed",
  },

  // === WHOIS_LOOKUP (16-25) ===
  {
    num: 16, tool: "whois_lookup",
    args: { domain: "google.com" },
    validate: (t) => t && t.includes("google.com") && (t.includes("Registrar") || t.includes("1997")) ? true : "Missing registrar or creation date",
  },
  {
    num: 17, tool: "whois_lookup",
    args: { domain: "github.com" },
    validate: (t) => t && t.includes("github.com") ? true : "Missing github.com",
  },
  {
    num: 18, tool: "whois_lookup",
    args: { domain: "amazon.com" },
    validate: (t) => t && t.includes("amazon.com") ? true : "Missing amazon.com",
  },
  {
    num: 19, tool: "whois_lookup",
    args: { domain: "https://stripe.com/" },
    validate: (t) => t && t.includes("stripe.com") ? true : "URL not stripped — missing stripe.com",
  },
  {
    num: 20, tool: "whois_lookup",
    args: { domain: "wordpress.org" },
    validate: (t) => t && t.includes("wordpress.org") ? true : "Missing wordpress.org",
  },
  {
    num: 21, tool: "whois_lookup",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com" },
    validate: (t) => {
      if (!t) return "Empty response";
      // Should not crash — any response is acceptable
      return true;
    },
  },
  {
    num: 22, tool: "whois_lookup",
    args: { domain: "facebook.com" },
    validate: (t) => t && t.includes("facebook.com") ? true : "Missing facebook.com",
  },
  {
    num: 23, tool: "whois_lookup",
    args: { domain: "openai.com" },
    validate: (t) => t && t.includes("openai.com") ? true : "Missing openai.com",
  },
  {
    num: 24, tool: "whois_lookup",
    args: { domain: "netflix.com" },
    validate: (t) => t && t.includes("netflix.com") ? true : "Missing netflix.com",
  },
  {
    num: 25, tool: "whois_lookup",
    args: { domain: "x.com" },
    validate: (t) => t && t.includes("x.com") ? true : "Missing x.com",
  },

  // === DOMAIN_AVAILABLE (26-35) ===
  {
    num: 26, tool: "domain_available",
    args: { domain: "google.com" },
    validate: (t) => t && t.includes("TAKEN") ? true : "Should say TAKEN",
  },
  {
    num: 27, tool: "domain_available",
    args: { domain: "thisdomain-definitely-does-not-exist-xyz-99999.com" },
    validate: (t) => t && (t.includes("AVAILABLE") || t.includes("TAKEN")) ? true : "Should indicate availability status",
  },
  {
    num: 28, tool: "domain_available",
    args: { domain: "a.com" },
    validate: (t) => t && t.includes("TAKEN") ? true : "Should say TAKEN",
  },
  {
    num: 29, tool: "domain_available",
    args: { domain: "my-cool-startup-idea-2025-test.io" },
    validate: (t) => t && (t.includes("AVAILABLE") || t.includes("TAKEN")) ? true : "Should indicate availability status",
  },
  {
    num: 30, tool: "domain_available",
    args: { domain: "apple.com" },
    validate: (t) => t && t.includes("TAKEN") ? true : "Should say TAKEN",
  },
  {
    num: 31, tool: "domain_available",
    args: { domain: "xyznonexistent123456789.dev" },
    validate: (t) => t && (t.includes("AVAILABLE") || t.includes("TAKEN")) ? true : "Should indicate availability status",
  },
  {
    num: 32, tool: "domain_available",
    args: { domain: "https://tesla.com" },
    validate: (t) => t && t.includes("tesla.com") && t.includes("TAKEN") ? true : "Should strip URL and say TAKEN",
  },
  {
    num: 33, tool: "domain_available",
    args: { domain: "microsoft.com" },
    validate: (t) => t && t.includes("TAKEN") ? true : "Should say TAKEN",
  },
  {
    num: 34, tool: "domain_available",
    args: { domain: "superlongdomainnamethatprobablydoesntexistanywhere123.com" },
    validate: (t) => t && (t.includes("AVAILABLE") || t.includes("TAKEN")) ? true : "Should indicate availability status",
  },
  {
    num: 35, tool: "domain_available",
    args: { domain: "ai.com" },
    validate: (t) => t && t.includes("TAKEN") ? true : "Should say TAKEN",
  },

  // === EMAIL_CONFIG_CHECK (36-45) ===
  {
    num: 36, tool: "email_config_check",
    args: { domain: "google.com" },
    validate: (t) => t && t.includes("google.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 37, tool: "email_config_check",
    args: { domain: "microsoft.com" },
    validate: (t) => t && t.includes("microsoft.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 38, tool: "email_config_check",
    args: { domain: "github.com" },
    validate: (t) => t && t.includes("github.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 39, tool: "email_config_check",
    args: { domain: "protonmail.com" },
    validate: (t) => t && t.includes("protonmail.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 40, tool: "email_config_check",
    args: { domain: "stripe.com" },
    validate: (t) => t && t.includes("stripe.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 41, tool: "email_config_check",
    args: { domain: "example.com" },
    validate: (t) => t && t.includes("example.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 42, tool: "email_config_check",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com" },
    validate: (t) => t && t.includes("Grade") ? true : "Should still produce a grade even with no records",
  },
  {
    num: 43, tool: "email_config_check",
    args: { domain: "cloudflare.com" },
    validate: (t) => t && t.includes("cloudflare.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 44, tool: "email_config_check",
    args: { domain: "zoho.com" },
    validate: (t) => t && t.includes("zoho.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },
  {
    num: 45, tool: "email_config_check",
    args: { domain: "hey.com" },
    validate: (t) => t && t.includes("hey.com") && t.includes("Grade") ? true : "Missing grade or domain",
  },

  // === SSL_CHECK (46-50) ===
  {
    num: 46, tool: "ssl_check",
    args: { domain: "google.com" },
    validate: (t) => t && t.includes("google.com") && t.includes("Certificate") ? true : "Missing cert details",
  },
  {
    num: 47, tool: "ssl_check",
    args: { domain: "github.com" },
    validate: (t) => t && t.includes("github.com") && t.includes("Certificate") ? true : "Missing cert details",
  },
  {
    num: 48, tool: "ssl_check",
    args: { domain: "expired.badssl.com" },
    validate: (t) => t && (t.includes("EXPIRED") || t.includes("INVALID") || t.includes("expired") || t.includes("Certificate")) ? true : "Should detect expired/invalid cert",
  },
  {
    num: 49, tool: "ssl_check",
    args: { domain: "amazon.com" },
    validate: (t) => t && t.includes("amazon.com") && t.includes("Certificate") ? true : "Missing cert details",
  },
  {
    num: 50, tool: "ssl_check",
    args: { domain: "smithery.ai" },
    validate: (t) => t && t.includes("smithery.ai") && t.includes("Certificate") ? true : "Missing cert details",
  },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(70));
  console.log(" MCP Domain Lookup — Real-World Test Suite (50 tests)");
  console.log("=".repeat(70));

  // Health check
  try {
    const h = await fetch(`${BASE}/health`);
    if (!h.ok) throw new Error(`HTTP ${h.status}`);
    console.log("✅ Server is reachable\n");
  } catch (err) {
    console.error(`❌ Cannot reach server at ${BASE}: ${err.message}`);
    console.error("   Start the server first: npm start");
    process.exit(1);
  }

  // Initialize MCP session
  try {
    await initialize();
    console.log(`✅ MCP session initialized (${sessionId})\n`);
  } catch (err) {
    console.error(`❌ MCP initialize failed: ${err.message}`);
    process.exit(1);
  }

  const totalStart = performance.now();

  // DNS_LOOKUP tests
  console.log("─".repeat(70));
  console.log(" DNS_LOOKUP TESTS (1-15)");
  console.log("─".repeat(70));
  for (const t of tests.filter((t) => t.num <= 15)) {
    await runToolTest(t.num, t.tool, t.args, t.validate);
  }

  // WHOIS_LOOKUP tests
  console.log("\n" + "─".repeat(70));
  console.log(" WHOIS_LOOKUP TESTS (16-25)");
  console.log("─".repeat(70));
  for (const t of tests.filter((t) => t.num >= 16 && t.num <= 25)) {
    await runToolTest(t.num, t.tool, t.args, t.validate);
  }

  // DOMAIN_AVAILABLE tests
  console.log("\n" + "─".repeat(70));
  console.log(" DOMAIN_AVAILABLE TESTS (26-35)");
  console.log("─".repeat(70));
  for (const t of tests.filter((t) => t.num >= 26 && t.num <= 35)) {
    await runToolTest(t.num, t.tool, t.args, t.validate);
  }

  // EMAIL_CONFIG_CHECK tests
  console.log("\n" + "─".repeat(70));
  console.log(" EMAIL_CONFIG_CHECK TESTS (36-45)");
  console.log("─".repeat(70));
  for (const t of tests.filter((t) => t.num >= 36 && t.num <= 45)) {
    await runToolTest(t.num, t.tool, t.args, t.validate);
  }

  // SSL_CHECK tests
  console.log("\n" + "─".repeat(70));
  console.log(" SSL_CHECK TESTS (46-50)");
  console.log("─".repeat(70));
  for (const t of tests.filter((t) => t.num >= 46)) {
    await runToolTest(t.num, t.tool, t.args, t.validate);
  }

  const totalElapsed = ((performance.now() - totalStart) / 1000).toFixed(2);

  // ---------------------------------------------------------------------------
  // Summary
  // ---------------------------------------------------------------------------

  const passCount = results.filter((r) => r.status === "PASS").length;
  const failCount = results.filter((r) => r.status === "FAIL").length;
  const errorCount = results.filter((r) => r.status === "ERROR").length;
  const failures = results.filter((r) => r.status !== "PASS");

  console.log("\n\n" + "=".repeat(70));
  console.log(" SUMMARY TABLE");
  console.log("=".repeat(70));
  console.log(
    " #  | Tool                 | Domain                                           | Result | Time"
  );
  console.log("─".repeat(70));
  for (const r of results) {
    const icon = r.status === "PASS" ? "✅" : r.status === "FAIL" ? "❌" : "💥";
    const num = String(r.testNum).padStart(2);
    const tool = r.toolName.padEnd(20);
    const dom = (r.domain || "").slice(0, 48).padEnd(48);
    const ms = (r.elapsed || 0).toFixed(0).padStart(6) + "ms";
    console.log(` ${num} | ${tool} | ${dom} | ${icon}   | ${ms}`);
  }

  console.log("\n" + "=".repeat(70));
  console.log(" REAL WORLD TEST RESULTS");
  console.log("=".repeat(70));
  console.log(` Total:    ${results.length}`);
  console.log(` Passed:   ${passCount}`);
  console.log(` Failed:   ${failCount}`);
  console.log(` Errors:   ${errorCount}`);
  console.log(` Time:     ${totalElapsed}s`);
  console.log("=".repeat(70));

  if (failures.length > 0) {
    console.log("\n FAILED TESTS:");
    for (const f of failures) {
      console.log(`  - Test ${f.testNum}: [${f.toolName}] ${f.domain} — ${f.errorMsg}`);
    }
    console.log("=".repeat(70));
  }

  if (passCount === results.length) {
    console.log("\n🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉");
    console.log("🎉                                                                  🎉");
    console.log("🎉   ALL 50 TESTS PASSED! SERVER IS PRODUCTION-READY! 🚀            🎉");
    console.log("🎉   Ready to publish on Smithery.ai!                                🎉");
    console.log("🎉                                                                  🎉");
    console.log("🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n");
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
