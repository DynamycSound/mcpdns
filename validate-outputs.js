// Content Validation Test Suite — Deep output inspection
// Run with: node validate-outputs.js
// Requires server running on http://localhost:3000

const BASE = "http://localhost:3000";
const TIMEOUT_MS = 15000;

let sessionId = null;
let rpcId = 200;
let totalChecks = 0;
let correctChecks = 0;
let wrongChecks = 0;
const failedTests = [];

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
      clientInfo: { name: "validate-outputs", version: "1.0.0" },
    },
    1
  );
  if (!res.result) throw new Error("Initialize failed: " + JSON.stringify(res));
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

async function callTool(toolName, args) {
  const id = ++rpcId;
  const res = await rpc("tools/call", { name: toolName, arguments: args }, id);
  if (res.error) return { text: null, error: res.error.message || JSON.stringify(res.error) };
  const text = res.result?.content?.[0]?.text || "";
  return { text, error: null };
}

// ---------------------------------------------------------------------------
// Validation engine
// ---------------------------------------------------------------------------

function mustContain(text, pattern, label) {
  totalChecks++;
  if (typeof pattern === "string") {
    if (text.toLowerCase().includes(pattern.toLowerCase())) {
      correctChecks++;
      return { pass: true, msg: `✓ Contains "${pattern}"` };
    }
    wrongChecks++;
    return { pass: false, msg: `✗ MISSING: "${pattern}" — ${label}` };
  }
  // regex
  if (pattern.test(text)) {
    correctChecks++;
    return { pass: true, msg: `✓ Matches ${pattern}` };
  }
  wrongChecks++;
  return { pass: false, msg: `✗ MISSING: ${pattern} — ${label}` };
}

function mustContainAny(text, patterns, label) {
  totalChecks++;
  for (const p of patterns) {
    if (typeof p === "string" && text.toLowerCase().includes(p.toLowerCase())) {
      correctChecks++;
      return { pass: true, msg: `✓ Contains "${p}"` };
    }
    if (p instanceof RegExp && p.test(text)) {
      correctChecks++;
      return { pass: true, msg: `✓ Matches ${p}` };
    }
  }
  wrongChecks++;
  return { pass: false, msg: `✗ MISSING: any of [${patterns.join(", ")}] — ${label}` };
}

function mustNotContain(text, pattern, label) {
  totalChecks++;
  if (typeof pattern === "string") {
    if (!text.toLowerCase().includes(pattern.toLowerCase())) {
      correctChecks++;
      return { pass: true, msg: `✓ Does not contain "${pattern}"` };
    }
    wrongChecks++;
    return { pass: false, msg: `✗ WRONG: Contains "${pattern}" — ${label}` };
  }
  if (!pattern.test(text)) {
    correctChecks++;
    return { pass: true, msg: `✓ Does not match ${pattern}` };
  }
  wrongChecks++;
  return { pass: false, msg: `✗ WRONG: Matches ${pattern} — ${label}` };
}

function gradeMustBe(text, allowedGrades, label) {
  totalChecks++;
  const gradeMatch = text.match(/Grade:\s*([A-F])/i);
  if (!gradeMatch) {
    wrongChecks++;
    return { pass: false, msg: `✗ WRONG: No grade found — ${label}` };
  }
  const grade = gradeMatch[1].toUpperCase();
  if (allowedGrades.includes(grade)) {
    correctChecks++;
    return { pass: true, msg: `✓ Grade is "${grade}" (expected ${allowedGrades.join(" or ")})` };
  }
  wrongChecks++;
  return { pass: false, msg: `✗ WRONG: Grade is "${grade}" but expected ${allowedGrades.join(" or ")} — ${label}` };
}

const IP_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

// ---------------------------------------------------------------------------
// Test definitions
// ---------------------------------------------------------------------------

const validationTests = [
  // === DNS_LOOKUP ===
  {
    num: 1,
    tool: "dns_lookup",
    args: { domain: "google.com", record_type: "ALL" },
    checks: (text) => [
      mustContain(text, IP_PATTERN, "should contain at least one IP address"),
      mustContain(text, "MX", "Google has mail servers"),
      mustContain(text, "NS", "Google has nameservers"),
    ],
  },
  {
    num: 2,
    tool: "dns_lookup",
    args: { domain: "github.com", record_type: "A" },
    checks: (text) => [
      mustContain(text, IP_PATTERN, "should contain at least one IP address"),
      mustNotContain(text, "No records found", "GitHub A records should exist"),
    ],
  },
  {
    num: 3,
    tool: "dns_lookup",
    args: { domain: "microsoft.com", record_type: "MX" },
    checks: (text) => [
      mustContain(text, "MX", "should mention MX"),
      mustContainAny(text, ["outlook", "microsoft"], "should show Microsoft mail servers"),
    ],
  },
  {
    num: 6,
    tool: "dns_lookup",
    args: { domain: "https://www.reddit.com/r/programming", record_type: "ALL" },
    checks: (text) => [
      mustContain(text, IP_PATTERN, "URL should be stripped, should find IP addresses"),
      mustContain(text, "reddit.com", "should query reddit.com after stripping"),
    ],
  },
  {
    num: 9,
    tool: "dns_lookup",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com", record_type: "ALL" },
    checks: (text) => [
      mustContainAny(text, ["No records found", "no records", "❌"], "should indicate no records"),
      mustNotContain(text, IP_PATTERN, "should NOT contain any IP address"),
    ],
  },
  {
    num: 14,
    tool: "dns_lookup",
    args: { domain: "google.com", record_type: "INVALIDTYPE" },
    checks: (text, error) => {
      // This test may return a JSON-RPC error (Zod validation) or a text error
      if (error) {
        totalChecks++;
        correctChecks++;
        return [{ pass: true, msg: `✓ Returned error for invalid type: "${error.slice(0, 80)}"` }];
      }
      return [
        mustContainAny(text, ["invalid", "unknown", "not supported", "error", "❌"], "should indicate invalid record type"),
      ];
    },
  },

  // === WHOIS_LOOKUP ===
  {
    num: 16,
    tool: "whois_lookup",
    args: { domain: "google.com" },
    checks: (text) => [
      mustContain(text, "1997", "Google was registered in 1997"),
      mustContain(text, /registrar/i, "should show registrar info"),
      mustContain(text, /expir/i, "should show expiry info"),
      mustContain(text, "days", "should show days remaining calculation"),
    ],
  },
  {
    num: 17,
    tool: "whois_lookup",
    args: { domain: "github.com" },
    checks: (text) => [
      mustContain(text, "2007", "GitHub was registered in 2007"),
    ],
  },
  {
    num: 21,
    tool: "whois_lookup",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com" },
    checks: (text) => {
      // Should not show a real registrar — either shows error or minimal data
      // The key is it should NOT crash and should NOT show fake registrar data
      totalChecks++;
      const hasRegistrar = /Registrar:\*\*\s+(?!Unknown)/.test(text);
      if (!hasRegistrar) {
        correctChecks++;
        return [{ pass: true, msg: "✓ Does not show a real registrar for nonexistent domain" }];
      }
      wrongChecks++;
      return [{ pass: false, msg: "✗ WRONG: Shows registrar data for a nonexistent domain" }];
    },
  },
  {
    num: 22,
    tool: "whois_lookup",
    args: { domain: "facebook.com" },
    checks: (text) => [
      mustContain(text, "1997", "facebook.com was registered in 1997"),
    ],
  },
  {
    num: 25,
    tool: "whois_lookup",
    args: { domain: "x.com" },
    checks: (text) => [
      mustContain(text, /registrar/i, "should have valid WHOIS data"),
    ],
  },

  // === DOMAIN_AVAILABLE ===
  {
    num: 26,
    tool: "domain_available",
    args: { domain: "google.com" },
    checks: (text) => [
      mustContain(text, "TAKEN", "google.com should be taken"),
      mustNotContain(text, /\bAPPEARS to be\b.*\bAVAILABLE\b/i, "should NOT say available"),
    ],
  },
  {
    num: 27,
    tool: "domain_available",
    args: { domain: "thisdomain-definitely-does-not-exist-xyz-99999.com" },
    checks: (text) => [
      mustContain(text, "AVAILABLE", "nonexistent domain should be available"),
      mustNotContain(text, /is\s+\*\*TAKEN\*\*/i, "should NOT say taken"),
    ],
  },
  {
    num: 28,
    tool: "domain_available",
    args: { domain: "a.com" },
    checks: (text) => [
      mustContain(text, "TAKEN", "a.com should be taken"),
    ],
  },
  {
    num: 30,
    tool: "domain_available",
    args: { domain: "apple.com" },
    checks: (text) => [
      mustContain(text, "TAKEN", "apple.com should be taken"),
      mustContainAny(text, ["alternatives", ".io", ".co", ".dev", ".net", ".org"], "should suggest alternative TLDs"),
    ],
  },
  {
    num: 32,
    tool: "domain_available",
    args: { domain: "https://tesla.com" },
    checks: (text) => [
      mustContain(text, "tesla.com", "URL should be stripped to tesla.com"),
      mustContain(text, "TAKEN", "tesla.com should be taken"),
    ],
  },
  {
    num: 35,
    tool: "domain_available",
    args: { domain: "ai.com" },
    checks: (text) => [
      mustContain(text, "TAKEN", "ai.com should be taken"),
    ],
  },

  // === EMAIL_CONFIG_CHECK ===
  {
    num: 36,
    tool: "email_config_check",
    args: { domain: "google.com" },
    checks: (text) => [
      mustContain(text, "MX", "Google has mail servers"),
      mustContain(text, "SPF", "Google has SPF record"),
      mustContainAny(text, ["Google", "gmail"], "should detect Google as provider"),
      mustContain(text, "Grade", "should show grade"),
      gradeMustBe(text, ["A", "B"], "Google should have strong email security"),
    ],
  },
  {
    num: 37,
    tool: "email_config_check",
    args: { domain: "microsoft.com" },
    checks: (text) => [
      mustContain(text, "MX", "Microsoft has mail servers"),
      mustContainAny(text, ["Microsoft", "outlook"], "should detect Microsoft as provider"),
    ],
  },
  {
    num: 39,
    tool: "email_config_check",
    args: { domain: "protonmail.com" },
    checks: (text) => [
      mustContain(text, "MX", "ProtonMail has mail servers"),
      mustContain(text, /proton/i, "should detect ProtonMail as provider"),
    ],
  },
  {
    num: 41,
    tool: "email_config_check",
    args: { domain: "example.com" },
    checks: (text) => [
      mustContain(text, "Grade", "should still produce a grade for reserved domain"),
    ],
  },
  {
    num: 42,
    tool: "email_config_check",
    args: { domain: "nonexistent-domain-xyz-abc-12345.com" },
    checks: (text) => [
      mustContain(text, "Grade", "should produce a grade"),
      gradeMustBe(text, ["F", "D"], "nonexistent domain should score poorly"),
      mustContain(text, "❌", "should show failing checks"),
    ],
  },
  {
    num: 44,
    tool: "email_config_check",
    args: { domain: "zoho.com" },
    checks: (text) => [
      mustContain(text, /zoho/i, "should detect Zoho as email provider"),
    ],
  },

  // === SSL_CHECK ===
  {
    num: 46,
    tool: "ssl_check",
    args: { domain: "google.com" },
    checks: (text) => [
      mustContain(text, /issuer/i, "should show certificate issuer"),
      mustContain(text, "days", "should show expiry days calculation"),
      mustContain(text, "🟢", "valid cert should show green"),
    ],
  },
  {
    num: 47,
    tool: "ssl_check",
    args: { domain: "github.com" },
    checks: (text) => [
      mustContain(text, "🟢", "valid cert should show green"),
      mustNotContain(text, "EXPIRED", "GitHub cert should NOT be expired"),
    ],
  },
  {
    num: 48,
    tool: "ssl_check",
    args: { domain: "expired.badssl.com" },
    checks: (text) => [
      mustContainAny(text, ["EXPIRED", "expired"], "should detect expired certificate"),
      mustContain(text, "🔴", "expired cert should show red"),
      mustNotContain(text, /🟢\s*\*\*Status/, "should NOT show green status"),
    ],
  },
  {
    num: 49,
    tool: "ssl_check",
    args: { domain: "amazon.com" },
    checks: (text) => [
      mustContain(text, "🟢", "valid cert should show green"),
      mustContain(text, /issuer/i, "should show certificate issuer"),
    ],
  },
  {
    num: 50,
    tool: "ssl_check",
    args: { domain: "smithery.ai" },
    checks: (text) => [
      mustContain(text, "🟢", "valid cert should show green"),
    ],
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function runValidation(test) {
  const { num, tool, args } = test;
  const domain = args.domain || "";

  let text, error;
  try {
    const result = await callTool(tool, args);
    text = result.text;
    error = result.error;
  } catch (err) {
    console.log(`  💥 Test ${num}: [${tool}] ${domain} — EXCEPTION: ${err.message}`);
    totalChecks++;
    wrongChecks++;
    failedTests.push({ num, tool, domain, reason: `Exception: ${err.message}` });
    return;
  }

  const results = test.checks(text || "", error);
  const allPassed = results.every((r) => r.pass);

  if (allPassed) {
    console.log(`  ✅ Test ${String(num).padStart(2)}: [${tool}] ${domain} — ALL CHECKS PASSED`);
    for (const r of results) console.log(`     ${r.msg}`);
  } else {
    console.log(`  ❌ Test ${String(num).padStart(2)}: [${tool}] ${domain} — FAILED`);
    for (const r of results) console.log(`     ${r.msg}`);
    // Show actual output for debugging
    const preview = (text || error || "(empty)").slice(0, 500);
    console.log(`     📄 Actual output (first 500 chars):`);
    for (const line of preview.split("\n")) {
      console.log(`        ${line}`);
    }
    const reasons = results.filter((r) => !r.pass).map((r) => r.msg);
    failedTests.push({ num, tool, domain, reason: reasons.join("; ") });
  }
  console.log();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(70));
  console.log(" MCP Domain Lookup — Content Validation Suite");
  console.log(" Verifying ACTUAL CONTENT of tool responses");
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

  // DNS_LOOKUP validations
  console.log("─".repeat(70));
  console.log(" DNS_LOOKUP CONTENT VALIDATIONS");
  console.log("─".repeat(70));
  for (const t of validationTests.filter((t) => t.tool === "dns_lookup")) {
    await runValidation(t);
  }

  // WHOIS_LOOKUP validations
  console.log("─".repeat(70));
  console.log(" WHOIS_LOOKUP CONTENT VALIDATIONS");
  console.log("─".repeat(70));
  for (const t of validationTests.filter((t) => t.tool === "whois_lookup")) {
    await runValidation(t);
  }

  // DOMAIN_AVAILABLE validations
  console.log("─".repeat(70));
  console.log(" DOMAIN_AVAILABLE CONTENT VALIDATIONS");
  console.log("─".repeat(70));
  for (const t of validationTests.filter((t) => t.tool === "domain_available")) {
    await runValidation(t);
  }

  // EMAIL_CONFIG_CHECK validations
  console.log("─".repeat(70));
  console.log(" EMAIL_CONFIG_CHECK CONTENT VALIDATIONS");
  console.log("─".repeat(70));
  for (const t of validationTests.filter((t) => t.tool === "email_config_check")) {
    await runValidation(t);
  }

  // SSL_CHECK validations
  console.log("─".repeat(70));
  console.log(" SSL_CHECK CONTENT VALIDATIONS");
  console.log("─".repeat(70));
  for (const t of validationTests.filter((t) => t.tool === "ssl_check")) {
    await runValidation(t);
  }

  // Summary
  console.log("\n" + "=".repeat(70));
  console.log(" CONTENT VALIDATION RESULTS");
  console.log("=".repeat(70));
  console.log(` Total checks:    ${totalChecks}`);
  console.log(` Correct:         ${correctChecks}`);
  console.log(` Wrong:           ${wrongChecks}`);
  console.log("=".repeat(70));

  if (failedTests.length > 0) {
    console.log("\n FAILED VALIDATIONS:");
    for (const f of failedTests) {
      console.log(`  - Test ${f.num}: [${f.tool}] ${f.domain} — ${f.reason}`);
    }
    console.log("=".repeat(70));
    console.log("\n❌ FIX THESE BEFORE PUBLISHING\n");
  } else {
    console.log("\n✅ Server outputs are VERIFIED CORRECT — safe to publish\n");
  }

  process.exit(failedTests.length > 0 ? 1 : 0);
}

main();
