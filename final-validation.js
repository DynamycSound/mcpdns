#!/usr/bin/env node

// final-validation.js — 40-test comprehensive validation for MCP Domain Lookup
// Run: node final-validation.js

const BASE = "http://localhost:3000";
let sessionId = null;
let rpcId = 0;

// Store all tool responses for Phase 6 quality checks
const allToolResponses = [];

// ─── Helpers ────────────────────────────────────────────────────────────────

async function httpGet(path) {
  const res = await fetch(`${BASE}${path}`);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { }
  return { status: res.status, headers: res.headers, text, json };
}

async function rpc(method, params, id, timeoutMs = 30000) {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${BASE}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: controller.signal,
    });

    const sid = res.headers.get("mcp-session-id");
    if (sid) sessionId = sid;

    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/event-stream")) {
      const body = await res.text();
      for (const line of body.split("\n")) {
        if (line.startsWith("data: ")) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.id === id) return data;
          } catch { }
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
    clientInfo: { name: "final-validation", version: "1.0.0" },
  }, ++rpcId);
  if (!res.result) throw new Error("Initialize failed: " + JSON.stringify(res));

  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  return res;
}

async function callTool(name, args, timeoutMs = 30000) {
  const id = ++rpcId;
  const start = Date.now();
  const res = await rpc("tools/call", { name, arguments: args }, id, timeoutMs);
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  const text = res?.result?.content?.[0]?.text || "";
  allToolResponses.push({ name, args, response: res, text, elapsed: parseFloat(elapsed) });
  return { text, elapsed: parseFloat(elapsed), raw: res };
}

// ─── Test runner ────────────────────────────────────────────────────────────

const results = { passed: 0, failed: 0, failures: [] };
const phaseResults = {};
let currentPhase = "";

function startPhase(name) {
  currentPhase = name;
  phaseResults[name] = { passed: 0, failed: 0, total: 0 };
  console.log(`\n${"═".repeat(60)}`);
  console.log(` ${name}`);
  console.log(`${"═".repeat(60)}`);
}

function pass(num, name) {
  results.passed++;
  phaseResults[currentPhase].passed++;
  phaseResults[currentPhase].total++;
  console.log(`  ✅ Test ${num}: ${name}`);
}

function fail(num, name, expected, got, output) {
  results.failed++;
  phaseResults[currentPhase].failed++;
  phaseResults[currentPhase].total++;
  const entry = { num, name, expected, got, output: (output || "").slice(0, 300) };
  results.failures.push(entry);
  console.log(`  ❌ Test ${num}: ${name}`);
  console.log(`     Expected: ${expected}`);
  console.log(`     Got: ${got}`);
  if (output) console.log(`     Output (first 300 chars): ${output.slice(0, 300)}`);
}

// ─── Phase 1: Server Health & Metadata ──────────────────────────────────────

async function phase1() {
  startPhase("Phase 1: Server Health & Metadata");

  // Test 1: Health endpoint
  {
    const r = await httpGet("/health");
    if (r.status === 200 && r.json?.status === "ok" && r.json?.tools === 15) {
      pass(1, "Health endpoint");
    } else {
      fail(1, "Health endpoint", "200, status ok, 15 tools", `${r.status}, ${r.text}`);
    }
  }

  // Test 2: Root info endpoint
  {
    const r = await httpGet("/");
    const hasName = r.json?.name || r.json?.server;
    const hasVersion = r.json?.version;
    const hasTools = r.json?.toolCount === 15 || r.json?.tools?.length === 15;
    if (r.status === 200 && hasName && hasVersion && hasTools) {
      pass(2, "Root info endpoint");
    } else {
      fail(2, "Root info endpoint", "JSON with name, version, 15 tools", `${r.status}, tools=${r.json?.toolCount || r.json?.tools?.length}`, r.text);
    }
  }

  // Test 3: Server card completeness
  {
    const r = await httpGet("/.well-known/mcp/server-card.json");
    const checks = [];
    if (!r.json) { checks.push("invalid JSON"); }
    else {
      if (!r.json.name) checks.push("missing name");
      if (!r.json.version) checks.push("missing version");
      if (!r.json.tools || r.json.tools.length !== 15) checks.push(`tools count = ${r.json.tools?.length || 0}, expected 15`);

      const expectedTools = [
        "domain_report", "dns_lookup", "whois_lookup", "domain_available",
        "email_config_check", "ssl_check", "reverse_dns", "dns_propagation",
        "subdomain_finder", "http_headers_check", "redirect_chain",
        "tech_stack_detect", "domain_age", "dns_compare", "port_check"
      ];

      if (r.json.tools) {
        const toolNames = r.json.tools.map(t => t.name);
        for (const t of expectedTools) {
          if (!toolNames.includes(t)) checks.push(`missing tool: ${t}`);
        }
        for (const t of r.json.tools) {
          if (!t.name || !t.description) checks.push(`tool missing name/desc`);
          if (!t.inputSchema || t.inputSchema.type !== "object") checks.push(`${t.name} missing inputSchema`);
        }
        console.log(`     Tools: ${toolNames.join(", ")}`);
      }
    }

    if (checks.length === 0) {
      pass(3, "Server card completeness");
    } else {
      fail(3, "Server card completeness", "valid card with 15 tools", checks.join("; "), r.text);
    }
  }

  // Test 4: About page
  {
    const r = await httpGet("/about");
    const isHtml = r.headers.get("content-type")?.includes("text/html");
    if (r.status === 200 && isHtml) {
      pass(4, "About page");
    } else {
      fail(4, "About page", "200 with text/html", `${r.status}, ct=${r.headers.get("content-type")}`);
    }
  }

  // Test 5: MCP Initialize handshake
  {
    try {
      const res = await initialize();
      if (res.result && sessionId) {
        pass(5, "MCP Initialize handshake");
      } else {
        fail(5, "MCP Initialize handshake", "valid result + session", JSON.stringify(res).slice(0, 200));
      }
    } catch (e) {
      fail(5, "MCP Initialize handshake", "success", e.message);
    }
  }
}

// ─── Phase 2: Tools List ────────────────────────────────────────────────────

async function phase2() {
  startPhase("Phase 2: Tools List Verification");

  // Test 6: tools/list
  {
    const id = ++rpcId;
    const res = await rpc("tools/list", {}, id);
    const tools = res?.result?.tools || [];
    const checks = [];
    if (tools.length !== 15) checks.push(`expected 15 tools, got ${tools.length}`);
    const hasDomainReport = tools.some(t => t.name === "domain_report");
    if (!hasDomainReport) checks.push("missing domain_report");
    for (const t of tools) {
      if (!t.name || !t.description || !t.inputSchema) {
        checks.push(`${t.name || "?"} missing name/desc/schema`);
        break;
      }
    }
    if (checks.length === 0) {
      pass(6, `tools/list returns all 15 tools`);
      console.log(`     Tools: ${tools.map(t => t.name).join(", ")}`);
    } else {
      fail(6, "tools/list returns all 15 tools", "15 tools with full metadata", checks.join("; "));
    }
  }
}

// ─── Phase 3: All Tools — google.com ────────────────────────────────────────

async function phase3() {
  startPhase("Phase 3: All Tools — google.com");

  // Test 7: domain_report
  {
    const r = await callTool("domain_report", { domain: "google.com" }, 60000);
    const checks = [];
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address found");
    if (!/1997/.test(r.text)) checks.push("missing 1997 (registration year)");
    if (!/grade/i.test(r.text)) checks.push("missing Grade");
    if (!/ssl|certificate|🔒/i.test(r.text)) checks.push("missing SSL section");
    if (!/summary/i.test(r.text)) checks.push("missing Summary section");
    if (r.text.length < 500) checks.push(`too short (${r.text.length} chars)`);
    if (r.elapsed > 60) checks.push(`too slow (${r.elapsed}s)`);
    if (checks.length === 0) pass(7, `domain_report | google.com (${r.elapsed}s)`);
    else fail(7, "domain_report | google.com", "IP, 1997, Grade, SSL, Summary, >500ch, <60s", checks.join("; "), r.text);
  }

  // Test 8: dns_lookup ALL
  {
    const r = await callTool("dns_lookup", { domain: "google.com", record_type: "ALL" });
    const checks = [];
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address");
    if (!/MX/i.test(r.text)) checks.push("missing MX");
    if (!/NS/i.test(r.text)) checks.push("missing NS");
    if (!/TXT/i.test(r.text)) checks.push("missing TXT");
    if (checks.length === 0) pass(8, `dns_lookup ALL | google.com (${r.elapsed}s)`);
    else fail(8, "dns_lookup ALL | google.com", "IP, MX, NS, TXT", checks.join("; "), r.text);
  }

  // Test 9: whois_lookup
  {
    const r = await callTool("whois_lookup", { domain: "google.com" });
    const checks = [];
    if (!/1997/.test(r.text)) checks.push("missing 1997");
    if (!/registrar/i.test(r.text)) checks.push("missing Registrar");
    if (!/expir/i.test(r.text)) checks.push("missing Expir*");
    if (!/days/i.test(r.text)) checks.push("missing days");
    if (checks.length === 0) pass(9, `whois_lookup | google.com (${r.elapsed}s)`);
    else fail(9, "whois_lookup | google.com", "1997, Registrar, Expir, days", checks.join("; "), r.text);
  }

  // Test 10: domain_available
  {
    const r = await callTool("domain_available", { domain: "google.com" });
    const checks = [];
    if (!/taken/i.test(r.text)) checks.push("missing TAKEN");
    // Should not say "AVAILABLE" as the primary verdict for google.com
    if (/^\s*✅.*available/im.test(r.text)) checks.push("incorrectly says AVAILABLE");
    if (checks.length === 0) pass(10, `domain_available | google.com (${r.elapsed}s)`);
    else fail(10, "domain_available | google.com", "TAKEN, not AVAILABLE", checks.join("; "), r.text);
  }

  // Test 11: email_config_check
  {
    const r = await callTool("email_config_check", { domain: "google.com" });
    const checks = [];
    if (!/MX/i.test(r.text)) checks.push("missing MX");
    if (!/SPF/i.test(r.text)) checks.push("missing SPF");
    if (!/google|gmail/i.test(r.text)) checks.push("missing Google/gmail");
    if (!/grade/i.test(r.text)) checks.push("missing Grade");
    if (!/DMARC/i.test(r.text)) checks.push("missing DMARC");
    if (checks.length === 0) pass(11, `email_config_check | google.com (${r.elapsed}s)`);
    else fail(11, "email_config_check | google.com", "MX, SPF, Google, Grade, DMARC", checks.join("; "), r.text);
  }

  // Test 12: ssl_check
  {
    const r = await callTool("ssl_check", { domain: "google.com" });
    const checks = [];
    if (!/🟢/.test(r.text)) checks.push("missing 🟢");
    if (!/issuer/i.test(r.text)) checks.push("missing Issuer");
    if (!/days/i.test(r.text)) checks.push("missing days");
    if (/EXPIRED/i.test(r.text)) checks.push("incorrectly says EXPIRED");
    if (/🔴/.test(r.text)) checks.push("has 🔴 (should not)");
    if (checks.length === 0) pass(12, `ssl_check | google.com (${r.elapsed}s)`);
    else fail(12, "ssl_check | google.com", "🟢, Issuer, days, no EXPIRED/🔴", checks.join("; "), r.text);
  }

  // Test 13: reverse_dns
  {
    const r = await callTool("reverse_dns", { target: "google.com" });
    const checks = [];
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address");
    if (r.text.length < 20) checks.push("response too short");
    if (/^❌.*error$/im.test(r.text) && r.text.length < 50) checks.push("only error with no useful data");
    if (checks.length === 0) pass(13, `reverse_dns | google.com (${r.elapsed}s)`);
    else fail(13, "reverse_dns | google.com", "IP + hostname", checks.join("; "), r.text);
  }

  // Test 14: dns_propagation
  {
    const r = await callTool("dns_propagation", { domain: "google.com" });
    const checks = [];
    if (!/8\.8\.8\.8|google/i.test(r.text)) checks.push("missing Google resolver");
    if (!/1\.1\.1\.1|cloudflare/i.test(r.text)) checks.push("missing Cloudflare resolver");
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address");
    if (!/propagated|✅/i.test(r.text)) checks.push("missing propagation indicator");
    if (checks.length === 0) pass(14, `dns_propagation | google.com (${r.elapsed}s)`);
    else fail(14, "dns_propagation | google.com", "resolvers, IP, propagated", checks.join("; "), r.text);
  }

  // Test 15: subdomain_finder
  {
    const r = await callTool("subdomain_finder", { domain: "google.com" }, 60000);
    const checks = [];
    if (!/www/i.test(r.text)) checks.push("missing www");
    if (!/mail/i.test(r.text)) checks.push("missing mail");
    const foundMatch = r.text.match(/Found\s+\*?\*?(\d+)/i);
    if (!foundMatch || parseInt(foundMatch[1]) < 3) checks.push("fewer than 3 subdomains found");
    if (r.elapsed > 30) checks.push(`too slow (${r.elapsed}s)`);
    if (checks.length === 0) pass(15, `subdomain_finder | google.com (${r.elapsed}s)`);
    else fail(15, "subdomain_finder | google.com", "www, mail, ≥3 found, <30s", checks.join("; "), r.text);
  }

  // Test 16: http_headers_check
  {
    const r = await callTool("http_headers_check", { domain: "google.com" });
    const checks = [];
    if (!/grade/i.test(r.text)) checks.push("missing Grade");
    if (!/strict-transport-security|hsts/i.test(r.text)) checks.push("missing HSTS");
    if (!/✅/.test(r.text)) checks.push("missing ✅");
    if (!/\d+\/\d+/.test(r.text)) checks.push("missing score format");
    if (checks.length === 0) pass(16, `http_headers_check | google.com (${r.elapsed}s)`);
    else fail(16, "http_headers_check | google.com", "Grade, HSTS, ✅, score", checks.join("; "), r.text);
  }

  // Test 17: redirect_chain
  {
    const r = await callTool("redirect_chain", { url: "http://google.com" });
    const checks = [];
    if (!/301|302|redirect/i.test(r.text)) checks.push("missing redirect status");
    // Google may redirect to http://www.google.com (www redirect) or https (HTTPS upgrade) — both are valid
    if (!/https|www/i.test(r.text)) checks.push("missing https or www redirect");
    if (!/final|destination|200|✅/i.test(r.text)) checks.push("missing final destination");
    if (checks.length === 0) pass(17, `redirect_chain | http://google.com (${r.elapsed}s)`);
    else fail(17, "redirect_chain | http://google.com", "301/302, https or www redirect, final destination", checks.join("; "), r.text);
  }

  // Test 18: tech_stack_detect
  {
    const r = await callTool("tech_stack_detect", { domain: "google.com" });
    const checks = [];
    if (!/google|gws|gfe/i.test(r.text)) checks.push("missing Google/gws/GFE");
    if (r.text.length < 30) checks.push("too short — no technologies detected");
    if (/no technologies/i.test(r.text) && !/could not/i.test(r.text)) checks.push("says no technologies");
    if (checks.length === 0) pass(18, `tech_stack_detect | google.com (${r.elapsed}s)`);
    else fail(18, "tech_stack_detect | google.com", "Google/gws/GFE, technologies", checks.join("; "), r.text);
  }

  // Test 19: domain_age
  {
    const r = await callTool("domain_age", { domain: "google.com" });
    const checks = [];
    if (!/1997/.test(r.text)) checks.push("missing 1997");
    if (!/2[789]|30/.test(r.text)) checks.push("missing age in years (27-30)");
    if (checks.length === 0) pass(19, `domain_age | google.com (${r.elapsed}s)`);
    else fail(19, "domain_age | google.com", "1997, 27-30 years", checks.join("; "), r.text);
  }

  // Test 20: dns_compare
  {
    const r = await callTool("dns_compare", { domain1: "google.com", domain2: "bing.com" });
    const checks = [];
    if (!/google\.com/i.test(r.text)) checks.push("missing google.com");
    if (!/bing\.com/i.test(r.text)) checks.push("missing bing.com");
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address");
    if (!/MX|NS|A/i.test(r.text)) checks.push("missing record type");
    if (checks.length === 0) pass(20, `dns_compare | google.com vs bing.com (${r.elapsed}s)`);
    else fail(20, "dns_compare", "both domains, IP, record types", checks.join("; "), r.text);
  }

  // Test 21: port_check
  {
    const r = await callTool("port_check", { domain: "google.com", ports: "80,443" });
    const checks = [];
    if (!/80/.test(r.text)) checks.push("missing port 80");
    if (!/443/.test(r.text)) checks.push("missing port 443");
    if (!/open/i.test(r.text) && !/✅/.test(r.text)) checks.push("no open indicator");
    if (!/\d+\s+open/i.test(r.text) && !/Results/.test(r.text)) checks.push("missing summary");
    if (checks.length === 0) pass(21, `port_check | google.com 80,443 (${r.elapsed}s)`);
    else fail(21, "port_check | google.com", "80+443 open, summary", checks.join("; "), r.text);
  }
}

// ─── Phase 4: Edge Cases — expired.badssl.com ───────────────────────────────

async function phase4() {
  startPhase("Phase 4: Edge Cases — expired.badssl.com");

  // Test 22: ssl_check — expired cert
  {
    const r = await callTool("ssl_check", { domain: "expired.badssl.com" });
    const checks = [];
    if (!/expired/i.test(r.text)) checks.push("missing EXPIRED");
    if (!/🔴/.test(r.text)) checks.push("missing 🔴");
    if (/🟢/.test(r.text)) checks.push("has 🟢 (should not)");
    if (checks.length === 0) pass(22, `ssl_check | expired.badssl.com — expired cert (${r.elapsed}s)`);
    else fail(22, "ssl_check | expired.badssl.com", "EXPIRED, 🔴, no 🟢", checks.join("; "), r.text);
  }

  // Test 23: dns_lookup A — expired.badssl.com
  {
    const r = await callTool("dns_lookup", { domain: "expired.badssl.com", record_type: "A" });
    const checks = [];
    if (!/\d+\.\d+\.\d+\.\d+/.test(r.text)) checks.push("no IP address");
    if (/no records found/i.test(r.text)) checks.push("says no records found");
    if (checks.length === 0) pass(23, `dns_lookup A | expired.badssl.com (${r.elapsed}s)`);
    else fail(23, "dns_lookup A | expired.badssl.com", "IP address present", checks.join("; "), r.text);
  }

  // Test 24: http_headers_check — graceful handling
  {
    const r = await callTool("http_headers_check", { domain: "expired.badssl.com" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace in output");
    if (checks.length === 0) pass(24, `http_headers_check | expired.badssl.com — no crash (${r.elapsed}s)`);
    else fail(24, "http_headers_check | expired.badssl.com", "non-empty, no stack trace", checks.join("; "), r.text);
  }

  // Test 25: tech_stack_detect — graceful handling
  {
    const r = await callTool("tech_stack_detect", { domain: "expired.badssl.com" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace in output");
    if (checks.length === 0) pass(25, `tech_stack_detect | expired.badssl.com — no crash (${r.elapsed}s)`);
    else fail(25, "tech_stack_detect | expired.badssl.com", "non-empty, no stack trace", checks.join("; "), r.text);
  }

  // Test 26: redirect_chain — graceful handling
  {
    const r = await callTool("redirect_chain", { url: "https://expired.badssl.com" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace in output");
    if (checks.length === 0) pass(26, `redirect_chain | expired.badssl.com — no crash (${r.elapsed}s)`);
    else fail(26, "redirect_chain | expired.badssl.com", "non-empty, no stack trace", checks.join("; "), r.text);
  }
}

// ─── Phase 5: Error Handling ────────────────────────────────────────────────

async function phase5() {
  startPhase("Phase 5: Error Handling");

  // Test 27: dns_lookup with garbage input
  {
    const r = await callTool("dns_lookup", { domain: "not a domain at all!!! @#$%" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace");
    if (checks.length === 0) pass(27, `dns_lookup garbage input — no crash (${r.elapsed}s)`);
    else fail(27, "dns_lookup garbage input", "error message, no crash", checks.join("; "), r.text);
  }

  // Test 28: whois_lookup with IP address
  {
    const r = await callTool("whois_lookup", { domain: "8.8.8.8" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace");
    if (checks.length === 0) pass(28, `whois_lookup IP address — no crash (${r.elapsed}s)`);
    else fail(28, "whois_lookup IP address", "works or helpful error", checks.join("; "), r.text);
  }

  // Test 29: domain_report with empty string
  {
    const r = await callTool("domain_report", { domain: "" }, 60000);
    const checks = [];
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace");
    // Even if text is empty, as long as no crash it's acceptable
    if (checks.length === 0) pass(29, `domain_report empty string — no crash (${r.elapsed}s)`);
    else fail(29, "domain_report empty string", "error message, no crash", checks.join("; "), r.text);
  }

  // Test 30: dns_compare with same domain twice
  {
    const r = await callTool("dns_compare", { domain1: "google.com", domain2: "google.com" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace");
    if (checks.length === 0) pass(30, `dns_compare same domain — no crash (${r.elapsed}s)`);
    else fail(30, "dns_compare same domain", "shows results or handles gracefully", checks.join("; "), r.text);
  }

  // Test 31: port_check with custom ports
  {
    const r = await callTool("port_check", { domain: "google.com", ports: "80,443,8080" });
    const checks = [];
    if (!/80/.test(r.text)) checks.push("missing port 80");
    if (!/443/.test(r.text)) checks.push("missing port 443");
    if (!/8080/.test(r.text)) checks.push("missing port 8080");
    if (checks.length === 0) pass(31, `port_check custom ports 80,443,8080 (${r.elapsed}s)`);
    else fail(31, "port_check custom ports", "results for all 3 ports", checks.join("; "), r.text);
  }

  // Test 32: reverse_dns with actual IP
  {
    const r = await callTool("reverse_dns", { target: "8.8.8.8" });
    const checks = [];
    if (!/dns\.google|google/i.test(r.text)) checks.push("missing dns.google hostname");
    if (checks.length === 0) pass(32, `reverse_dns 8.8.8.8 → dns.google (${r.elapsed}s)`);
    else fail(32, "reverse_dns 8.8.8.8", "dns.google or google hostname", checks.join("; "), r.text);
  }

  // Test 33: dns_propagation with nonexistent domain
  {
    const r = await callTool("dns_propagation", { domain: "this-domain-absolutely-does-not-exist-xyz-99999.com" });
    const checks = [];
    if (!r.text || r.text.length === 0) checks.push("empty response");
    if (/at Object\.|at Module\.|node_modules/i.test(r.text)) checks.push("stack trace");
    if (checks.length === 0) pass(33, `dns_propagation nonexistent domain — no crash (${r.elapsed}s)`);
    else fail(33, "dns_propagation nonexistent", "no crash, shows resolver results", checks.join("; "), r.text);
  }
}

// ─── Phase 6: Response Quality ──────────────────────────────────────────────

async function phase6() {
  startPhase("Phase 6: Response Quality");

  // Test 34: All responses have correct MCP structure
  {
    let correct = 0;
    let incorrect = 0;
    const issues = [];
    for (const r of allToolResponses) {
      const raw = r.response;
      if (raw?.jsonrpc !== "2.0") { incorrect++; issues.push(`${r.name}: missing jsonrpc 2.0`); continue; }
      if (!raw?.result?.content || !Array.isArray(raw.result.content)) { incorrect++; issues.push(`${r.name}: missing content array`); continue; }
      if (raw.result.content[0]?.type !== "text") { incorrect++; issues.push(`${r.name}: content[0].type != text`); continue; }
      if (typeof raw.result.content[0]?.text !== "string" || raw.result.content[0].text.length === 0) { incorrect++; issues.push(`${r.name}: empty text`); continue; }
      correct++;
    }
    if (incorrect === 0) {
      pass(34, `All ${correct} tool responses have correct MCP structure`);
    } else {
      fail(34, "MCP structure", `${allToolResponses.length} correct`, `${correct} correct, ${incorrect} incorrect: ${issues.slice(0, 3).join("; ")}`);
    }
  }

  // Test 35: No stack traces or internal paths
  {
    const leaks = [];
    for (const r of allToolResponses) {
      const t = r.text;
      if (/at Object\./i.test(t)) leaks.push(`${r.name}: "at Object." stack trace`);
      if (/at Module\./i.test(t)) leaks.push(`${r.name}: "at Module." stack trace`);
      if (/node_modules\//i.test(t)) leaks.push(`${r.name}: node_modules path`);
      if (/C:\\Apps\\|C:\/Apps\//i.test(t)) leaks.push(`${r.name}: local file path`);
      if (/SUPABASE/i.test(t)) leaks.push(`${r.name}: Supabase reference`);
    }
    if (leaks.length === 0) {
      pass(35, `No stack traces or internal paths in any response`);
    } else {
      fail(35, "No data leaks", "0 leaks", `${leaks.length} leaks: ${leaks.slice(0, 3).join("; ")}`);
    }
  }

  // Test 36: Emoji formatting consistency (domain_report for google.com)
  {
    const reportResponse = allToolResponses.find(r => r.name === "domain_report" && r.args?.domain === "google.com");
    if (!reportResponse) {
      fail(36, "Emoji formatting", "domain_report output", "domain_report response not found");
    } else {
      const t = reportResponse.text;
      const checks = [];
      // Count unique emojis
      const emojiMatches = t.match(/[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu) || [];
      const uniqueEmojis = new Set(emojiMatches);
      if (uniqueEmojis.size < 3) checks.push(`only ${uniqueEmojis.size} unique emojis (need ≥3)`);

      const checkmarks = (t.match(/✅/g) || []).length;
      if (checkmarks < 2) checks.push(`only ${checkmarks} ✅ marks (need ≥2)`);

      if (!/[ABCDEF]/.test(t)) checks.push("no grade letter A-F");
      if (!/═/.test(t)) checks.push("no ═ section dividers");

      if (checks.length === 0) pass(36, `Emoji formatting consistent (${uniqueEmojis.size} emojis, ${checkmarks} ✅)`);
      else fail(36, "Emoji formatting", "≥3 emojis, ≥2 ✅, grade, dividers", checks.join("; "));
    }
  }
}

// ─── Phase 7: Responsible Usage Verification ────────────────────────────────

async function phase7() {
  startPhase("Phase 7: Responsible Usage Verification");

  // Test 37: Subdomain finder doesn't check too many prefixes
  {
    const r = await callTool("subdomain_finder", { domain: "example.com" }, 30000);
    const checks = [];
    if (r.elapsed > 20) checks.push(`took ${r.elapsed}s (max 20s)`);
    const prefixMatch = r.text.match(/Checking\s+(\d+)\s+common/i);
    if (prefixMatch) {
      const count = parseInt(prefixMatch[1]);
      if (count > 100) checks.push(`checking ${count} prefixes (max 100)`);
      if (checks.length === 0) pass(37, `subdomain_finder — ${count} prefixes, ${r.elapsed}s (responsible)`);
      else fail(37, "subdomain_finder limits", "<100 prefixes, <20s", checks.join("; "), r.text);
    } else {
      if (r.elapsed <= 20) pass(37, `subdomain_finder — ${r.elapsed}s (responsible, prefix count not shown)`);
      else fail(37, "subdomain_finder limits", "<20s", `took ${r.elapsed}s`, r.text);
    }
  }

  // Test 38: Port check only scans limited ports
  {
    const r = await callTool("port_check", { domain: "google.com" });
    const checks = [];
    // Extract all port numbers from the output
    const portNumbers = [...r.text.matchAll(/^(\d+)\s+│/gm)].map(m => parseInt(m[1]));
    if (portNumbers.some(p => p > 10000)) checks.push(`port above 10000 found: ${portNumbers.filter(p => p > 10000).join(", ")}`);
    if (portNumbers.length > 20) checks.push(`too many ports checked (${portNumbers.length})`);
    if (r.elapsed > 30) checks.push(`took ${r.elapsed}s (max 30s)`);
    if (checks.length === 0) pass(38, `port_check defaults — ${portNumbers.length} ports, <10000, ${r.elapsed}s`);
    else fail(38, "port_check limits", "<20 ports, none >10000, <30s", checks.join("; "), r.text);
  }

  // Test 39: Redirect chain has max redirect limit
  {
    const r = await callTool("redirect_chain", { url: "http://google.com" });
    const checks = [];
    // Count hops
    const hopMatches = r.text.match(/→|Hop|redirect/gi) || [];
    if (hopMatches.length > 15) checks.push(`too many hops (${hopMatches.length})`);
    if (r.elapsed > 15) checks.push(`took ${r.elapsed}s (should not hang)`);
    if (checks.length === 0) pass(39, `redirect_chain — max limit respected, ${r.elapsed}s`);
    else fail(39, "redirect_chain limits", "≤15 hops, no hanging", checks.join("; "), r.text);
  }

  // Test 40: Tech stack detect doesn't download excessive data
  {
    const r = await callTool("tech_stack_detect", { domain: "google.com" });
    const checks = [];
    if (r.elapsed > 10) checks.push(`took ${r.elapsed}s (max 10s)`);
    if (r.text.length > 5000) checks.push(`response ${r.text.length} chars (max 5000)`);
    if (checks.length === 0) pass(40, `tech_stack_detect — ${r.text.length} chars, ${r.elapsed}s (responsible)`);
    else fail(40, "tech_stack_detect limits", "<10s, <5000 chars", checks.join("; "), r.text);
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log(`${"═".repeat(60)}`);
  console.log(` FINAL VALIDATION — MCP Domain Lookup`);
  console.log(` ${new Date().toISOString()}`);
  console.log(`${"═".repeat(60)}`);

  const totalStart = Date.now();

  try {
    await phase1();
    await phase2();
    await phase3();
    await phase4();
    await phase5();
    await phase6();
    await phase7();
  } catch (e) {
    console.error(`\n💥 FATAL ERROR: ${e.message}`);
    console.error(e.stack);
  }

  const totalElapsed = ((Date.now() - totalStart) / 1000).toFixed(1);

  // ─── Final Summary ──────────────────────────────────────────────────────

  console.log(`\n${"═".repeat(60)}`);
  console.log(` FINAL VALIDATION RESULTS`);
  console.log(`${"═".repeat(60)}`);

  for (const [name, r] of Object.entries(phaseResults)) {
    const icon = r.failed === 0 ? "✅" : "❌";
    console.log(` ${name.padEnd(42)} ${r.passed}/${r.total}  ${icon}`);
  }

  const total = results.passed + results.failed;
  console.log(`${"═".repeat(60)}`);
  console.log(` TOTAL: ${results.passed}/${total} passed    (${totalElapsed}s)`);
  console.log(`${"═".repeat(60)}`);

  if (results.failures.length > 0) {
    console.log(`\n${"─".repeat(60)}`);
    console.log(` FAILURES:`);
    console.log(`${"─".repeat(60)}`);
    for (const f of results.failures) {
      console.log(`  ❌ Test ${f.num}: ${f.name}`);
      console.log(`     Expected: ${f.expected}`);
      console.log(`     Got: ${f.got}`);
      if (f.output) console.log(`     Output: ${f.output}`);
      console.log();
    }
  }

  console.log();
  if (results.failed === 0) {
    console.log(`${"═".repeat(60)}`);
    console.log(` 🎉 ALL ${total} TESTS PASSED!`);
    console.log(`${"═".repeat(60)}`);
    console.log(` ✅ All 15 tools working correctly`);
    console.log(` ✅ Error handling is solid (no crashes)`);
    console.log(` ✅ No data leaks or stack traces`);
    console.log(` ✅ Responsible usage verified (no aggressive scanning)`);
    console.log(` ✅ Server card valid for Smithery scanning`);
    console.log(` ✅ MCP protocol handshake works`);
    console.log();
    console.log(` 🚀 READY TO DEPLOY AND PUBLISH ON SMITHERY.AI`);
    console.log(`${"═".repeat(60)}`);
  } else {
    console.log(`${"═".repeat(60)}`);
    console.log(` ❌ ${results.failed} TEST(S) FAILED — FIX BEFORE PUBLISHING`);
    console.log(`${"═".repeat(60)}`);
  }

  process.exit(results.failed > 0 ? 1 : 0);
}

main();
