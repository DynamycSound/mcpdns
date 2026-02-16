#!/usr/bin/env node
// Test with API key — Comprehensive domain intelligence on 2 websites
// Usage: node test-with-api-key.js

const BASE = "http://localhost:3000";
const TIMEOUT_MS = 30000;
const API_KEY = "dk_live_b682c3135e57bc290c47965df6878db4";

// Test domains
const DOMAINS = ["stripe.com", "github.com"];

let sessionId = null;
let rpcId = 100;

async function rpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "x-api-key": API_KEY,
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

    // Capture rate limit headers
    const rateLimitHeaders = {
      limit: res.headers.get("x-ratelimit-limit"),
      remaining: res.headers.get("x-ratelimit-remaining"),
      reset: res.headers.get("x-ratelimit-reset"),
    };

    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream")) {
      const text = await res.text();
      for (const line of text.split("\n")) {
        if (line.startsWith("data: ")) {
          const data = JSON.parse(line.slice(6));
          if (data.id === id) return { ...data, rateLimitHeaders };
        }
      }
      throw new Error("No matching response in SSE stream");
    }
    const json = await res.json();
    return { ...json, rateLimitHeaders };
  } finally {
    clearTimeout(timer);
  }
}

async function initialize() {
  const res = await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "api-key-test", version: "1.0.0" },
  }, 1);
  if (!res.result) throw new Error("Initialize failed");
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "x-api-key": API_KEY };
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
  if (res.error) return { text: null, error: res.error.message, rateLimitHeaders: res.rateLimitHeaders };
  return { text: res.result?.content?.[0]?.text || "", error: null, rateLimitHeaders: res.rateLimitHeaders };
}

async function main() {
  console.log("=".repeat(70));
  console.log(" COMPREHENSIVE DOMAIN INTELLIGENCE TEST (with API Key)");
  console.log("=".repeat(70));
  console.log(` API Key: ${API_KEY.slice(0, 16)}...`);
  console.log(` Testing: ${DOMAINS.join(", ")}`);
  console.log("=".repeat(70) + "\n");

  // Initialize
  await initialize();
  console.log("✅ Session initialized\n");

  // Check usage first
  console.log("─".repeat(70));
  console.log(" USAGE CHECK");
  console.log("─".repeat(70));
  const usageRes = await callTool("usage_check", { api_key: API_KEY });
  console.log(usageRes.text || "❌ Failed to get usage");
  console.log();

  // For each domain, run comprehensive checks
  for (const domain of DOMAINS) {
    console.log("=".repeat(70));
    console.log(` DOMAIN: ${domain.toUpperCase()}`);
    console.log("=".repeat(70) + "\n");

    // 1. Domain Report (flagship — combines DNS, WHOIS, email, SSL, headers, tech, age)
    console.log("─".repeat(70));
    console.log(" 1. DOMAIN REPORT (flagship — all checks in one)");
    console.log("─".repeat(70));
    const reportRes = await callTool("domain_report", { domain });
    if (reportRes.error) {
      console.log(`❌ Error: ${reportRes.error}`);
    } else {
      console.log(reportRes.text);
    }
    console.log();

    // 2. DNS Lookup (detailed)
    console.log("─".repeat(70));
    console.log(" 2. DNS RECORDS (detailed)");
    console.log("─".repeat(70));
    const dnsRes = await callTool("dns_lookup", { domain, type: "A" });
    console.log(dnsRes.text || dnsRes.error);
    console.log();

    // 3. WHOIS Lookup
    console.log("─".repeat(70));
    console.log(" 3. WHOIS REGISTRATION DATA");
    console.log("─".repeat(70));
    const whoisRes = await callTool("whois_lookup", { domain });
    console.log(whoisRes.text || whoisRes.error);
    console.log();

    // 4. SSL Certificate
    console.log("─".repeat(70));
    console.log(" 4. SSL/TLS CERTIFICATE");
    console.log("─".repeat(70));
    const sslRes = await callTool("ssl_check", { domain });
    console.log(sslRes.text || sslRes.error);
    console.log();

    // 5. Email Security
    console.log("─".repeat(70));
    console.log(" 5. EMAIL SECURITY (MX/SPF/DKIM/DMARC)");
    console.log("─".repeat(70));
    const emailRes = await callTool("email_config_check", { domain });
    console.log(emailRes.text || emailRes.error);
    console.log();

    // 6. HTTP Security Headers
    console.log("─".repeat(70));
    console.log(" 6. HTTP SECURITY HEADERS AUDIT");
    console.log("─".repeat(70));
    const headersRes = await callTool("http_headers_check", { domain });
    console.log(headersRes.text || headersRes.error);
    console.log();

    // 7. Tech Stack Detection
    console.log("─".repeat(70));
    console.log(" 7. TECHNOLOGY STACK DETECTION");
    console.log("─".repeat(70));
    const techRes = await callTool("tech_stack_detect", { domain });
    console.log(techRes.text || techRes.error);
    console.log();

    // 8. Domain Age
    console.log("─".repeat(70));
    console.log(" 8. DOMAIN AGE CALCULATION");
    console.log("─".repeat(70));
    const ageRes = await callTool("domain_age", { domain });
    console.log(ageRes.text || ageRes.error);
    console.log();

    // 9. Subdomain Finder
    console.log("─".repeat(70));
    console.log(" 9. SUBDOMAIN DISCOVERY");
    console.log("─".repeat(70));
    const subRes = await callTool("subdomain_finder", { domain });
    console.log(subRes.text || subRes.error);
    console.log();

    // 10. Port Check
    console.log("─".repeat(70));
    console.log(" 10. PORT SCANNING (common ports)");
    console.log("─".repeat(70));
    const portRes = await callTool("port_check", { domain, ports: "80,443,22,25,53,587,993,995" });
    console.log(portRes.text || portRes.error);
    console.log();

    // 11. DNS Propagation
    console.log("─".repeat(70));
    console.log(" 11. DNS PROPAGATION (8 global resolvers)");
    console.log("─".repeat(70));
    const propRes = await callTool("dns_propagation", { domain });
    console.log(propRes.text || propRes.error);
    console.log();

    // 12. Redirect Chain
    console.log("─".repeat(70));
    console.log(" 12. REDIRECT CHAIN");
    console.log("─".repeat(70));
    const redirectRes = await callTool("redirect_chain", { url: `http://${domain}` });
    console.log(redirectRes.text || redirectRes.error);
    console.log();
  }

  // Final usage check
  console.log("=".repeat(70));
  console.log(" FINAL USAGE CHECK");
  console.log("=".repeat(70));
  const finalUsage = await callTool("usage_check", { api_key: API_KEY });
  console.log(finalUsage.text || "❌ Failed to get usage");
  console.log();

  console.log("=".repeat(70));
  console.log(" TEST COMPLETE");
  console.log("=".repeat(70));
}

main().catch(err => {
  console.error("Fatal:", err);
  process.exit(1);
});
