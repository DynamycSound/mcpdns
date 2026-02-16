import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import dns from "dns";
import tls from "tls";
import net from "net";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import whoisJson from "whois-json";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const resolver = new dns.promises.Resolver();

function cleanDomain(input) {
  let d = input.trim();
  d = d.replace(/^https?:\/\//i, "");
  d = d.replace(/\/.*$/, "");
  d = d.replace(/:\d+$/, "");
  return d.toLowerCase();
}

async function resolveDns(domain, type) {
  try {
    const records = await resolver.resolve(domain, type);
    return records;
  } catch {
    return null;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function whoisWithRetry(domain, maxRetries = 2) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const data = await whoisJson(domain);
      const rec = Array.isArray(data) ? data[0] : data;
      // Detect sparse/rate-limited response: has domainName but no registrar or dates
      const hasMeaningfulData =
        rec.registrar || rec.Registrar ||
        rec.creationDate || rec.createdDate || rec.created ||
        rec.registrarRegistrationExpirationDate || rec.expirationDate || rec.expiryDate;
      if (hasMeaningfulData || attempt === maxRetries) {
        return rec;
      }
      // Sparse response — likely rate-limited, wait and retry
      await sleep(1500 * (attempt + 1));
    } catch (err) {
      if (attempt === maxRetries) throw err;
      await sleep(1500 * (attempt + 1));
    }
  }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function dnsLookup(domain, recordType) {
  domain = cleanDomain(domain);
  const types = recordType === "ALL" ? ["A", "AAAA", "MX", "TXT", "NS", "CNAME"] : [recordType];
  const lines = [`🔍 DNS Lookup for **${domain}**\n`];

  for (const t of types) {
    const records = await resolveDns(domain, t);
    if (!records) {
      lines.push(`❌ ${t}: No records found`);
      continue;
    }
    if (t === "MX") {
      const sorted = records.sort((a, b) => a.priority - b.priority);
      lines.push(`✅ ${t} Records:`);
      sorted.forEach((r) => lines.push(`   Priority ${r.priority} → ${r.exchange}`));
    } else if (t === "TXT") {
      lines.push(`✅ ${t} Records:`);
      records.forEach((r) => {
        const val = Array.isArray(r) ? r.join("") : r;
        lines.push(`   ${val}`);
      });
    } else {
      lines.push(`✅ ${t} Records:`);
      records.forEach((r) => lines.push(`   ${r}`));
    }
  }
  return lines.join("\n");
}

async function whoisLookup(domain) {
  domain = cleanDomain(domain);
  const lines = [`🔍 WHOIS Lookup for **${domain}**\n`];
  try {
    const rec = await whoisWithRetry(domain);

    const registrar = rec.registrar || rec.Registrar || "Unknown";
    const createdRaw = rec.creationDate || rec.createdDate || rec.created || rec.CreationDate || null;
    const expiryRaw = rec.registrarRegistrationExpirationDate || rec.expirationDate || rec.expiryDate || rec.expires || rec.ExpirationDate || null;
    const updatedRaw = rec.updatedDate || rec.lastUpdated || rec.UpdatedDate || null;
    const status = rec.domainStatus || rec.status || rec.Status || "Unknown";
    const nameServers = rec.nameServer || rec.nameServers || rec.NameServer || null;

    lines.push(`📋 **Registrar:** ${registrar}`);

    if (createdRaw) {
      const created = new Date(createdRaw);
      lines.push(`📅 **Created:** ${created.toISOString().split("T")[0]}`);
    }

    if (expiryRaw) {
      const expiry = new Date(expiryRaw);
      const now = new Date();
      const daysRemaining = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
      let indicator;
      if (daysRemaining < 0) indicator = "🔴 EXPIRED";
      else if (daysRemaining <= 30) indicator = "🔴 EXPIRING VERY SOON";
      else if (daysRemaining <= 90) indicator = "🟡 Expiring soon";
      else indicator = "🟢 OK";
      lines.push(`📅 **Expires:** ${expiry.toISOString().split("T")[0]} (${daysRemaining} days remaining) ${indicator}`);
    }

    if (updatedRaw) {
      const updated = new Date(updatedRaw);
      lines.push(`📅 **Updated:** ${updated.toISOString().split("T")[0]}`);
    }

    if (status) {
      const statuses = Array.isArray(status) ? status : [status];
      lines.push(`📌 **Status:** ${statuses.map((s) => s.toString().split(" ")[0]).join(", ")}`);
    }

    if (nameServers) {
      const ns = Array.isArray(nameServers) ? nameServers : [nameServers];
      lines.push(`🌐 **Name Servers:** ${ns.join(", ")}`);
    }
  } catch (err) {
    lines.push(`❌ WHOIS lookup failed: ${err.message}`);
  }
  return lines.join("\n");
}

async function domainAvailable(domain) {
  domain = cleanDomain(domain);
  const lines = [`🔍 Domain Availability Check for **${domain}**\n`];

  // Fast check: try DNS first
  let taken = false;
  const aRecords = await resolveDns(domain, "A");
  const aaaaRecords = await resolveDns(domain, "AAAA");
  if (aRecords || aaaaRecords) {
    taken = true;
  }

  // Fallback: WHOIS
  if (!taken) {
    try {
      const rec = await whoisWithRetry(domain, 1);
      if (rec && (rec.domainName || rec.domain || rec.registrar || rec.Registrar || rec.created || rec.source)) {
        taken = true;
      }
    } catch {
      // WHOIS failure — treat as potentially available
    }
  }

  if (!taken) {
    lines.push(`✅ **${domain}** appears to be **AVAILABLE** for registration!`);
  } else {
    lines.push(`❌ **${domain}** is **TAKEN**.\n`);

    // Suggest alternatives
    const base = domain.split(".")[0];
    const alts = [".com", ".net", ".org", ".io", ".co", ".dev", ".app", ".xyz", ".info", ".me"];
    const suggestions = [];
    for (const tld of alts) {
      const alt = base + tld;
      if (alt === domain) continue;
      const altA = await resolveDns(alt, "A");
      if (!altA) suggestions.push(alt);
      if (suggestions.length >= 5) break;
    }
    if (suggestions.length > 0) {
      lines.push(`💡 **Potentially available alternatives:**`);
      suggestions.forEach((s) => lines.push(`   🟢 ${s}`));
    } else {
      lines.push(`💡 No obvious alternative TLDs appear available for "${base}".`);
    }
  }
  return lines.join("\n");
}

const EMAIL_PROVIDERS = [
  { pattern: /google|gmail|googlemail/i, name: "Google Workspace" },
  { pattern: /outlook|microsoft|hotmail/i, name: "Microsoft 365" },
  { pattern: /zoho/i, name: "Zoho Mail" },
  { pattern: /protonmail|proton/i, name: "ProtonMail" },
  { pattern: /mimecast/i, name: "Mimecast" },
  { pattern: /barracuda/i, name: "Barracuda" },
  { pattern: /messagelabs|symantec/i, name: "Symantec/Broadcom" },
];

const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"];

async function emailConfigCheck(domain) {
  domain = cleanDomain(domain);
  const lines = [`📧 Email Configuration Audit for **${domain}**\n`];
  let score = 0;
  const maxScore = 4; // MX, SPF, DKIM, DMARC

  // --- MX ---
  const mxRecords = await resolveDns(domain, "MX");
  if (mxRecords && mxRecords.length > 0) {
    score++;
    const sorted = mxRecords.sort((a, b) => a.priority - b.priority);
    lines.push(`✅ **MX Records Found** (${sorted.length}):`);
    sorted.forEach((r) => lines.push(`   Priority ${r.priority} → ${r.exchange}`));
    // Detect provider
    const allExchanges = sorted.map((r) => r.exchange).join(" ");
    for (const ep of EMAIL_PROVIDERS) {
      if (ep.pattern.test(allExchanges)) {
        lines.push(`   📌 Detected provider: **${ep.name}**`);
        break;
      }
    }
  } else {
    lines.push(`❌ **No MX Records** — this domain cannot receive email`);
  }

  // --- SPF ---
  lines.push("");
  const txtRecords = await resolveDns(domain, "TXT");
  let spfFound = false;
  if (txtRecords) {
    for (const rec of txtRecords) {
      const val = Array.isArray(rec) ? rec.join("") : rec;
      if (val.startsWith("v=spf1")) {
        spfFound = true;
        score++;
        lines.push(`✅ **SPF Record Found:**`);
        lines.push(`   ${val}`);
        if (val.includes("-all")) {
          lines.push(`   🟢 Strict policy (-all) — good`);
        } else if (val.includes("~all")) {
          lines.push(`   🟡 Soft-fail policy (~all) — acceptable`);
        } else if (val.includes("?all")) {
          lines.push(`   🟡 Neutral policy (?all) — weak`);
        } else if (val.includes("+all")) {
          lines.push(`   🔴 Permissive policy (+all) — **dangerous**, allows any sender`);
        }
        break;
      }
    }
  }
  if (!spfFound) {
    lines.push(`❌ **No SPF Record** — vulnerable to email spoofing`);
  }

  // --- DKIM ---
  lines.push("");
  let dkimFound = false;
  const dkimResults = [];
  for (const sel of DKIM_SELECTORS) {
    const dkimDomain = `${sel}._domainkey.${domain}`;
    const dkimTxt = await resolveDns(dkimDomain, "TXT");
    if (dkimTxt) {
      dkimFound = true;
      dkimResults.push(sel);
    }
  }
  if (dkimFound) {
    score++;
    lines.push(`✅ **DKIM Records Found** (selectors: ${dkimResults.join(", ")}):`);
    dkimResults.forEach((sel) => lines.push(`   🟢 ${sel}._domainkey.${domain}`));
  } else {
    lines.push(`❌ **No DKIM Records** found for common selectors (${DKIM_SELECTORS.join(", ")})`);
    lines.push(`   ⚠️ DKIM may use custom selectors not checked here`);
  }

  // --- DMARC ---
  lines.push("");
  const dmarcDomain = `_dmarc.${domain}`;
  const dmarcTxt = await resolveDns(dmarcDomain, "TXT");
  let dmarcFound = false;
  if (dmarcTxt) {
    for (const rec of dmarcTxt) {
      const val = Array.isArray(rec) ? rec.join("") : rec;
      if (val.startsWith("v=DMARC1")) {
        dmarcFound = true;
        score++;
        lines.push(`✅ **DMARC Record Found:**`);
        lines.push(`   ${val}`);
        if (/p=reject/i.test(val)) {
          lines.push(`   🟢 Policy: reject — strongest protection`);
        } else if (/p=quarantine/i.test(val)) {
          lines.push(`   🟡 Policy: quarantine — good`);
        } else if (/p=none/i.test(val)) {
          lines.push(`   🟡 Policy: none — monitoring only, no protection`);
        }
        break;
      }
    }
  }
  if (!dmarcFound) {
    lines.push(`❌ **No DMARC Record** — no policy to protect against spoofing`);
  }

  // --- Grade ---
  lines.push("");
  let grade, emoji;
  if (score === 4) { grade = "A"; emoji = "🟢"; }
  else if (score === 3) { grade = "B"; emoji = "🟢"; }
  else if (score === 2) { grade = "C"; emoji = "🟡"; }
  else if (score === 1) { grade = "D"; emoji = "🟡"; }
  else { grade = "F"; emoji = "🔴"; }

  lines.push(`${emoji} **Overall Email Security Grade: ${grade}** (${score}/${maxScore})`);
  if (score < 4) {
    const missing = [];
    if (!mxRecords || mxRecords.length === 0) missing.push("MX");
    if (!spfFound) missing.push("SPF");
    if (!dkimFound) missing.push("DKIM");
    if (!dmarcFound) missing.push("DMARC");
    lines.push(`⚠️ Missing: ${missing.join(", ")}`);
  }

  return lines.join("\n");
}

async function sslCheck(domain) {
  domain = cleanDomain(domain);
  const lines = [`🔒 SSL/TLS Certificate Check for **${domain}**\n`];

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      sock.destroy();
      lines.push(`❌ SSL check timed out after 10 seconds`);
      resolve(lines.join("\n"));
    }, 10000);

    const sock = tls.connect(443, domain, { rejectUnauthorized: false, servername: domain }, () => {
      clearTimeout(timeout);

      const cert = sock.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        lines.push(`❌ No SSL certificate found for ${domain}`);
        sock.end();
        resolve(lines.join("\n"));
        return;
      }

      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
      const isExpired = daysRemaining < 0;
      const authorized = sock.authorized;

      // Status
      if (isExpired) {
        lines.push(`🔴 **Status: EXPIRED** (expired ${Math.abs(daysRemaining)} days ago)`);
      } else if (!authorized) {
        lines.push(`🟡 **Status: INVALID** — certificate exists but is not trusted`);
      } else {
        lines.push(`🟢 **Status: VALID**`);
      }

      // Subject
      lines.push(`\n📋 **Certificate Details:**`);
      lines.push(`   **Common Name:** ${cert.subject?.CN || "N/A"}`);

      // SANs
      if (cert.subjectaltname) {
        const sans = cert.subjectaltname.split(", ").map((s) => s.replace("DNS:", ""));
        lines.push(`   **Alt Names:** ${sans.join(", ")}`);
      }

      // Issuer
      const issuerOrg = cert.issuer?.O || cert.issuer?.CN || "Unknown";
      lines.push(`   **Issuer:** ${issuerOrg}`);

      // Dates
      lines.push(`   **Valid From:** ${validFrom.toISOString().split("T")[0]}`);
      lines.push(`   **Valid To:** ${validTo.toISOString().split("T")[0]}`);

      // Days remaining with color
      let indicator;
      if (isExpired) {
        indicator = `🔴 EXPIRED ${Math.abs(daysRemaining)} days ago`;
      } else if (daysRemaining <= 14) {
        indicator = `🔴 ${daysRemaining} days remaining — RENEW IMMEDIATELY`;
      } else if (daysRemaining <= 30) {
        indicator = `🟡 ${daysRemaining} days remaining — renew soon`;
      } else if (daysRemaining <= 60) {
        indicator = `🟡 ${daysRemaining} days remaining`;
      } else {
        indicator = `🟢 ${daysRemaining} days remaining`;
      }
      lines.push(`   **Expiry:** ${indicator}`);

      // Protocol
      lines.push(`   **Protocol:** ${sock.getProtocol?.() || "N/A"}`);

      // Serial
      if (cert.serialNumber) {
        lines.push(`   **Serial:** ${cert.serialNumber}`);
      }

      // Fingerprint
      if (cert.fingerprint256) {
        lines.push(`   **Fingerprint (SHA-256):** ${cert.fingerprint256}`);
      }

      sock.end();
      resolve(lines.join("\n"));
    });

    sock.on("error", (err) => {
      clearTimeout(timeout);
      lines.push(`❌ SSL check failed: ${err.message}`);
      resolve(lines.join("\n"));
    });
  });
}

// ---------------------------------------------------------------------------
// New tool implementations (tools 6–15)
// ---------------------------------------------------------------------------

const IP_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

async function reverseDns(target) {
  target = target.trim();
  const lines = [`🔄 Reverse DNS Lookup for **${target}**\n`];

  const ipsToReverse = [];

  if (IP_REGEX.test(target)) {
    ipsToReverse.push(target);
  } else {
    const domain = cleanDomain(target);
    lines.push(`Resolving **${domain}** to IP addresses first…\n`);
    const aRecs = await resolveDns(domain, "A");
    const aaaaRecs = await resolveDns(domain, "AAAA");
    if (aRecs) aRecs.forEach((ip) => ipsToReverse.push(ip));
    if (aaaaRecs) aaaaRecs.forEach((ip) => ipsToReverse.push(ip));
    if (ipsToReverse.length === 0) {
      lines.push(`❌ Could not resolve ${domain} to any IP address`);
      return lines.join("\n");
    }
    lines.push(`Found ${ipsToReverse.length} IP(s): ${ipsToReverse.join(", ")}\n`);
  }

  for (const ip of ipsToReverse) {
    try {
      const hostnames = await new Promise((resolve, reject) => {
        dns.reverse(ip, (err, hosts) => (err ? reject(err) : resolve(hosts)));
      });
      lines.push(`✅ **${ip}** → ${hostnames.join(", ")}`);
      // Forward-confirmed check
      for (const host of hostnames) {
        const fwd = await resolveDns(host, "A");
        if (fwd && fwd.includes(ip)) {
          lines.push(`   🟢 Forward-confirmed: ${host} → ${ip} ✓`);
        } else {
          lines.push(`   🟡 Forward mismatch: ${host} does not resolve back to ${ip}`);
        }
      }
    } catch {
      lines.push(`❌ **${ip}** → No reverse DNS (PTR) record found`);
    }
  }

  return lines.join("\n");
}

const PUBLIC_RESOLVERS = [
  { name: "Google", ip: "8.8.8.8" },
  { name: "Google Alt", ip: "8.8.4.4" },
  { name: "Cloudflare", ip: "1.1.1.1" },
  { name: "Cloudflare Alt", ip: "1.0.0.1" },
  { name: "OpenDNS", ip: "208.67.222.222" },
  { name: "Quad9", ip: "9.9.9.9" },
  { name: "AdGuard", ip: "94.140.14.14" },
  { name: "CleanBrowsing", ip: "185.228.168.9" },
];

async function dnsPropagation(domain, recordType = "A") {
  domain = cleanDomain(domain);
  const lines = [`🌍 DNS Propagation Check for **${domain}** (${recordType})\n`];
  const results = [];

  const queries = PUBLIC_RESOLVERS.map(async (r) => {
    const res = new dns.Resolver();
    res.setServers([r.ip]);
    try {
      const records = await new Promise((resolve, reject) => {
        const method = recordType === "AAAA" ? "resolve6" : "resolve4";
        res[method](domain, (err, addrs) => (err ? reject(err) : resolve(addrs)));
      });
      return { ...r, records: records.sort(), status: "ok" };
    } catch {
      return { ...r, records: [], status: "fail" };
    }
  });

  const all = await Promise.allSettled(queries);
  for (const a of all) {
    if (a.status === "fulfilled") results.push(a.value);
  }

  // Table
  const pad = (s, n) => String(s).padEnd(n);
  lines.push(`${pad("Resolver", 28)} │ ${pad("Result", 40)} │ Status`);
  lines.push(`${"─".repeat(28)}─┼─${"─".repeat(40)}─┼─${"─".repeat(8)}`);

  const answerSets = new Set();
  for (const r of results) {
    const ip = r.records.length > 0 ? r.records.join(", ") : "(no response)";
    const icon = r.status === "ok" ? "✅" : "❌";
    lines.push(`${pad(`${r.name} (${r.ip})`, 28)} │ ${pad(ip, 40)} │ ${icon}`);
    if (r.records.length > 0) answerSets.add(r.records.join(","));
  }

  lines.push("");
  const okCount = results.filter((r) => r.status === "ok").length;
  if (okCount === 0) {
    lines.push(`❌ **NOT PROPAGATED** — no resolver returned results`);
  } else if (answerSets.size === 1) {
    lines.push(`✅ **FULLY PROPAGATED** — all ${okCount} resolvers return the same answer`);
  } else {
    lines.push(`⚠️ **PARTIALLY PROPAGATED** — ${answerSets.size} different answers across ${okCount} resolvers`);
  }

  return lines.join("\n");
}

const SUBDOMAIN_PREFIXES = [
  "www", "mail", "ftp", "admin", "blog", "shop", "store", "api", "dev", "staging",
  "test", "beta", "app", "portal", "secure", "vpn", "remote", "webmail", "email",
  "cloud", "cdn", "media", "static", "assets", "img", "images", "video", "docs",
  "wiki", "help", "support", "status", "monitor", "dashboard", "panel", "cpanel",
  "ns1", "ns2", "mx", "smtp", "imap", "pop", "autodiscover", "calendar",
  "git", "gitlab", "jenkins", "ci", "deploy", "build",
  "db", "mysql", "postgres", "redis", "mongo", "elastic",
  "auth", "login", "sso", "oauth", "accounts", "id",
  "m", "mobile",
  "staging", "preprod", "uat", "qa", "sandbox",
  "old", "new", "v2", "legacy", "archive",
  "search", "analytics", "tracking", "ads", "marketing",
];

const SUBDOMAIN_CATEGORIES = {
  "📧 Email & Communication": ["mail", "webmail", "email", "smtp", "imap", "pop", "mx", "autodiscover", "calendar"],
  "🖥️ Web & Apps": ["www", "app", "portal", "m", "mobile", "blog", "shop", "store", "secure"],
  "🔧 Development & CI/CD": ["dev", "staging", "test", "beta", "preprod", "uat", "qa", "sandbox", "git", "gitlab", "jenkins", "ci", "deploy", "build"],
  "⚙️ Infrastructure": ["cdn", "media", "static", "assets", "img", "images", "video", "ns1", "ns2", "cloud", "ftp", "vpn", "remote"],
  "🛠️ Admin & Monitoring": ["admin", "panel", "cpanel", "dashboard", "monitor", "status", "analytics", "tracking"],
  "💾 Databases": ["db", "mysql", "postgres", "redis", "mongo", "elastic"],
  "🔐 Auth & Identity": ["auth", "login", "sso", "oauth", "accounts", "id"],
  "📚 Content": ["docs", "wiki", "help", "support", "search", "ads", "marketing"],
  "📦 Legacy / Versioned": ["old", "new", "v2", "legacy", "archive"],
};

async function subdomainFinder(domain) {
  domain = cleanDomain(domain);
  const lines = [`🔍 Subdomain Discovery: **${domain}**\n`];
  const unique = [...new Set(SUBDOMAIN_PREFIXES)];
  lines.push(`Checking ${unique.length} common prefixes…\n`);

  const found = [];
  const CONCURRENCY = 10;

  for (let i = 0; i < unique.length; i += CONCURRENCY) {
    const batch = unique.slice(i, i + CONCURRENCY);
    const tasks = batch.map(async (prefix) => {
      const sub = `${prefix}.${domain}`;
      const a = await resolveDns(sub, "A");
      if (a && a.length > 0) return { prefix, subdomain: sub, ips: a };
      return null;
    });
    const results = await Promise.allSettled(tasks);
    for (const r of results) {
      if (r.status === "fulfilled" && r.value) found.push(r.value);
    }
  }

  if (found.length === 0) {
    lines.push(`❌ No common subdomains found for ${domain}`);
    return lines.join("\n");
  }

  lines.push(`✅ Found **${found.length}** subdomains:\n`);

  const foundPrefixes = new Set(found.map((f) => f.prefix));

  for (const [category, prefixes] of Object.entries(SUBDOMAIN_CATEGORIES)) {
    const matching = found.filter((f) => prefixes.includes(f.prefix));
    if (matching.length === 0) continue;
    lines.push(`${category}:`);
    for (const m of matching) {
      lines.push(`   ${m.subdomain.padEnd(35)} → ${m.ips.join(", ")}`);
    }
    lines.push("");
  }

  // Any uncategorized
  const allCategorized = new Set(Object.values(SUBDOMAIN_CATEGORIES).flat());
  const uncategorized = found.filter((f) => !allCategorized.has(f.prefix));
  if (uncategorized.length > 0) {
    lines.push(`📌 Other:`);
    for (const m of uncategorized) {
      lines.push(`   ${m.subdomain.padEnd(35)} → ${m.ips.join(", ")}`);
    }
    lines.push("");
  }

  lines.push(`📊 ${found.length}/${unique.length} subdomains found`);
  return lines.join("\n");
}

const CRITICAL_HEADERS = [
  { name: "Strict-Transport-Security", points: 2, tip: "Add HSTS to enforce HTTPS connections" },
  { name: "Content-Security-Policy", points: 2, tip: "Add CSP to prevent XSS and injection attacks" },
  { name: "X-Content-Type-Options", points: 2, tip: 'Add "nosniff" to prevent MIME-type sniffing' },
  { name: "X-Frame-Options", points: 2, tip: "Add to prevent clickjacking (DENY or SAMEORIGIN)" },
];

const IMPORTANT_HEADERS = [
  { name: "Referrer-Policy", points: 1, tip: "Add to control referrer information leakage" },
  { name: "Permissions-Policy", points: 1, tip: "Add to control browser feature access" },
  { name: "X-XSS-Protection", points: 1, tip: "Add legacy XSS protection header" },
  { name: "Cross-Origin-Opener-Policy", points: 1, tip: "Add to isolate browsing context" },
  { name: "Cross-Origin-Resource-Policy", points: 1, tip: "Add to control cross-origin resource loading" },
  { name: "Cross-Origin-Embedder-Policy", points: 1, tip: "Add to control cross-origin embedding" },
];

async function httpHeadersCheck(domain) {
  domain = cleanDomain(domain);
  const url = `https://${domain}`;
  const lines = [`🛡️ HTTP Security Headers Audit: **${domain}**\n`];

  let res;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "MCP-Domain-Lookup/1.0" },
    });
    clearTimeout(timer);
  } catch (err) {
    lines.push(`❌ Could not connect to ${url}: ${err.message}`);
    return lines.join("\n");
  }

  let score = 0;
  const maxScore = CRITICAL_HEADERS.reduce((s, h) => s + h.points, 0) + IMPORTANT_HEADERS.reduce((s, h) => s + h.points, 0);

  const checkHeader = (header, hdrs) => {
    const val = hdrs.get(header.name.toLowerCase());
    if (val) {
      score += header.points;
      return { present: true, value: val };
    }
    return { present: false };
  };

  lines.push(`**CRITICAL HEADERS:**`);
  for (const h of CRITICAL_HEADERS) {
    const result = checkHeader(h, res.headers);
    if (result.present) {
      lines.push(`✅ **${h.name}:** ${result.value}`);
    } else {
      lines.push(`❌ **${h.name}:** MISSING`);
      lines.push(`   💡 ${h.tip}`);
    }
  }

  lines.push(`\n**IMPORTANT HEADERS:**`);
  for (const h of IMPORTANT_HEADERS) {
    const result = checkHeader(h, res.headers);
    if (result.present) {
      lines.push(`✅ **${h.name}:** ${result.value}`);
    } else {
      lines.push(`❌ **${h.name}:** MISSING`);
      lines.push(`   💡 ${h.tip}`);
    }
  }

  // Information leakage
  lines.push(`\n**INFORMATION LEAKAGE:**`);
  const server = res.headers.get("server");
  if (server) {
    const hasVersion = /\/[\d.]+/.test(server);
    if (hasVersion) {
      lines.push(`⚠️ **Server:** ${server} — reveals version number!`);
      lines.push(`   💡 Remove version from Server header`);
    } else {
      lines.push(`ℹ️ **Server:** ${server}`);
    }
  } else {
    lines.push(`✅ **Server:** Not disclosed`);
  }

  const powered = res.headers.get("x-powered-by");
  if (powered) {
    lines.push(`⚠️ **X-Powered-By:** ${powered} — reveals framework!`);
    lines.push(`   💡 Remove X-Powered-By header`);
  } else {
    lines.push(`✅ **X-Powered-By:** Not disclosed`);
  }

  // Grade
  lines.push("");
  let grade, emoji;
  if (score >= 12) { grade = "A"; emoji = "🟢"; }
  else if (score >= 9) { grade = "B"; emoji = "🟢"; }
  else if (score >= 6) { grade = "C"; emoji = "🟡"; }
  else if (score >= 3) { grade = "D"; emoji = "🟡"; }
  else { grade = "F"; emoji = "🔴"; }

  lines.push(`══════════════════════════════════════════════`);
  lines.push(`📊 Security Headers Score: ${score}/${maxScore}`);
  lines.push(`🏆 Grade: **${grade}** ${emoji}`);
  lines.push(`══════════════════════════════════════════════`);

  return lines.join("\n");
}

async function redirectChain(inputUrl, maxRedirects = 10) {
  let url = inputUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  const lines = [`🔀 Redirect Chain: **${url}**\n`];

  const hops = [];
  let current = url;
  const visited = new Set();
  const startTime = Date.now();

  for (let i = 0; i < maxRedirects; i++) {
    if (visited.has(current)) {
      lines.push(`❌ **Redirect loop detected** at ${current}`);
      break;
    }
    visited.add(current);

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(current, {
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "MCP-Domain-Lookup/1.0" },
      });
      clearTimeout(timer);

      const location = res.headers.get("location");
      hops.push({ url: current, status: res.status, statusText: res.statusText, location });

      if (res.status >= 300 && res.status < 400 && location) {
        // Resolve relative URLs
        current = location.startsWith("http") ? location : new URL(location, current).href;
      } else {
        break;
      }
    } catch (err) {
      hops.push({ url: current, status: 0, statusText: `Error: ${err.message}`, location: null });
      break;
    }
  }

  const totalTime = Date.now() - startTime;

  for (let i = 0; i < hops.length; i++) {
    const h = hops[i];
    lines.push(`**Hop ${i + 1}:** ${h.url}`);
    if (h.status >= 300 && h.status < 400) {
      lines.push(`   → ${h.status} ${h.statusText}`);
      lines.push(`   → Location: ${h.location}`);
    } else if (h.status >= 200 && h.status < 300) {
      lines.push(`   → ${h.status} ${h.statusText} ✅ (Final Destination)`);
    } else {
      lines.push(`   → ${h.status} ${h.statusText}`);
    }
    lines.push("");
  }

  lines.push(`══════════════════════════════════════════════`);
  lines.push(`Total Hops: ${hops.length}`);

  // Detect patterns
  const urls = hops.map((h) => h.url);
  const hasHttpToHttps = urls.some((u, i) => u.startsWith("http://") && i + 1 < urls.length && (hops[i].location || "").startsWith("https://"));
  const hasWwwRedirect = urls.some((u, i) => {
    const loc = hops[i].location || "";
    return (!u.includes("://www.") && loc.includes("://www.")) || (u.includes("://www.") && !loc.includes("://www."));
  });

  if (hasHttpToHttps) lines.push(`✅ HTTP→HTTPS upgrade detected (good!)`);
  if (hasWwwRedirect) lines.push(`ℹ️ www redirect detected`);

  const final = hops[hops.length - 1];
  lines.push(`Final URL: ${final.location || final.url}`);
  lines.push(`Total Time: ${totalTime}ms`);
  lines.push(`══════════════════════════════════════════════`);

  return lines.join("\n");
}

const TECH_SIGNATURES = {
  headers: {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "x-github-request-id": "GitHub Pages",
    "x-served-by": "Fastly",
    "fly-request-id": "Fly.io",
    "x-render-origin-server": "Render",
  },
  serverValues: [
    { pattern: /cloudflare/i, tech: "Cloudflare" },
    { pattern: /nginx/i, tech: "nginx" },
    { pattern: /apache/i, tech: "Apache" },
    { pattern: /microsoft-iis/i, tech: "Microsoft IIS" },
    { pattern: /litespeed/i, tech: "LiteSpeed" },
    { pattern: /caddy/i, tech: "Caddy" },
    { pattern: /openresty/i, tech: "OpenResty" },
    { pattern: /gunicorn/i, tech: "Gunicorn (Python)" },
    { pattern: /\bgws\b/i, tech: "Google Web Server (GWS)" },
    { pattern: /\bgfe\b|google\s*front/i, tech: "Google Front End (GFE)" },
    { pattern: /\benvoy\b/i, tech: "Envoy Proxy" },
    { pattern: /\bvarnish\b/i, tech: "Varnish" },
    { pattern: /\btraefik\b/i, tech: "Traefik" },
    { pattern: /\bkestrel\b/i, tech: "Kestrel (.NET)" },
  ],
  htmlPatterns: [
    { pattern: /react/i, tech: "React", category: "framework" },
    { pattern: /next\.js|__next|_next\/static/i, tech: "Next.js", category: "framework" },
    { pattern: /nuxt|__nuxt/i, tech: "Nuxt.js", category: "framework" },
    { pattern: /vue\.?js/i, tech: "Vue.js", category: "framework" },
    { pattern: /angular/i, tech: "Angular", category: "framework" },
    { pattern: /svelte/i, tech: "Svelte", category: "framework" },
    { pattern: /jquery/i, tech: "jQuery", category: "framework" },
    { pattern: /wordpress|wp-content|wp-includes/i, tech: "WordPress", category: "cms" },
    { pattern: /drupal/i, tech: "Drupal", category: "cms" },
    { pattern: /shopify/i, tech: "Shopify", category: "cms" },
    { pattern: /squarespace/i, tech: "Squarespace", category: "cms" },
    { pattern: /wix\.com/i, tech: "Wix", category: "cms" },
    { pattern: /ghost/i, tech: "Ghost", category: "cms" },
    { pattern: /webflow/i, tech: "Webflow", category: "cms" },
    { pattern: /tailwindcss|tailwind/i, tech: "Tailwind CSS", category: "css" },
    { pattern: /bootstrap/i, tech: "Bootstrap", category: "css" },
    { pattern: /material-ui|@mui/i, tech: "Material UI", category: "css" },
    { pattern: /google-analytics|gtag|GA4|googletagmanager/i, tech: "Google Analytics", category: "analytics" },
    { pattern: /plausible/i, tech: "Plausible", category: "analytics" },
    { pattern: /segment\.com|analytics\.js/i, tech: "Segment", category: "analytics" },
    { pattern: /hotjar/i, tech: "Hotjar", category: "analytics" },
    { pattern: /intercom/i, tech: "Intercom", category: "chat" },
    { pattern: /drift/i, tech: "Drift", category: "chat" },
    { pattern: /crisp/i, tech: "Crisp", category: "chat" },
    { pattern: /zendesk/i, tech: "Zendesk", category: "chat" },
    { pattern: /hubspot/i, tech: "HubSpot", category: "analytics" },
  ],
  metaGenerator: [
    { pattern: /wordpress/i, tech: "WordPress" },
    { pattern: /drupal/i, tech: "Drupal" },
    { pattern: /joomla/i, tech: "Joomla" },
    { pattern: /shopify/i, tech: "Shopify" },
    { pattern: /squarespace/i, tech: "Squarespace" },
    { pattern: /wix/i, tech: "Wix" },
    { pattern: /ghost/i, tech: "Ghost" },
    { pattern: /hugo/i, tech: "Hugo" },
    { pattern: /gatsby/i, tech: "Gatsby" },
    { pattern: /webflow/i, tech: "Webflow" },
  ],
};

async function techStackDetect(domain) {
  domain = cleanDomain(domain);
  const url = `https://${domain}`;
  const lines = [`🖥️ Tech Stack Detection: **${domain}**\n`];

  let res, body;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "MCP-Domain-Lookup/1.0" },
    });
    clearTimeout(timer);
    body = await res.text();
  } catch (err) {
    lines.push(`❌ Could not fetch ${url}: ${err.message}`);
    return lines.join("\n");
  }

  const detected = {
    "🌐 CDN/Proxy": new Set(),
    "🖥️ Web Server": new Set(),
    "⚡ Framework": new Set(),
    "📝 CMS": new Set(),
    "🎨 CSS Framework": new Set(),
    "📊 Analytics": new Set(),
    "💬 Live Chat": new Set(),
    "☁️ Hosting": new Set(),
  };

  // Check headers for CDN/hosting signatures
  for (const [header, tech] of Object.entries(TECH_SIGNATURES.headers)) {
    if (res.headers.get(header)) {
      if (["Cloudflare", "Amazon CloudFront", "Fastly"].includes(tech)) {
        detected["🌐 CDN/Proxy"].add(tech);
      } else {
        detected["☁️ Hosting"].add(tech);
      }
    }
  }

  // Server header
  const serverHeader = res.headers.get("server") || "";
  for (const sig of TECH_SIGNATURES.serverValues) {
    if (sig.pattern.test(serverHeader)) detected["🖥️ Web Server"].add(sig.tech);
  }

  // X-Powered-By
  const powered = res.headers.get("x-powered-by") || "";
  if (/express/i.test(powered)) detected["⚡ Framework"].add("Express.js (Node.js)");
  if (/php/i.test(powered)) detected["⚡ Framework"].add("PHP");
  if (/asp\.net/i.test(powered)) detected["⚡ Framework"].add("ASP.NET");

  // Meta generator
  const genMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
  if (genMatch) {
    for (const sig of TECH_SIGNATURES.metaGenerator) {
      if (sig.pattern.test(genMatch[1])) detected["📝 CMS"].add(sig.tech);
    }
  }

  // HTML body patterns
  for (const sig of TECH_SIGNATURES.htmlPatterns) {
    if (sig.pattern.test(body)) {
      const catMap = {
        framework: "⚡ Framework",
        cms: "📝 CMS",
        css: "🎨 CSS Framework",
        analytics: "📊 Analytics",
        chat: "💬 Live Chat",
      };
      const cat = catMap[sig.category] || "⚡ Framework";
      detected[cat].add(sig.tech);
    }
  }

  // Output
  let anyDetected = false;
  for (const [category, techs] of Object.entries(detected)) {
    if (techs.size > 0) {
      anyDetected = true;
      lines.push(`${category}: ${[...techs].join(", ")}`);
    }
  }

  if (!anyDetected) {
    lines.push(`ℹ️ No technologies confidently detected`);
  }

  // Raw key headers
  lines.push(`\n📋 **Raw Headers:**`);
  const interestingHeaders = ["server", "x-powered-by", "via", "cf-ray", "x-cache", "x-vercel-id", "x-amz-cf-id"];
  for (const h of interestingHeaders) {
    const val = res.headers.get(h);
    if (val) lines.push(`   ${h}: ${val}`);
  }

  lines.push(`\n══════════════════════════════════════════════`);
  return lines.join("\n");
}

async function domainAge(domain) {
  domain = cleanDomain(domain);
  const lines = [`📅 Domain Age: **${domain}**\n`];

  try {
    const rec = await whoisWithRetry(domain);
    const createdRaw = rec.creationDate || rec.createdDate || rec.created || rec.CreationDate || null;
    const updatedRaw = rec.updatedDate || rec.lastUpdated || rec.UpdatedDate || null;
    const expiryRaw = rec.registrarRegistrationExpirationDate || rec.expirationDate || rec.expiryDate || rec.expires || rec.ExpirationDate || null;

    if (!createdRaw) {
      lines.push(`❌ Could not determine creation date for ${domain}`);
      return lines.join("\n");
    }

    const created = new Date(createdRaw);
    const now = new Date();

    // Calculate exact age
    let years = now.getFullYear() - created.getFullYear();
    let months = now.getMonth() - created.getMonth();
    let days = now.getDate() - created.getDate();
    if (days < 0) { months--; days += 30; }
    if (months < 0) { years--; months += 12; }

    // Timeline
    lines.push(`📆 **Registration Timeline:**`);
    lines.push(`├── 🟢 **Created:**  ${created.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}`);
    if (updatedRaw) {
      const updated = new Date(updatedRaw);
      lines.push(`├── 🔄 **Updated:**  ${updated.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}`);
    }
    lines.push(`├── 📍 **Current:**  ${now.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}`);
    if (expiryRaw) {
      const expiry = new Date(expiryRaw);
      lines.push(`└── 🔴 **Expires:**  ${expiry.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}`);
    }

    lines.push("");
    lines.push(`⏱️ **Age: ${years} years, ${months} months, ${days} days**`);

    // Context
    const totalYears = years + months / 12;
    let context;
    if (totalYears < 1) context = "🆕 Very new domain — may have lower trust score";
    else if (totalYears < 3) context = "📅 Relatively new domain";
    else if (totalYears < 10) context = "✅ Established domain";
    else if (totalYears < 20) context = "🏆 Well-established domain";
    else context = "👴 Internet veteran!";
    lines.push(context);

    // Longevity bar if we have expiry
    if (expiryRaw) {
      const expiry = new Date(expiryRaw);
      const totalSpan = expiry - created;
      const usedSpan = now - created;
      const pct = Math.min(100, Math.max(0, Math.round((usedSpan / totalSpan) * 100)));
      const filled = Math.round(pct / 100 * 30);
      const bar = "█".repeat(filled) + "░".repeat(30 - filled);
      const daysUntilExpiry = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
      lines.push("");
      lines.push(`📊 **Domain Longevity:**`);
      lines.push(`${bar} ${pct}% of registration used`);
      if (daysUntilExpiry > 0) {
        const ey = Math.floor(daysUntilExpiry / 365);
        const em = Math.floor((daysUntilExpiry % 365) / 30);
        lines.push(`${ey > 0 ? ey + " years, " : ""}${em} months until expiry`);
      } else {
        lines.push(`🔴 Domain has EXPIRED!`);
      }
    }

    lines.push(`\n══════════════════════════════════════════════`);
  } catch (err) {
    lines.push(`❌ Could not retrieve domain age: ${err.message}`);
  }

  return lines.join("\n");
}

async function dnsCompare(domain1, domain2) {
  domain1 = cleanDomain(domain1);
  domain2 = cleanDomain(domain2);
  const lines = [`🔄 DNS Comparison: **${domain1}** vs **${domain2}**\n`];

  const types = ["A", "AAAA", "MX", "NS", "TXT"];

  const pad = (s, n) => {
    s = String(s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s.padEnd(n);
  };

  lines.push(`${pad("Record Type", 12)} │ ${pad(domain1, 30)} │ ${pad(domain2, 30)}`);
  lines.push(`${"─".repeat(12)}─┼─${"─".repeat(30)}─┼─${"─".repeat(30)}`);

  const differences = [];

  for (const t of types) {
    const [r1, r2] = await Promise.all([resolveDns(domain1, t), resolveDns(domain2, t)]);

    const format = (records) => {
      if (!records || records.length === 0) return ["(none)"];
      return records.map((r) => {
        if (typeof r === "object" && r.exchange) return `${r.exchange} (${r.priority})`;
        const s = Array.isArray(r) ? r.join("") : String(r);
        return s.length > 28 ? s.slice(0, 25) + "…" : s;
      });
    };

    const f1 = format(r1);
    const f2 = format(r2);
    const maxRows = Math.max(f1.length, f2.length);

    for (let i = 0; i < maxRows; i++) {
      const label = i === 0 ? pad(t, 12) : pad("", 12);
      lines.push(`${label} │ ${pad(f1[i] || "", 30)} │ ${pad(f2[i] || "", 30)}`);
    }
    lines.push(`${"─".repeat(12)}─┼─${"─".repeat(30)}─┼─${"─".repeat(30)}`);

    // Track differences
    const s1 = JSON.stringify(r1 || []);
    const s2 = JSON.stringify(r2 || []);
    if (s1 !== s2) {
      differences.push(t);
    }
  }

  lines.push("");
  if (differences.length === 0) {
    lines.push(`✅ Both domains have identical DNS configuration`);
  } else {
    lines.push(`**Key Differences:**`);
    for (const t of differences) {
      lines.push(`• ${t} records differ between the two domains`);
    }
  }

  return lines.join("\n");
}

const PORT_SERVICES = {
  21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
  110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
  587: "Submission", 993: "IMAPS", 995: "POP3S",
  3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP Alt", 8443: "HTTPS Alt",
};

const COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443];

function checkPort(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port }, () => {
      sock.destroy();
      resolve({ port, open: true });
    });
    sock.setTimeout(timeoutMs);
    sock.on("timeout", () => { sock.destroy(); resolve({ port, open: false }); });
    sock.on("error", () => { sock.destroy(); resolve({ port, open: false }); });
  });
}

async function portCheck(domain, portsArg = "common") {
  domain = cleanDomain(domain);
  const lines = [`🔌 Port Check: **${domain}**\n`];

  let ports;
  if (portsArg === "common") {
    ports = COMMON_PORTS;
  } else {
    ports = portsArg.split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => p > 0 && p <= 65535);
    if (ports.length === 0) {
      lines.push(`❌ No valid ports specified`);
      return lines.join("\n");
    }
  }

  // Resolve to IP for display
  const aRecs = await resolveDns(domain, "A");
  const ip = aRecs ? aRecs[0] : domain;
  if (aRecs) lines.push(`Resolved to: ${ip}\n`);

  const startTime = Date.now();
  const results = await Promise.all(ports.map((p) => checkPort(ip, p)));
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  const pad = (s, n) => String(s).padEnd(n);
  lines.push(`${pad("Port", 7)} │ ${pad("Service", 13)} │ Status`);
  lines.push(`${"─".repeat(7)}─┼─${"─".repeat(13)}─┼─${"─".repeat(10)}`);

  let openCount = 0;
  for (const r of results) {
    const svc = PORT_SERVICES[r.port] || "Unknown";
    const icon = r.open ? "✅ Open" : "❌ Closed";
    if (r.open) openCount++;
    lines.push(`${pad(r.port, 7)} │ ${pad(svc, 13)} │ ${icon}`);
  }

  lines.push("");
  lines.push(`══════════════════════════════════════════════`);
  lines.push(`📊 Results: ${openCount} open, ${results.length - openCount} closed out of ${results.length} ports checked`);
  lines.push(`⏱️ Scan completed in ${elapsed}s`);

  // Insights
  const openPorts = new Set(results.filter((r) => r.open).map((r) => r.port));
  if (openPorts.has(80) && openPorts.has(443)) lines.push(`\n✅ Web services: HTTP and HTTPS are both open (good!)`);
  else if (openPorts.has(443) && !openPorts.has(80)) lines.push(`\n✅ HTTPS is open, HTTP closed (HTTPS-only — good!)`);
  else if (openPorts.has(80) && !openPorts.has(443)) lines.push(`\n⚠️ HTTP is open but HTTPS is closed — add SSL!`);

  const dbPorts = [3306, 5432];
  const openDb = dbPorts.filter((p) => openPorts.has(p));
  if (openDb.length > 0) lines.push(`🔴 Database port(s) exposed: ${openDb.join(", ")} — security risk!`);
  else if (ports.some((p) => dbPorts.includes(p))) lines.push(`ℹ️ No database ports exposed (good security practice)`);

  if (!openPorts.has(22) && ports.includes(22)) lines.push(`ℹ️ No SSH port detected (may be on non-standard port)`);

  lines.push(`══════════════════════════════════════════════`);
  return lines.join("\n");
}

async function domainReport(domain) {
  domain = cleanDomain(domain);
  const startTime = Date.now();
  const lines = [
    `══════════════════════════════════════════════`,
    `📊 COMPLETE DOMAIN INTELLIGENCE REPORT`,
    `📌 Domain: **${domain}**`,
    `🕐 Generated: ${new Date().toISOString()}`,
    `══════════════════════════════════════════════\n`,
  ];

  // Run checks in parallel (exclude subdomain_finder — too slow, exclude dns_compare/dns_propagation — need extra params)
  const checks = await Promise.allSettled([
    dnsLookup(domain, "ALL"),
    whoisLookup(domain),
    emailConfigCheck(domain),
    sslCheck(domain),
    httpHeadersCheck(domain),
    techStackDetect(domain),
    domainAge(domain),
    portCheck(domain, "80,443,22,21,25"),
  ]);

  const labels = ["DNS Records", "WHOIS Registration", "Email Security", "SSL Certificate", "HTTP Security Headers", "Technology Stack", "Domain Age", "Port Scan"];

  for (let i = 0; i < checks.length; i++) {
    lines.push(`\n${"─".repeat(50)}`);
    lines.push(`📑 ${labels[i]}`);
    lines.push(`${"─".repeat(50)}`);
    if (checks[i].status === "fulfilled") {
      lines.push(checks[i].value);
    } else {
      lines.push(`❌ ${labels[i]} check failed: ${checks[i].reason?.message || "Unknown error"}`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  // Quick summary
  lines.push(`\n══════════════════════════════════════════════`);
  lines.push(`📊 QUICK SUMMARY — ${domain}`);
  lines.push(`══════════════════════════════════════════════`);

  // DNS summary
  const dnsText = checks[0].status === "fulfilled" ? checks[0].value : "";
  const dnsRecordCount = (dnsText.match(/✅/g) || []).length;
  lines.push(`🌐 DNS:          ${dnsRecordCount > 0 ? `✅ Configured (${dnsRecordCount} record types found)` : "❌ No records"}`);

  // WHOIS summary
  const whoisText = checks[1].status === "fulfilled" ? checks[1].value : "";
  const createdMatch = whoisText.match(/Created:\*\*\s*(\S+)/);
  const expiryDaysMatch = whoisText.match(/\((\d+) days remaining\)/);
  if (createdMatch) {
    lines.push(`🏢 Registration: ✅ Registered since ${createdMatch[1]}${expiryDaysMatch ? ` | Expires in ${expiryDaysMatch[1]} days` : ""}`);
  } else {
    lines.push(`🏢 Registration: ⚠️ WHOIS data limited`);
  }

  // Email summary
  const emailText = checks[2].status === "fulfilled" ? checks[2].value : "";
  const emailGrade = emailText.match(/Grade:\s*(\w)/);
  const mxOk = emailText.includes("✅") && emailText.includes("MX");
  lines.push(`📧 Email:        ${emailGrade ? `Grade ${emailGrade[1]}` : "N/A"}${mxOk ? " — MX ✅" : ""}`);

  // SSL summary
  const sslText = checks[3].status === "fulfilled" ? checks[3].value : "";
  if (sslText.includes("🟢")) lines.push(`🔒 SSL:          ✅ Valid`);
  else if (sslText.includes("🔴")) lines.push(`🔒 SSL:          🔴 Expired or invalid`);
  else lines.push(`🔒 SSL:          ⚠️ Check failed`);

  // Headers summary
  const headersText = checks[4].status === "fulfilled" ? checks[4].value : "";
  const headersGrade = headersText.match(/Grade:\s*\*\*(\w)\*\*/);
  lines.push(`🛡️ Headers:      ${headersGrade ? `Grade ${headersGrade[1]}` : "N/A"}`);

  // Tech summary
  const techText = checks[5].status === "fulfilled" ? checks[5].value : "";
  const techLines = techText.split("\n").filter((l) => l.match(/^[🌐🖥⚡📝🎨📊💬☁]/));
  lines.push(`🖥️ Tech:         ${techLines.length > 0 ? techLines.map((l) => l.split(": ")[1]).filter(Boolean).join(" | ") : "N/A"}`);

  // Age summary
  const ageText = checks[6].status === "fulfilled" ? checks[6].value : "";
  const ageMatch = ageText.match(/Age:\s*(.+)\*\*/);
  lines.push(`📅 Age:          ${ageMatch ? ageMatch[1].replace(/\*\*/g, "") : "N/A"}`);

  lines.push(`══════════════════════════════════════════════`);
  lines.push(`⏱️ Report generated in ${elapsed}s`);

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Server card (for Smithery scanning / .well-known)
// ---------------------------------------------------------------------------

const SERVER_CARD = {
  name: "mcp-domain-lookup",
  displayName: "Domain Inspector",
  description: "The most comprehensive domain intelligence MCP server. 15 tools for DNS, WHOIS, email security, SSL, HTTP headers, tech stack detection, subdomain discovery, port scanning, and more.",
  version: "2.0.0",
  homepage: "https://mcpdns.onrender.com",
  icons: [{ src: "https://mcpdns.onrender.com/icon.svg", mimeType: "image/svg+xml", sizes: ["any"] }],
  config: {
    schema: {
      type: "object",
      properties: {
        timeout: {
          type: "number",
          title: "Request Timeout (ms)",
          description: "Maximum time in milliseconds for each tool request. Default is 30000 (30 seconds).",
          default: 30000,
        },
      },
      required: [],
    },
  },
  tools: [
    {
      name: "domain_report",
      description: "Get a complete domain intelligence report. Runs ALL checks at once: DNS, WHOIS, email security, SSL, HTTP headers, tech stack detection, and domain age. This is the recommended starting tool.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain to analyze" } }, required: ["domain"] },
    },
    {
      name: "dns_lookup",
      description: "Look up DNS records (A, AAAA, MX, TXT, NS, CNAME, or ALL) for any domain.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain name to look up" }, record_type: { type: "string", enum: ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "ALL"], description: "DNS record type to query", default: "ALL" } }, required: ["domain"] },
    },
    {
      name: "whois_lookup",
      description: "Get WHOIS registration data for a domain including registrar, creation/expiry dates, and days remaining.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain name to look up" } }, required: ["domain"] },
    },
    {
      name: "domain_available",
      description: "Check whether a domain is available for registration. Suggests alternative TLDs if taken.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain name to check" } }, required: ["domain"] },
    },
    {
      name: "email_config_check",
      description: "Audit email security: MX, SPF, DKIM, DMARC records with letter grade A–F.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain name to audit" } }, required: ["domain"] },
    },
    {
      name: "ssl_check",
      description: "Check SSL/TLS certificate details: issuer, validity, days remaining, protocol, fingerprint.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain or hostname to check" } }, required: ["domain"] },
    },
    {
      name: "reverse_dns",
      description: "Reverse DNS lookup — convert an IP address to its hostname(s), or find the IP behind a domain and do reverse lookup.",
      inputSchema: { type: "object", properties: { target: { type: "string", description: "IP address or domain name" } }, required: ["target"] },
    },
    {
      name: "dns_propagation",
      description: "Check if DNS has propagated by querying 8 public resolvers worldwide (Google, Cloudflare, OpenDNS, Quad9, etc.).",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain to check" }, record_type: { type: "string", description: "Record type (default A)", default: "A" } }, required: ["domain"] },
    },
    {
      name: "subdomain_finder",
      description: "Discover common subdomains by checking ~80 common prefixes via DNS resolution.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain to scan for subdomains" } }, required: ["domain"] },
    },
    {
      name: "http_headers_check",
      description: "Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) with letter grade A–F.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain or URL to check" } }, required: ["domain"] },
    },
    {
      name: "redirect_chain",
      description: "Trace the full redirect chain for a URL. Shows every hop, status code, and final destination.",
      inputSchema: { type: "object", properties: { url: { type: "string", description: "URL to trace (e.g. http://example.com)" }, max_redirects: { type: "number", description: "Maximum redirects to follow (default 10)", default: 10 } }, required: ["url"] },
    },
    {
      name: "tech_stack_detect",
      description: "Detect the technology stack: web server, CDN, framework, CMS, analytics, and more.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain to analyze" } }, required: ["domain"] },
    },
    {
      name: "domain_age",
      description: "Calculate exact domain age with registration timeline and longevity visualization.",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain to check age of" } }, required: ["domain"] },
    },
    {
      name: "dns_compare",
      description: "Compare DNS records of two domains side by side.",
      inputSchema: { type: "object", properties: { domain1: { type: "string", description: "First domain" }, domain2: { type: "string", description: "Second domain" } }, required: ["domain1", "domain2"] },
    },
    {
      name: "port_check",
      description: "Check if common network ports are open on a domain (HTTP, HTTPS, SSH, SMTP, databases, etc.).",
      inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain or IP to scan" }, ports: { type: "string", description: "Comma-separated port numbers or 'common' for standard ports", default: "common" } }, required: ["domain"] },
    },
  ],
};

// ---------------------------------------------------------------------------
// MCP Server setup
// ---------------------------------------------------------------------------

function createMcpServer() {
  const server = new McpServer({
    name: "mcp-domain-lookup",
    version: "2.0.0",
  });

  // --- domain_report (flagship) ---
  server.tool(
    "domain_report",
    "Get a complete domain intelligence report. Runs ALL checks at once: DNS, WHOIS, email security, SSL, HTTP headers, tech stack detection, and domain age. This is the recommended starting tool.",
    { domain: z.string().describe("Domain to analyze (e.g. example.com)") },
    { title: "Domain Report", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await domainReport(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- dns_lookup ---
  server.tool(
    "dns_lookup",
    "Look up DNS records (A, AAAA, MX, TXT, NS, CNAME, or ALL) for any domain.",
    {
      domain: z.string().describe("Domain name to look up (e.g. example.com)"),
      record_type: z
        .enum(["A", "AAAA", "MX", "TXT", "NS", "CNAME", "ALL"])
        .default("ALL")
        .describe("DNS record type to query. Use ALL to fetch every type."),
    },
    { title: "DNS Lookup", readOnlyHint: true, openWorldHint: true },
    async ({ domain, record_type }) => {
      const text = await dnsLookup(domain, record_type);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- whois_lookup ---
  server.tool(
    "whois_lookup",
    "Get WHOIS registration data for a domain including registrar, creation/expiry dates, and days remaining.",
    { domain: z.string().describe("Domain name to look up (e.g. example.com)") },
    { title: "WHOIS Lookup", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await whoisLookup(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- domain_available ---
  server.tool(
    "domain_available",
    "Check whether a domain is available for registration. Suggests alternative TLDs if the domain is taken.",
    { domain: z.string().describe("Domain name to check (e.g. example.com)") },
    { title: "Domain Availability", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await domainAvailable(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- email_config_check ---
  server.tool(
    "email_config_check",
    "Audit email security configuration: MX, SPF, DKIM (common selectors), and DMARC records. Returns a letter grade A–F.",
    { domain: z.string().describe("Domain name to audit (e.g. example.com)") },
    { title: "Email Security Audit", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await emailConfigCheck(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- ssl_check ---
  server.tool(
    "ssl_check",
    "Check SSL/TLS certificate details for a domain: issuer, validity dates, days remaining, protocol, and fingerprint.",
    { domain: z.string().describe("Domain or hostname to check (e.g. example.com)") },
    { title: "SSL Certificate Check", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await sslCheck(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- reverse_dns ---
  server.tool(
    "reverse_dns",
    "Reverse DNS lookup — convert an IP address to its hostname(s), or find the IP behind a domain and do reverse lookup.",
    { target: z.string().describe("IP address or domain name (e.g. 8.8.8.8 or example.com)") },
    { title: "Reverse DNS", readOnlyHint: true, openWorldHint: true },
    async ({ target }) => {
      const text = await reverseDns(target);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- dns_propagation ---
  server.tool(
    "dns_propagation",
    "Check if DNS has propagated by querying 8 public resolvers worldwide (Google, Cloudflare, OpenDNS, Quad9, etc.).",
    {
      domain: z.string().describe("Domain to check (e.g. example.com)"),
      record_type: z.string().default("A").describe("Record type to check (default A)"),
    },
    { title: "DNS Propagation Check", readOnlyHint: true, openWorldHint: true },
    async ({ domain, record_type }) => {
      const text = await dnsPropagation(domain, record_type);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- subdomain_finder ---
  server.tool(
    "subdomain_finder",
    "Discover common subdomains for a domain by checking ~80 common subdomain prefixes.",
    { domain: z.string().describe("Domain to scan for subdomains (e.g. example.com)") },
    { title: "Subdomain Finder", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await subdomainFinder(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- http_headers_check ---
  server.tool(
    "http_headers_check",
    "Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) and give a letter grade A–F.",
    { domain: z.string().describe("Domain or URL to check (e.g. example.com)") },
    { title: "HTTP Security Headers", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await httpHeadersCheck(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- redirect_chain ---
  server.tool(
    "redirect_chain",
    "Trace the full redirect chain for a URL. Shows every redirect hop, status code, and final destination.",
    {
      url: z.string().describe("URL to trace (e.g. http://example.com)"),
      max_redirects: z.number().default(10).describe("Maximum redirects to follow (default 10)"),
    },
    { title: "Redirect Chain Tracer", readOnlyHint: true, openWorldHint: true },
    async ({ url, max_redirects }) => {
      const text = await redirectChain(url, max_redirects);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- tech_stack_detect ---
  server.tool(
    "tech_stack_detect",
    "Detect the technology stack of a website: web server, CDN, framework, CMS, analytics, and more.",
    { domain: z.string().describe("Domain to analyze (e.g. example.com)") },
    { title: "Tech Stack Detector", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await techStackDetect(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- domain_age ---
  server.tool(
    "domain_age",
    "Calculate the exact age of a domain and show its registration timeline.",
    { domain: z.string().describe("Domain to check age of (e.g. example.com)") },
    { title: "Domain Age Calculator", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const text = await domainAge(domain);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- dns_compare ---
  server.tool(
    "dns_compare",
    "Compare DNS records of two domains side by side. Useful for comparing setups or verifying migration.",
    {
      domain1: z.string().describe("First domain (e.g. google.com)"),
      domain2: z.string().describe("Second domain (e.g. bing.com)"),
    },
    { title: "DNS Comparison", readOnlyHint: true, openWorldHint: true },
    async ({ domain1, domain2 }) => {
      const text = await dnsCompare(domain1, domain2);
      return { content: [{ type: "text", text }] };
    }
  );

  // --- port_check ---
  server.tool(
    "port_check",
    "Check if common network ports are open on a domain. Useful for verifying services are running.",
    {
      domain: z.string().describe("Domain or IP to scan (e.g. example.com)"),
      ports: z.string().default("common").describe("Comma-separated port numbers or 'common' for standard web/mail/ssh ports"),
    },
    { title: "Port Scanner", readOnlyHint: true, openWorldHint: true },
    async ({ domain, ports }) => {
      const text = await portCheck(domain, ports);
      return { content: [{ type: "text", text }] };
    }
  );

  // ─── Prompts ────────────────────────────────────────────────────────────────

  // --- domain-check prompt ---
  server.prompt(
    "domain-check",
    "Run a full domain intelligence report with analysis and recommendations",
    { domain: z.string().describe("Domain to analyze") },
    ({ domain }) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Run a complete domain report for ${domain} using the domain_report tool. After getting the results, provide a brief executive summary covering:\n- Overall health assessment (DNS, SSL, email security)\n- Any urgent issues (expiring certificates, missing security headers, exposed ports)\n- Key recommendations ranked by priority\n- Notable findings about the domain's infrastructure` },
        },
      ],
    })
  );

  // --- security-audit prompt ---
  server.prompt(
    "security-audit",
    "Audit the security posture of a domain",
    { domain: z.string().describe("Domain to audit") },
    ({ domain }) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Perform a security audit on ${domain}. Use these tools in order:\n1. ssl_check — verify the certificate is valid and not expiring soon\n2. http_headers_check — grade the security headers\n3. email_config_check — check SPF, DKIM, DMARC\n4. port_check — scan for open ports\n\nSummarize the findings with an overall security rating and actionable recommendations.` },
        },
      ],
    })
  );

  // --- compare-domains prompt ---
  server.prompt(
    "compare-domains",
    "Compare two domains side by side",
    {
      domain1: z.string().describe("First domain"),
      domain2: z.string().describe("Second domain"),
    },
    ({ domain1, domain2 }) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Compare ${domain1} and ${domain2} using dns_compare, then run ssl_check and http_headers_check on both. Present a side-by-side comparison highlighting key differences in DNS configuration, SSL certificates, and security headers.` },
        },
      ],
    })
  );

  // --- find-subdomains prompt ---
  server.prompt(
    "find-subdomains",
    "Discover and analyze subdomains of a domain",
    { domain: z.string().describe("Domain to scan") },
    ({ domain }) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: `Find all subdomains of ${domain} using subdomain_finder. For each discovered subdomain, briefly note what it likely serves (mail, API, CDN, etc.) based on its name and IP. Summarize the domain's infrastructure footprint.` },
        },
      ],
    })
  );

  // ─── Resources ──────────────────────────────────────────────────────────────

  // --- tool catalog resource ---
  server.resource(
    "tool-catalog",
    "info://tools",
    { title: "Tool Catalog", description: "Complete list of all 15 domain intelligence tools with descriptions and parameters", mimeType: "application/json" },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify(SERVER_CARD.tools, null, 2),
      }],
    })
  );

  // --- server info resource ---
  server.resource(
    "server-info",
    "info://server",
    { title: "Server Information", description: "MCP Domain Lookup server metadata, version, and capabilities", mimeType: "application/json" },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify({
          name: SERVER_CARD.name,
          displayName: "Domain Inspector",
          version: SERVER_CARD.version,
          description: SERVER_CARD.description,
          toolCount: SERVER_CARD.tools.length,
          homepage: "https://mcpdns.onrender.com",
        }, null, 2),
      }],
    })
  );

  return server;
}

// ---------------------------------------------------------------------------
// Homepage HTML (loaded from file)
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOMEPAGE_HTML = fs.readFileSync(path.join(__dirname, "homepage.html"), "utf-8");
const TERMS_HTML = fs.readFileSync(path.join(__dirname, "terms.html"), "utf-8");
const PRIVACY_HTML = fs.readFileSync(path.join(__dirname, "privacy.html"), "utf-8");

// ---------------------------------------------------------------------------
// Express app & transport wiring
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

// Session store: mcp-session-id → transport
// NOTE: In production with multiple instances, replace with Redis or similar shared store.
// Consider adding a TTL-based cleanup sweep for abandoned sessions.
const sessions = new Map();

// --- POST /mcp — main JSON-RPC handler (initialize + tool calls) ---
app.post("/mcp", async (req, res) => {
  try {
    const sessionId = req.headers["mcp-session-id"];

    if (sessionId && sessions.has(sessionId)) {
      // Existing session
      const transport = sessions.get(sessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // Only allow new sessions for initialize requests
    if (!isInitializeRequest(req.body)) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID provided. Send an initialize request first." },
        id: null,
      });
      return;
    }

    // New session — create server + transport
    const server = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, transport);
      },
    });

    transport.onclose = () => {
      const id = transport.sessionId;
      if (id) sessions.delete(id);
    };

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("Error handling MCP POST:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

// --- GET /mcp — SSE stream for an existing session ---
app.get("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: "Invalid or missing session. Send an initialize request first." });
    return;
  }
  const transport = sessions.get(sessionId);
  await transport.handleRequest(req, res);
});

// --- DELETE /mcp — session cleanup ---
app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: "Invalid or missing session." });
    return;
  }
  const transport = sessions.get(sessionId);
  await transport.handleRequest(req, res);
  sessions.delete(sessionId);
});

// --- Well-known server card ---
app.get("/.well-known/mcp/server-card.json", (_req, res) => {
  res.json(SERVER_CARD);
});

// --- Health check ---
app.get("/health", (_req, res) => {
  res.json({ status: "ok", tools: SERVER_CARD.tools.length, version: SERVER_CARD.version });
});

// --- SVG icon ---
const ICON_SVG = `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="24" cy="24" r="22" stroke="#6366f1" stroke-width="2" opacity=".3"/><circle cx="24" cy="24" r="15" stroke="#818cf8" stroke-width="2"/><circle cx="24" cy="24" r="4" fill="#818cf8"/><line x1="24" y1="2" x2="24" y2="46" stroke="#6366f1" stroke-width="1" opacity=".3"/><ellipse cx="24" cy="24" rx="10" ry="22" stroke="#6366f1" stroke-width="1" opacity=".3"/></svg>`;
app.get("/icon.svg", (_req, res) => {
  res.type("image/svg+xml").send(ICON_SVG);
});

// --- Homepage ---
app.get("/about", (_req, res) => {
  res.type("html").send(HOMEPAGE_HTML);
});

// --- Legal pages ---
app.get("/terms", (_req, res) => {
  res.type("html").send(TERMS_HTML);
});
app.get("/privacy", (_req, res) => {
  res.type("html").send(PRIVACY_HTML);
});

// --- Root — serve homepage for browsers, JSON for API clients ---
app.get("/", (req, res) => {
  const accept = req.headers.accept || "";
  if (accept.includes("text/html")) {
    res.type("html").send(HOMEPAGE_HTML);
    return;
  }
  res.json({
    name: "mcp-domain-lookup",
    displayName: "Domain Inspector",
    version: SERVER_CARD.version,
    description: SERVER_CARD.description,
    homepage: "https://mcpdns.onrender.com",
    endpoints: {
      mcp: "/mcp",
      health: "/health",
      homepage: "/about",
      icon: "/icon.svg",
      serverCard: "/.well-known/mcp/server-card.json",
    },
    toolCount: SERVER_CARD.tools.length,
    tools: SERVER_CARD.tools.map((t) => t.name),
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 MCP Domain Lookup server running on port ${PORT}`);
  console.log(`   MCP endpoint:  http://localhost:${PORT}/mcp`);
  console.log(`   Server card:   http://localhost:${PORT}/.well-known/mcp/server-card.json`);
  console.log(`   About:         http://localhost:${PORT}/about`);
  console.log(`   Health check:  http://localhost:${PORT}/health`);
});
