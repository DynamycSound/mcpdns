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

function getBaseDomain(domain) {
  const parts = domain.split(".");
  // For domains like www.example.com or blog.example.com → example.com
  // For domains like example.co.uk → example.co.uk (keep 3 parts for known 2-part TLDs)
  const twoPartTlds = ["co.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp", "co.kr", "org.uk", "net.au"];
  const last2 = parts.slice(-2).join(".");
  if (twoPartTlds.includes(last2) && parts.length > 2) return parts.slice(-3).join(".");
  if (parts.length > 2) return parts.slice(-2).join(".");
  return domain;
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
  const result = { domain, queriedTypes: types, records: {} };

  for (const t of types) {
    const records = await resolveDns(domain, t);
    if (!records) {
      result.records[t] = null;
      continue;
    }
    if (t === "MX") {
      result.records[t] = records.sort((a, b) => a.priority - b.priority).map((r) => ({ priority: r.priority, exchange: r.exchange }));
    } else if (t === "TXT") {
      result.records[t] = records.map((r) => (Array.isArray(r) ? r.join("") : r));
    } else {
      result.records[t] = records;
    }
  }
  const found = Object.entries(result.records).filter(([, v]) => v !== null).length;
  result.summary = `${found}/${types.length} record types found`;
  return result;
}

async function whoisLookup(domain) {
  domain = cleanDomain(domain);
  const baseDomain = getBaseDomain(domain);
  const result = { domain, queriedDomain: baseDomain !== domain ? baseDomain : domain, error: null };
  try {
    let rec = await whoisWithRetry(domain);
    // If subdomain WHOIS returned no useful data, try base domain
    const hasData = rec.registrar || rec.Registrar || rec.creationDate || rec.createdDate || rec.created;
    if (!hasData && baseDomain !== domain) {
      rec = await whoisWithRetry(baseDomain);
      result.queriedDomain = baseDomain;
    }
    result.registrar = rec.registrar || rec.Registrar || "Unknown";

    const createdRaw = rec.creationDate || rec.createdDate || rec.created || rec.CreationDate || null;
    const expiryRaw = rec.registrarRegistrationExpirationDate || rec.expirationDate || rec.expiryDate || rec.expires || rec.ExpirationDate || null;
    const updatedRaw = rec.updatedDate || rec.lastUpdated || rec.UpdatedDate || null;
    const status = rec.domainStatus || rec.status || rec.Status || "Unknown";
    const nameServers = rec.nameServer || rec.nameServers || rec.NameServer || null;

    result.created = createdRaw ? new Date(createdRaw).toISOString().split("T")[0] : null;
    result.expires = expiryRaw ? new Date(expiryRaw).toISOString().split("T")[0] : null;
    result.updated = updatedRaw ? new Date(updatedRaw).toISOString().split("T")[0] : null;

    if (expiryRaw) {
      const daysRemaining = Math.ceil((new Date(expiryRaw) - new Date()) / (1000 * 60 * 60 * 24));
      result.daysUntilExpiry = daysRemaining;
      result.expiryStatus = daysRemaining < 0 ? "EXPIRED" : daysRemaining <= 30 ? "EXPIRING_SOON" : daysRemaining <= 90 ? "EXPIRING" : "OK";
    }

    result.status = Array.isArray(status) ? status.map((s) => s.toString().split(" ")[0]) : [String(status).split(" ")[0]];
    result.nameServers = nameServers ? (Array.isArray(nameServers) ? nameServers : [nameServers]) : [];
  } catch (err) {
    result.error = err.message;
  }
  return result;
}

async function domainAvailable(domain) {
  domain = cleanDomain(domain);
  const result = { domain, available: false, alternatives: [] };

  let taken = false;
  const aRecords = await resolveDns(domain, "A");
  const aaaaRecords = await resolveDns(domain, "AAAA");
  if (aRecords || aaaaRecords) taken = true;

  if (!taken) {
    try {
      const rec = await whoisWithRetry(domain, 1);
      if (rec && (rec.domainName || rec.domain || rec.registrar || rec.Registrar || rec.created || rec.source)) taken = true;
    } catch { /* treat as potentially available */ }
  }

  result.available = !taken;

  if (taken) {
    const base = domain.split(".")[0];
    const alts = [".com", ".net", ".org", ".io", ".co", ".dev", ".app", ".xyz", ".info", ".me"];
    for (const tld of alts) {
      const alt = base + tld;
      if (alt === domain) continue;
      const altA = await resolveDns(alt, "A");
      if (!altA) result.alternatives.push(alt);
      if (result.alternatives.length >= 5) break;
    }
  }
  return result;
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
  const result = { domain, score: 0, maxScore: 4, checks: {}, grade: "F", missing: [], provider: null };

  // --- MX ---
  const mxRecords = await resolveDns(domain, "MX");
  if (mxRecords && mxRecords.length > 0) {
    result.score++;
    const sorted = mxRecords.sort((a, b) => a.priority - b.priority);
    result.checks.mx = { found: true, records: sorted.map((r) => ({ priority: r.priority, exchange: r.exchange })) };
    const allExchanges = sorted.map((r) => r.exchange).join(" ");
    for (const ep of EMAIL_PROVIDERS) {
      if (ep.pattern.test(allExchanges)) { result.provider = ep.name; break; }
    }
  } else {
    result.checks.mx = { found: false, records: [] };
    result.missing.push("MX");
  }

  // --- SPF ---
  const txtRecords = await resolveDns(domain, "TXT");
  let spfFound = false;
  if (txtRecords) {
    for (const rec of txtRecords) {
      const val = Array.isArray(rec) ? rec.join("") : rec;
      if (val.startsWith("v=spf1")) {
        spfFound = true;
        result.score++;
        let policy = "unknown";
        if (val.includes("-all")) policy = "strict (-all)";
        else if (val.includes("~all")) policy = "soft-fail (~all)";
        else if (val.includes("?all")) policy = "neutral (?all)";
        else if (val.includes("+all")) policy = "permissive (+all) - DANGEROUS";
        result.checks.spf = { found: true, record: val, policy };
        break;
      }
    }
  }
  if (!spfFound) { result.checks.spf = { found: false }; result.missing.push("SPF"); }

  // --- DKIM ---
  const dkimSelectors = [];
  for (const sel of DKIM_SELECTORS) {
    const dkimTxt = await resolveDns(`${sel}._domainkey.${domain}`, "TXT");
    if (dkimTxt) dkimSelectors.push(sel);
  }
  if (dkimSelectors.length > 0) {
    result.score++;
    result.checks.dkim = { found: true, selectors: dkimSelectors };
  } else {
    result.checks.dkim = { found: false, selectorsChecked: DKIM_SELECTORS };
    result.missing.push("DKIM");
  }

  // --- DMARC ---
  const dmarcTxt = await resolveDns(`_dmarc.${domain}`, "TXT");
  let dmarcFound = false;
  if (dmarcTxt) {
    for (const rec of dmarcTxt) {
      const val = Array.isArray(rec) ? rec.join("") : rec;
      if (val.startsWith("v=DMARC1")) {
        dmarcFound = true;
        result.score++;
        let policy = "unknown";
        if (/p=reject/i.test(val)) policy = "reject";
        else if (/p=quarantine/i.test(val)) policy = "quarantine";
        else if (/p=none/i.test(val)) policy = "none (monitoring only)";
        result.checks.dmarc = { found: true, record: val, policy };
        break;
      }
    }
  }
  if (!dmarcFound) { result.checks.dmarc = { found: false }; result.missing.push("DMARC"); }

  // --- Grade ---
  const grades = { 4: "A", 3: "B", 2: "C", 1: "D", 0: "F" };
  result.grade = grades[result.score] || "F";

  return result;
}

async function sslCheck(domain) {
  domain = cleanDomain(domain);
  const result = { domain, error: null };

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      sock.destroy();
      result.error = "SSL check timed out after 10 seconds";
      resolve(result);
    }, 10000);

    const sock = tls.connect(443, domain, { rejectUnauthorized: false, servername: domain }, () => {
      clearTimeout(timeout);

      const cert = sock.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        result.error = "No SSL certificate found";
        sock.end();
        resolve(result);
        return;
      }

      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
      const isExpired = daysRemaining < 0;
      const authorized = sock.authorized;

      result.status = isExpired ? "EXPIRED" : !authorized ? "INVALID" : "VALID";
      result.commonName = cert.subject?.CN || null;
      result.altNames = cert.subjectaltname ? cert.subjectaltname.split(", ").map((s) => s.replace("DNS:", "")) : [];
      result.issuer = cert.issuer?.O || cert.issuer?.CN || "Unknown";
      result.validFrom = validFrom.toISOString().split("T")[0];
      result.validTo = validTo.toISOString().split("T")[0];
      result.daysRemaining = daysRemaining;
      result.expiryUrgency = isExpired ? "EXPIRED" : daysRemaining <= 14 ? "CRITICAL" : daysRemaining <= 30 ? "WARNING" : daysRemaining <= 60 ? "NOTICE" : "OK";
      result.protocol = sock.getProtocol?.() || null;
      result.serialNumber = cert.serialNumber || null;
      result.fingerprint256 = cert.fingerprint256 || null;

      sock.end();
      resolve(result);
    });

    sock.on("error", (err) => {
      clearTimeout(timeout);
      result.error = err.message;
      resolve(result);
    });
  });
}

// ---------------------------------------------------------------------------
// New tool implementations (tools 6–15)
// ---------------------------------------------------------------------------

const IP_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

async function reverseDns(target) {
  target = target.trim();
  const result = { target, isIp: IP_REGEX.test(target), resolvedIps: [], lookups: [] };

  const ipsToReverse = [];

  if (result.isIp) {
    ipsToReverse.push(target);
  } else {
    const domain = cleanDomain(target);
    result.resolvedFrom = domain;
    const aRecs = await resolveDns(domain, "A");
    const aaaaRecs = await resolveDns(domain, "AAAA");
    if (aRecs) aRecs.forEach((ip) => ipsToReverse.push(ip));
    if (aaaaRecs) aaaaRecs.forEach((ip) => ipsToReverse.push(ip));
    if (ipsToReverse.length === 0) {
      result.error = `Could not resolve ${domain} to any IP address`;
      return result;
    }
  }

  result.resolvedIps = ipsToReverse;

  for (const ip of ipsToReverse) {
    try {
      const hostnames = await new Promise((resolve, reject) => {
        dns.reverse(ip, (err, hosts) => (err ? reject(err) : resolve(hosts)));
      });
      const forwardChecks = [];
      for (const host of hostnames) {
        const fwd = await resolveDns(host, "A");
        forwardChecks.push({ hostname: host, forwardConfirmed: !!(fwd && fwd.includes(ip)) });
      }
      result.lookups.push({ ip, hostnames, forwardChecks });
    } catch {
      result.lookups.push({ ip, hostnames: [], error: "No reverse DNS (PTR) record found" });
    }
  }

  return result;
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
  const resolverResults = [];

  const queries = PUBLIC_RESOLVERS.map(async (r) => {
    const res = new dns.Resolver();
    res.setServers([r.ip]);
    try {
      const records = await new Promise((resolve, reject) => {
        const method = recordType === "AAAA" ? "resolve6" : "resolve4";
        res[method](domain, (err, addrs) => (err ? reject(err) : resolve(addrs)));
      });
      return { resolver: r.name, ip: r.ip, records: records.sort(), status: "ok" };
    } catch {
      return { resolver: r.name, ip: r.ip, records: [], status: "fail" };
    }
  });

  const all = await Promise.allSettled(queries);
  for (const a of all) {
    if (a.status === "fulfilled") resolverResults.push(a.value);
  }

  const answerSets = new Set();
  for (const r of resolverResults) {
    if (r.records.length > 0) answerSets.add(r.records.join(","));
  }

  const okCount = resolverResults.filter((r) => r.status === "ok").length;
  let propagationStatus;
  if (okCount === 0) propagationStatus = "NOT_PROPAGATED";
  else if (answerSets.size === 1) propagationStatus = "FULLY_PROPAGATED";
  else propagationStatus = "PARTIALLY_PROPAGATED";

  return { domain, recordType, resolvers: resolverResults, propagationStatus, respondingCount: okCount, uniqueAnswers: answerSets.size };
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
  const unique = [...new Set(SUBDOMAIN_PREFIXES)];
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

  // Categorize
  const categorized = {};
  const allCategorized = new Set(Object.values(SUBDOMAIN_CATEGORIES).flat());
  for (const [category, prefixes] of Object.entries(SUBDOMAIN_CATEGORIES)) {
    const catName = category.replace(/^[^\w]+\s*/, ""); // strip emoji prefix
    const matching = found.filter((f) => prefixes.includes(f.prefix));
    if (matching.length > 0) categorized[catName] = matching.map((m) => ({ subdomain: m.subdomain, ips: m.ips }));
  }
  const uncategorized = found.filter((f) => !allCategorized.has(f.prefix));
  if (uncategorized.length > 0) categorized["Other"] = uncategorized.map((m) => ({ subdomain: m.subdomain, ips: m.ips }));

  return { domain, prefixesChecked: unique.length, found: found.length, subdomains: found.map((f) => ({ subdomain: f.subdomain, ips: f.ips })), categories: categorized };
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
  const result = { domain, error: null, score: 0, maxScore: 0, grade: "F", critical: [], important: [], leakage: {} };

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
    result.error = `Could not connect to ${url}: ${err.message}`;
    return result;
  }

  result.maxScore = CRITICAL_HEADERS.reduce((s, h) => s + h.points, 0) + IMPORTANT_HEADERS.reduce((s, h) => s + h.points, 0);

  for (const h of CRITICAL_HEADERS) {
    const val = res.headers.get(h.name.toLowerCase());
    if (val) { result.score += h.points; result.critical.push({ header: h.name, present: true, value: val }); }
    else { result.critical.push({ header: h.name, present: false, tip: h.tip }); }
  }

  for (const h of IMPORTANT_HEADERS) {
    const val = res.headers.get(h.name.toLowerCase());
    if (val) { result.score += h.points; result.important.push({ header: h.name, present: true, value: val }); }
    else { result.important.push({ header: h.name, present: false, tip: h.tip }); }
  }

  const server = res.headers.get("server");
  result.leakage.server = server ? { disclosed: true, value: server, exposesVersion: /\/[\d.]+/.test(server) } : { disclosed: false };
  const powered = res.headers.get("x-powered-by");
  result.leakage.xPoweredBy = powered ? { disclosed: true, value: powered } : { disclosed: false };

  if (result.score >= 12) result.grade = "A";
  else if (result.score >= 9) result.grade = "B";
  else if (result.score >= 6) result.grade = "C";
  else if (result.score >= 3) result.grade = "D";
  else result.grade = "F";

  return result;
}

async function redirectChain(inputUrl, maxRedirects = 10) {
  let url = inputUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;

  const hops = [];
  let current = url;
  const visited = new Set();
  const startTime = Date.now();
  let loopDetected = false;

  for (let i = 0; i < maxRedirects; i++) {
    if (visited.has(current)) { loopDetected = true; break; }
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
        current = location.startsWith("http") ? location : new URL(location, current).href;
      } else {
        break;
      }
    } catch (err) {
      hops.push({ url: current, status: 0, statusText: `Error: ${err.message}`, location: null });
      break;
    }
  }

  const totalTimeMs = Date.now() - startTime;
  const urls = hops.map((h) => h.url);
  const hasHttpToHttps = urls.some((u, i) => u.startsWith("http://") && i + 1 < urls.length && (hops[i].location || "").startsWith("https://"));
  const hasWwwRedirect = urls.some((u, i) => {
    const loc = hops[i].location || "";
    return (!u.includes("://www.") && loc.includes("://www.")) || (u.includes("://www.") && !loc.includes("://www."));
  });
  const final = hops.length > 0 ? (hops[hops.length - 1].location || hops[hops.length - 1].url) : url;

  return { inputUrl: url, hops, totalHops: hops.length, finalUrl: final, totalTimeMs, loopDetected, httpToHttps: hasHttpToHttps, wwwRedirect: hasWwwRedirect };
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
  const result = { domain, error: null, technologies: {} };

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
    result.error = `Could not fetch ${url}: ${err.message}`;
    return result;
  }

  const detected = {
    cdn: new Set(),
    webServer: new Set(),
    framework: new Set(),
    cms: new Set(),
    cssFramework: new Set(),
    analytics: new Set(),
    liveChat: new Set(),
    hosting: new Set(),
  };

  for (const [header, tech] of Object.entries(TECH_SIGNATURES.headers)) {
    if (res.headers.get(header)) {
      if (["Cloudflare", "Amazon CloudFront", "Fastly"].includes(tech)) detected.cdn.add(tech);
      else detected.hosting.add(tech);
    }
  }

  const serverHeader = res.headers.get("server") || "";
  for (const sig of TECH_SIGNATURES.serverValues) {
    if (sig.pattern.test(serverHeader)) detected.webServer.add(sig.tech);
  }

  const powered = res.headers.get("x-powered-by") || "";
  if (/express/i.test(powered)) detected.framework.add("Express.js (Node.js)");
  if (/php/i.test(powered)) detected.framework.add("PHP");
  if (/asp\.net/i.test(powered)) detected.framework.add("ASP.NET");

  const genMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
  if (genMatch) {
    for (const sig of TECH_SIGNATURES.metaGenerator) {
      if (sig.pattern.test(genMatch[1])) detected.cms.add(sig.tech);
    }
  }

  for (const sig of TECH_SIGNATURES.htmlPatterns) {
    if (sig.pattern.test(body)) {
      const catMap = { framework: "framework", cms: "cms", css: "cssFramework", analytics: "analytics", chat: "liveChat" };
      const cat = catMap[sig.category] || "framework";
      detected[cat].add(sig.tech);
    }
  }

  for (const [cat, techs] of Object.entries(detected)) {
    if (techs.size > 0) result.technologies[cat] = [...techs];
  }

  // Raw headers of interest
  result.rawHeaders = {};
  const interestingHeaders = ["server", "x-powered-by", "via", "cf-ray", "x-cache", "x-vercel-id", "x-amz-cf-id"];
  for (const h of interestingHeaders) {
    const val = res.headers.get(h);
    if (val) result.rawHeaders[h] = val;
  }

  return result;
}

async function domainAge(domain) {
  domain = cleanDomain(domain);
  const baseDomain = getBaseDomain(domain);
  const result = { domain, queriedDomain: domain, error: null };

  try {
    let rec = await whoisWithRetry(domain);
    let createdRaw = rec.creationDate || rec.createdDate || rec.created || rec.CreationDate || null;

    // If subdomain has no creation date, try base domain
    if (!createdRaw && baseDomain !== domain) {
      rec = await whoisWithRetry(baseDomain);
      createdRaw = rec.creationDate || rec.createdDate || rec.created || rec.CreationDate || null;
      result.queriedDomain = baseDomain;
    }

    const updatedRaw = rec.updatedDate || rec.lastUpdated || rec.UpdatedDate || null;
    const expiryRaw = rec.registrarRegistrationExpirationDate || rec.expirationDate || rec.expiryDate || rec.expires || rec.ExpirationDate || null;

    if (!createdRaw) {
      result.error = `Could not determine creation date for ${domain} or ${baseDomain}`;
      return result;
    }

    const created = new Date(createdRaw);
    const now = new Date();

    let years = now.getFullYear() - created.getFullYear();
    let months = now.getMonth() - created.getMonth();
    let days = now.getDate() - created.getDate();
    if (days < 0) { months--; days += 30; }
    if (months < 0) { years--; months += 12; }

    result.created = created.toISOString().split("T")[0];
    result.updated = updatedRaw ? new Date(updatedRaw).toISOString().split("T")[0] : null;
    result.expires = expiryRaw ? new Date(expiryRaw).toISOString().split("T")[0] : null;
    result.age = { years, months, days };
    result.ageDescription = `${years} years, ${months} months, ${days} days`;

    const totalYears = years + months / 12;
    if (totalYears < 1) result.maturity = "very_new";
    else if (totalYears < 3) result.maturity = "new";
    else if (totalYears < 10) result.maturity = "established";
    else if (totalYears < 20) result.maturity = "well_established";
    else result.maturity = "veteran";

    if (expiryRaw) {
      const expiry = new Date(expiryRaw);
      const daysUntilExpiry = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
      result.daysUntilExpiry = daysUntilExpiry;
      const totalSpan = expiry - created;
      const usedSpan = now - created;
      result.registrationUsedPercent = Math.min(100, Math.max(0, Math.round((usedSpan / totalSpan) * 100)));
    }
  } catch (err) {
    result.error = err.message;
  }

  return result;
}

async function dnsCompare(domain1, domain2) {
  domain1 = cleanDomain(domain1);
  domain2 = cleanDomain(domain2);

  const types = ["A", "AAAA", "MX", "NS", "TXT"];
  const comparison = [];
  const differences = [];

  for (const t of types) {
    const [r1, r2] = await Promise.all([resolveDns(domain1, t), resolveDns(domain2, t)]);
    const fmt = (records) => {
      if (!records || records.length === 0) return [];
      return records.map((r) => {
        if (typeof r === "object" && r.exchange) return `${r.exchange} (pri ${r.priority})`;
        return Array.isArray(r) ? r.join("") : String(r);
      });
    };
    const f1 = fmt(r1);
    const f2 = fmt(r2);
    const match = JSON.stringify(r1 || []) === JSON.stringify(r2 || []);
    if (!match) differences.push(t);
    comparison.push({ type: t, [domain1]: f1, [domain2]: f2, match });
  }

  return { domain1, domain2, records: comparison, differences, identical: differences.length === 0 };
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

  let ports;
  if (portsArg === "common") {
    ports = COMMON_PORTS;
  } else {
    ports = portsArg.split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => p > 0 && p <= 65535);
    if (ports.length === 0) return { domain, error: "No valid ports specified" };
  }

  const aRecs = await resolveDns(domain, "A");
  const ip = aRecs ? aRecs[0] : domain;

  const startTime = Date.now();
  const results = await Promise.all(ports.map((p) => checkPort(ip, p)));
  const scanTimeMs = Date.now() - startTime;

  const portResults = results.map((r) => ({ port: r.port, service: PORT_SERVICES[r.port] || "Unknown", open: r.open }));
  const openCount = results.filter((r) => r.open).length;
  const openSet = new Set(results.filter((r) => r.open).map((r) => r.port));

  const insights = [];
  if (openSet.has(80) && openSet.has(443)) insights.push("HTTP and HTTPS both open");
  else if (openSet.has(443) && !openSet.has(80)) insights.push("HTTPS-only (good)");
  else if (openSet.has(80) && !openSet.has(443)) insights.push("HTTP open but no HTTPS - add SSL");
  const dbPorts = [3306, 5432];
  const openDb = dbPorts.filter((p) => openSet.has(p));
  if (openDb.length > 0) insights.push(`Database ports exposed: ${openDb.join(", ")} - security risk`);

  return { domain, resolvedIp: ip, ports: portResults, openCount, closedCount: results.length - openCount, totalChecked: results.length, scanTimeMs, insights };
}

async function domainReport(domain) {
  domain = cleanDomain(domain);
  const startTime = Date.now();

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

  const get = (i) => checks[i].status === "fulfilled" ? checks[i].value : { error: checks[i].reason?.message || "Check failed" };

  const dnsData = get(0);
  const whoisData = get(1);
  const emailData = get(2);
  const sslData = get(3);
  const headersData = get(4);
  const techData = get(5);
  const ageData = get(6);
  const portData = get(7);

  const elapsedMs = Date.now() - startTime;

  // Build actionable summary — tell the user WHAT matters, not just grades
  const dnsFound = dnsData.records ? Object.values(dnsData.records).filter((v) => v !== null).length : 0;
  const techList = techData.technologies ? Object.values(techData.technologies).flat() : [];

  // Collect urgent issues and recommendations
  const issues = [];
  const good = [];

  // DNS
  if (dnsFound > 0) good.push(`DNS is configured with ${dnsFound} record types`);
  else issues.push("No DNS records found - domain may not be resolving");

  // SSL
  if (sslData.status === "VALID") {
    if (sslData.daysRemaining <= 30) issues.push(`SSL certificate expires in ${sslData.daysRemaining} days - renew soon`);
    else good.push(`SSL valid (${sslData.issuer}, expires in ${sslData.daysRemaining} days)`);
  } else if (sslData.status === "EXPIRED") {
    issues.push("SSL certificate is EXPIRED - visitors will see security warnings");
  } else if (sslData.error) {
    issues.push(`SSL check failed: ${sslData.error}`);
  }

  // Email security - explain what's actually missing
  if (emailData.missing && emailData.missing.length > 0) {
    const emailIssues = [];
    if (emailData.missing.includes("MX")) emailIssues.push("no MX records (cannot receive email)");
    if (emailData.missing.includes("SPF")) emailIssues.push("no SPF (anyone can spoof your email)");
    if (emailData.missing.includes("DKIM")) emailIssues.push("no DKIM (emails not cryptographically signed)");
    if (emailData.missing.includes("DMARC")) emailIssues.push("no DMARC (no policy to reject spoofed emails)");
    issues.push(`Email security: ${emailIssues.join(", ")}`);
  } else if (emailData.score === emailData.maxScore) {
    good.push("Email security fully configured (MX, SPF, DKIM, DMARC)");
  }

  // HTTP headers - explain what's actually missing
  if (headersData.critical) {
    const missingCritical = headersData.critical.filter((h) => !h.present).map((h) => h.header);
    if (missingCritical.length > 0) {
      issues.push(`Missing security headers: ${missingCritical.join(", ")} - site vulnerable to XSS, clickjacking, MIME sniffing`);
    } else {
      good.push("All critical security headers present");
    }
  }

  // WHOIS / Age
  if (whoisData.created) good.push(`Registered since ${whoisData.created}`);
  if (whoisData.daysUntilExpiry && whoisData.daysUntilExpiry <= 90) issues.push(`Domain expires in ${whoisData.daysUntilExpiry} days - renew soon`);
  if (ageData.ageDescription) good.push(`Domain age: ${ageData.ageDescription}`);

  // Ports
  if (portData.insights) {
    for (const insight of portData.insights) {
      if (insight.includes("security risk")) issues.push(insight);
      else good.push(insight);
    }
  }

  // Tech
  if (techList.length > 0) good.push(`Tech stack: ${techList.join(", ")}`);

  return {
    domain,
    generatedAt: new Date().toISOString(),
    elapsedMs,
    issues,
    good,
    scores: {
      email: emailData.grade ? { grade: emailData.grade, score: emailData.score, max: emailData.maxScore, missing: emailData.missing } : null,
      headers: headersData.grade ? { grade: headersData.grade, score: headersData.score, max: headersData.maxScore } : null,
      ssl: sslData.status || null,
    },
    sections: {
      dns: dnsData,
      whois: whoisData,
      email: emailData,
      ssl: sslData,
      httpHeaders: headersData,
      techStack: techData,
      domainAge: ageData,
      ports: portData,
    },
  };
}

// ---------------------------------------------------------------------------
// Server card (for Smithery scanning / .well-known)
// ---------------------------------------------------------------------------

const CONFIG_SCHEMA = {
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
};

const SERVER_CARD = {
  // SEP-1649 server card fields
  serverInfo: {
    name: "mcp-domain-lookup",
    title: "Domain Inspector",
    version: "2.0.0",
  },
  description: "The most comprehensive domain intelligence MCP server. 15 tools for DNS, WHOIS, email security, SSL, HTTP headers, tech stack detection, subdomain discovery, port scanning, and more.",
  homepage: "https://mcpdns.onrender.com/about",
  iconUrl: "https://mcpdns.onrender.com/icon.svg",
  icons: [{ mimeType: "image/svg+xml", url: "https://mcpdns.onrender.com/icon.svg" }],
  transport: {
    type: "streamable-http",
    endpoint: "/mcp",
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
  prompts: [
    {
      name: "domain-check",
      description: "Run a full domain intelligence report with analysis and recommendations",
      arguments: {
        type: "object",
        properties: {
          domain: { type: "string", description: "Domain to analyze" }
        },
        required: ["domain"]
      }
    },
    {
      name: "security-audit",
      description: "Audit the security posture of a domain",
      arguments: {
        type: "object",
        properties: {
          domain: { type: "string", description: "Domain to audit" }
        },
        required: ["domain"]
      }
    },
    {
      name: "compare-domains",
      description: "Compare two domains side by side",
      arguments: {
        type: "object",
        properties: {
          domain1: { type: "string", description: "First domain" },
          domain2: { type: "string", description: "Second domain" }
        },
        required: ["domain1", "domain2"]
      }
    },
    {
      name: "find-subdomains",
      description: "Discover and analyze subdomains of a domain",
      arguments: {
        type: "object",
        properties: {
          domain: { type: "string", description: "Domain to scan" }
        },
        required: ["domain"]
      }
    }
  ],
  resources: [
    {
      uri: "info://tools",
      name: "Tool Catalog",
      description: "Complete list of all 15 domain intelligence tools with descriptions and parameters",
      mimeType: "application/json"
    },
    {
      uri: "info://server",
      name: "Server Information",
      description: "MCP Domain Lookup server metadata, version, and capabilities",
      mimeType: "application/json"
    }
  ]
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
      const data = await domainReport(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
      const data = await dnsLookup(domain, record_type);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- whois_lookup ---
  server.tool(
    "whois_lookup",
    "Get WHOIS registration data for a domain including registrar, creation/expiry dates, and days remaining.",
    { domain: z.string().describe("Domain name to look up (e.g. example.com)") },
    { title: "WHOIS Lookup", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await whoisLookup(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- domain_available ---
  server.tool(
    "domain_available",
    "Check whether a domain is available for registration. Suggests alternative TLDs if the domain is taken.",
    { domain: z.string().describe("Domain name to check (e.g. example.com)") },
    { title: "Domain Availability", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await domainAvailable(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- email_config_check ---
  server.tool(
    "email_config_check",
    "Audit email security configuration: MX, SPF, DKIM (common selectors), and DMARC records. Returns a letter grade A–F.",
    { domain: z.string().describe("Domain name to audit (e.g. example.com)") },
    { title: "Email Security Audit", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await emailConfigCheck(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- ssl_check ---
  server.tool(
    "ssl_check",
    "Check SSL/TLS certificate details for a domain: issuer, validity dates, days remaining, protocol, and fingerprint.",
    { domain: z.string().describe("Domain or hostname to check (e.g. example.com)") },
    { title: "SSL Certificate Check", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await sslCheck(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- reverse_dns ---
  server.tool(
    "reverse_dns",
    "Reverse DNS lookup — convert an IP address to its hostname(s), or find the IP behind a domain and do reverse lookup.",
    { target: z.string().describe("IP address or domain name (e.g. 8.8.8.8 or example.com)") },
    { title: "Reverse DNS", readOnlyHint: true, openWorldHint: true },
    async ({ target }) => {
      const data = await reverseDns(target);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
      const data = await dnsPropagation(domain, record_type);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- subdomain_finder ---
  server.tool(
    "subdomain_finder",
    "Discover common subdomains for a domain by checking ~80 common subdomain prefixes.",
    { domain: z.string().describe("Domain to scan for subdomains (e.g. example.com)") },
    { title: "Subdomain Finder", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await subdomainFinder(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- http_headers_check ---
  server.tool(
    "http_headers_check",
    "Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) and give a letter grade A–F.",
    { domain: z.string().describe("Domain or URL to check (e.g. example.com)") },
    { title: "HTTP Security Headers", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await httpHeadersCheck(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
      const data = await redirectChain(url, max_redirects);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- tech_stack_detect ---
  server.tool(
    "tech_stack_detect",
    "Detect the technology stack of a website: web server, CDN, framework, CMS, analytics, and more.",
    { domain: z.string().describe("Domain to analyze (e.g. example.com)") },
    { title: "Tech Stack Detector", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await techStackDetect(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // --- domain_age ---
  server.tool(
    "domain_age",
    "Calculate the exact age of a domain and show its registration timeline.",
    { domain: z.string().describe("Domain to check age of (e.g. example.com)") },
    { title: "Domain Age Calculator", readOnlyHint: true, openWorldHint: true },
    async ({ domain }) => {
      const data = await domainAge(domain);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
      const data = await dnsCompare(domain1, domain2);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
      const data = await portCheck(domain, ports);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
          name: SERVER_CARD.serverInfo.name,
          displayName: SERVER_CARD.serverInfo.title,
          version: SERVER_CARD.serverInfo.version,
          description: SERVER_CARD.description,
          toolCount: SERVER_CARD.tools.length,
          homepage: SERVER_CARD.homepage,
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
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));

// ---------------------------------------------------------------------------
// Transparent request + usage logging
// ---------------------------------------------------------------------------
// Logs are JSON lines so Render logs can be filtered/searched easily.
// We intentionally do not log authorization headers or full MCP session IDs.

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}

function truncate(value, max = 240) {
  if (value === undefined || value === null) return null;
  const str = String(value);
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function redactSessionId(sessionId) {
  if (!sessionId) return null;
  const str = String(sessionId);
  if (str.length <= 8) return "present";
  return `${str.slice(0, 4)}…${str.slice(-4)}`;
}

function safeQuery(query) {
  const result = {};
  for (const [key, value] of Object.entries(query || {})) {
    result[key] = Array.isArray(value) ? value.map((v) => truncate(v, 120)) : truncate(value, 120);
  }
  return result;
}

function getHeaderSnapshot(req) {
  return {
    host: truncate(req.headers.host),
    userAgent: truncate(req.headers["user-agent"]),
    referer: truncate(req.headers.referer || req.headers.referrer),
    origin: truncate(req.headers.origin),
    accept: truncate(req.headers.accept),
    contentType: truncate(req.headers["content-type"]),
    secFetchSite: truncate(req.headers["sec-fetch-site"]),
    forwardedHost: truncate(req.headers["x-forwarded-host"]),
    forwardedProto: truncate(req.headers["x-forwarded-proto"]),
    mcpSessionId: redactSessionId(req.headers["mcp-session-id"]),
  };
}

function inferSource(req) {
  const haystack = [
    req.headers["user-agent"],
    req.headers.referer,
    req.headers.referrer,
    req.headers.origin,
    req.headers.host,
    req.headers["x-forwarded-host"],
  ].filter(Boolean).join(" ").toLowerCase();

  const checks = [
    ["smithery", "Smithery"],
    ["mcp.so", "MCP.so"],
    ["mcpstore", "MCP Store"],
    ["mcpmarket", "MCP Market"],
    ["pulsemcp", "PulseMCP"],
    ["glama", "Glama"],
    ["lobehub", "LobeHub"],
    ["cursor", "Cursor"],
    ["claude", "Claude"],
    ["anthropic", "Anthropic/Claude"],
    ["vscode", "VS Code"],
    ["windsurf", "Windsurf"],
    ["github", "GitHub"],
    ["render", "Render"],
    ["uptime", "Uptime monitor"],
    ["bot", "Bot/Crawler"],
    ["spider", "Bot/Crawler"],
    ["crawler", "Bot/Crawler"],
    ["curl", "curl"],
    ["python-requests", "Python requests"],
  ];

  for (const [needle, label] of checks) {
    if (haystack.includes(needle)) {
      return { sourceGuess: label, sourceEvidence: needle };
    }
  }

  if (req.path === "/.well-known/mcp/server-card.json" || req.path === "/.well-known/mcp-config") {
    return { sourceGuess: "MCP discovery probe", sourceEvidence: req.path };
  }
  if (req.path === "/health") {
    return { sourceGuess: "Health check / uptime probe", sourceEvidence: req.path };
  }
  if (req.path === "/mcp") {
    return { sourceGuess: "MCP client", sourceEvidence: req.method };
  }
  if (req.path.startsWith("/api/")) {
    return { sourceGuess: "REST API client", sourceEvidence: req.path };
  }

  return { sourceGuess: "Unknown", sourceEvidence: null };
}

function logEvent(event, fields = {}) {
  console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }));
}

function shouldLogHealthChecks() {
  return String(process.env.LOG_HEALTH_CHECKS || "").toLowerCase() === "true";
}

function isHealthCheckRequest(req) {
  return req.path === "/health";
}

function isRenderHealthCheck(req) {
  return isHealthCheckRequest(req) && String(req.headers["user-agent"] || "").toLowerCase().includes("render");
}

function shouldSkipRequestLog(req) {
  // Render can call /health repeatedly during deploys and uptime checks. Keep
  // usage logs focused on real clients, MCP discovery, and tool calls by
  // hiding health checks unless explicitly enabled.
  return isHealthCheckRequest(req) && !shouldLogHealthChecks();
}

function getRpcSummary(body) {
  const method = body?.method || null;
  const toolName = method === "tools/call" ? body?.params?.name || null : null;
  const toolArgs = method === "tools/call" ? body?.params?.arguments || {} : {};
  const clientInfo = method === "initialize" ? body?.params?.clientInfo || null : null;
  return {
    rpcMethod: method,
    rpcId: body?.id ?? null,
    toolName,
    toolArgs: safeQuery(toolArgs),
    clientInfo,
  };
}

app.use((req, res, next) => {
  const started = Date.now();
  const requestId = crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader("x-request-id", requestId);

  res.on("finish", () => {
    if (shouldSkipRequestLog(req)) return;

    const inferred = inferSource(req);
    logEvent("http_request", {
      requestId,
      method: req.method,
      path: req.path,
      originalUrl: truncate(req.originalUrl, 500),
      status: res.statusCode,
      durationMs: Date.now() - started,
      ip: getClientIp(req),
      ...inferred,
      headers: getHeaderSnapshot(req),
      query: safeQuery(req.query),
    });
  });

  next();
});

// Session store: mcp-session-id → transport
// NOTE: In production with multiple instances, replace with Redis or similar shared store.
// Consider adding a TTL-based cleanup sweep for abandoned sessions.
const sessions = new Map();

// --- POST /mcp — main JSON-RPC handler (initialize + tool calls) ---
app.post("/mcp", async (req, res) => {
  try {
    const sessionId = req.headers["mcp-session-id"];
    const rpcSummary = getRpcSummary(req.body);

    logEvent("mcp_post", {
      requestId: req.requestId,
      ip: getClientIp(req),
      source: inferSource(req),
      sessionKnown: Boolean(sessionId && sessions.has(sessionId)),
      sessionId: redactSessionId(sessionId),
      headers: getHeaderSnapshot(req),
      ...rpcSummary,
    });

    if (sessionId && sessions.has(sessionId)) {
      // Existing session
      const transport = sessions.get(sessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // Only allow new sessions for initialize requests
    if (!isInitializeRequest(req.body)) {
      logEvent("mcp_rejected", {
        requestId: req.requestId,
        reason: "missing_or_invalid_session",
        rpcMethod: rpcSummary.rpcMethod,
        sessionId: redactSessionId(sessionId),
      });
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
        logEvent("mcp_session_initialized", {
          requestId: req.requestId,
          sessionId: redactSessionId(id),
          ip: getClientIp(req),
          source: inferSource(req),
          clientInfo: rpcSummary.clientInfo,
          activeSessions: sessions.size,
        });
      },
    });

    transport.onclose = () => {
      const id = transport.sessionId;
      if (id) sessions.delete(id);
      logEvent("mcp_session_closed", {
        requestId: req.requestId,
        sessionId: redactSessionId(id),
        activeSessions: sessions.size,
      });
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
  logEvent("mcp_stream_open", {
    requestId: req.requestId,
    ip: getClientIp(req),
    source: inferSource(req),
    sessionKnown: Boolean(sessionId && sessions.has(sessionId)),
    sessionId: redactSessionId(sessionId),
    headers: getHeaderSnapshot(req),
  });
  if (!sessionId || !sessions.has(sessionId)) {
    logEvent("mcp_rejected", {
      requestId: req.requestId,
      reason: "invalid_or_missing_session_for_stream",
      sessionId: redactSessionId(sessionId),
    });
    res.status(400).json({ error: "Invalid or missing session. Send an initialize request first." });
    return;
  }
  const transport = sessions.get(sessionId);
  await transport.handleRequest(req, res);
});

// --- DELETE /mcp — session cleanup ---
app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  logEvent("mcp_session_delete_requested", {
    requestId: req.requestId,
    ip: getClientIp(req),
    source: inferSource(req),
    sessionKnown: Boolean(sessionId && sessions.has(sessionId)),
    sessionId: redactSessionId(sessionId),
  });
  if (!sessionId || !sessions.has(sessionId)) {
    logEvent("mcp_rejected", {
      requestId: req.requestId,
      reason: "invalid_or_missing_session_for_delete",
      sessionId: redactSessionId(sessionId),
    });
    res.status(400).json({ error: "Invalid or missing session." });
    return;
  }
  const transport = sessions.get(sessionId);
  await transport.handleRequest(req, res);
  sessions.delete(sessionId);
  logEvent("mcp_session_deleted", {
    requestId: req.requestId,
    sessionId: redactSessionId(sessionId),
    activeSessions: sessions.size,
  });
});

// ---------------------------------------------------------------------------
// Simple REST API — no MCP handshake needed, just GET with ?domain=
// ---------------------------------------------------------------------------

const TOOL_MAP = {
  "domain-report": (q) => domainReport(q.domain),
  "dns-lookup": (q) => dnsLookup(q.domain, q.record_type || "ALL"),
  "whois": (q) => whoisLookup(q.domain),
  "domain-available": (q) => domainAvailable(q.domain),
  "email-security": (q) => emailConfigCheck(q.domain),
  "ssl": (q) => sslCheck(q.domain),
  "reverse-dns": (q) => reverseDns(q.target || q.domain),
  "dns-propagation": (q) => dnsPropagation(q.domain, q.record_type || "A"),
  "subdomains": (q) => subdomainFinder(q.domain),
  "http-headers": (q) => httpHeadersCheck(q.domain),
  "redirect-chain": (q) => redirectChain(q.url || `https://${q.domain}`, parseInt(q.max_redirects) || 10),
  "tech-stack": (q) => techStackDetect(q.domain),
  "domain-age": (q) => domainAge(q.domain),
  "dns-compare": (q) => dnsCompare(q.domain1, q.domain2),
  "port-check": (q) => portCheck(q.domain, q.ports || "common"),
};

app.get("/api/:tool", async (req, res) => {
  const toolName = req.params.tool;
  const tool = TOOL_MAP[toolName];

  logEvent("rest_tool_requested", {
    requestId: req.requestId,
    toolName,
    ip: getClientIp(req),
    source: inferSource(req),
    headers: getHeaderSnapshot(req),
    query: safeQuery(req.query),
  });

  if (!tool) {
    logEvent("rest_tool_rejected", {
      requestId: req.requestId,
      toolName,
      reason: "unknown_tool",
    });
    return res.status(404).json({ error: `Unknown tool: ${toolName}`, availableTools: Object.keys(TOOL_MAP) });
  }

  const needsDomain = !["redirect-chain", "reverse-dns", "dns-compare"].includes(toolName);
  if (needsDomain && !req.query.domain) {
    logEvent("rest_tool_rejected", {
      requestId: req.requestId,
      toolName,
      reason: "missing_domain",
    });
    return res.status(400).json({ error: "Missing required query parameter: domain", example: `/api/${toolName}?domain=example.com` });
  }
  if (toolName === "dns-compare" && (!req.query.domain1 || !req.query.domain2)) {
    logEvent("rest_tool_rejected", {
      requestId: req.requestId,
      toolName,
      reason: "missing_compare_domains",
    });
    return res.status(400).json({ error: "Missing required query parameters: domain1, domain2" });
  }

  try {
    const data = await tool(req.query);
    logEvent("rest_tool_completed", {
      requestId: req.requestId,
      toolName,
      domain: truncate(req.query.domain || req.query.target || req.query.domain1),
      source: inferSource(req),
    });
    res.json(data);
  } catch (err) {
    logEvent("rest_tool_failed", {
      requestId: req.requestId,
      toolName,
      error: err.message,
    });
    res.status(500).json({ error: err.message });
  }
});

// --- API index ---
app.get("/api", (req, res) => {
  logEvent("api_index_requested", {
    requestId: req.requestId,
    ip: getClientIp(req),
    source: inferSource(req),
    headers: getHeaderSnapshot(req),
  });
  res.json({
    description: "Domain Inspector REST API. Use any tool via simple GET requests.",
    baseUrl: "https://mcpdns.onrender.com/api",
    tools: Object.keys(TOOL_MAP).map((name) => ({
      endpoint: `/api/${name}`,
      example: name === "dns-compare" ? `/api/${name}?domain1=google.com&domain2=bing.com` : `/api/${name}?domain=example.com`,
    })),
  });
});

// --- Well-known server card ---
app.get("/.well-known/mcp/server-card.json", (req, res) => {
  logEvent("mcp_discovery_requested", {
    requestId: req.requestId,
    ip: getClientIp(req),
    source: inferSource(req),
    headers: getHeaderSnapshot(req),
  });
  res.json(SERVER_CARD);
});

// --- Well-known MCP config (Smithery reads configSchema from here for external servers) ---
app.get("/.well-known/mcp-config", (req, res) => {
  logEvent("mcp_config_requested", {
    requestId: req.requestId,
    ip: getClientIp(req),
    source: inferSource(req),
    headers: getHeaderSnapshot(req),
  });
  res.json({ configSchema: CONFIG_SCHEMA });
});

// --- Health check ---
app.get("/health", (req, res) => {
  if (shouldLogHealthChecks()) {
    logEvent("health_check", {
      requestId: req.requestId,
      ip: getClientIp(req),
      source: inferSource(req),
      renderHealthCheck: isRenderHealthCheck(req),
      headers: getHeaderSnapshot(req),
    });
  }
  res.json({ status: "ok", tools: SERVER_CARD.tools.length, version: SERVER_CARD.serverInfo.version });
});

// --- SVG icon ---
const ICON_SVG = `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="24" cy="24" r="22" stroke="#6366f1" stroke-width="2" opacity=".3"/><circle cx="24" cy="24" r="15" stroke="#818cf8" stroke-width="2"/><circle cx="24" cy="24" r="4" fill="#818cf8"/><line x1="24" y1="2" x2="24" y2="46" stroke="#6366f1" stroke-width="1" opacity=".3"/><ellipse cx="24" cy="24" rx="10" ry="22" stroke="#6366f1" stroke-width="1" opacity=".3"/></svg>`;
app.get("/icon.svg", (req, res) => {
  logEvent("asset_requested", { requestId: req.requestId, asset: "icon.svg", ip: getClientIp(req), source: inferSource(req) });
  res.type("image/svg+xml").send(ICON_SVG);
});

// --- Homepage ---
app.get("/about", (req, res) => {
  logEvent("page_requested", { requestId: req.requestId, page: "about", ip: getClientIp(req), source: inferSource(req), headers: getHeaderSnapshot(req) });
  res.type("html").send(HOMEPAGE_HTML);
});

// --- Legal pages ---
app.get("/terms", (req, res) => {
  logEvent("page_requested", { requestId: req.requestId, page: "terms", ip: getClientIp(req), source: inferSource(req), headers: getHeaderSnapshot(req) });
  res.type("html").send(TERMS_HTML);
});
app.get("/privacy", (req, res) => {
  logEvent("page_requested", { requestId: req.requestId, page: "privacy", ip: getClientIp(req), source: inferSource(req), headers: getHeaderSnapshot(req) });
  res.type("html").send(PRIVACY_HTML);
});

// --- Root — serve homepage for browsers, JSON for API clients ---
app.get("/", (req, res) => {
  logEvent("root_requested", { requestId: req.requestId, ip: getClientIp(req), source: inferSource(req), headers: getHeaderSnapshot(req) });
  const accept = req.headers.accept || "";
  if (accept.includes("text/html")) {
    res.type("html").send(HOMEPAGE_HTML);
    return;
  }
  res.json({
    name: "mcp-domain-lookup",
    displayName: "Domain Inspector",
    version: SERVER_CARD.serverInfo.version,
    description: SERVER_CARD.description,
    homepage: SERVER_CARD.homepage,
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
