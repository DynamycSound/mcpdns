# MCP Domain Lookup Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that provides DNS and domain intelligence tools. Designed to run as a remote MCP server over Streamable HTTP transport and publish on [Smithery.ai](https://smithery.ai/).

## Tools

| Tool | Description |
|------|-------------|
| `dns_lookup` | Look up DNS records (A, AAAA, MX, TXT, NS, CNAME) for any domain |
| `whois_lookup` | Get WHOIS registration data — registrar, dates, expiry countdown |
| `domain_available` | Check if a domain is available; suggests alternatives if taken |
| `email_config_check` | Audit email security (MX, SPF, DKIM, DMARC) with A–F grading |
| `ssl_check` | Inspect SSL/TLS certificate — issuer, expiry, trust status |

## Quick Start

```bash
npm install
npm start
```

The server starts on port `3000` by default (override with `PORT` env var).

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mcp` | MCP Streamable HTTP (JSON-RPC) |
| GET | `/mcp` | SSE stream for existing sessions |
| DELETE | `/mcp` | Session cleanup |
| GET | `/.well-known/mcp/server-card.json` | Server metadata card |
| GET | `/health` | Health check |
| GET | `/` | Server info |

## Deploy

Works on any Node.js host (Railway, Render, Fly.io, etc.):

1. Set the `PORT` environment variable if needed (most platforms inject it automatically).
2. Start command: `node server.js`

No API keys or external services required — all lookups use built-in DNS resolution, raw WHOIS queries, and direct TLS connections.

## License

MIT
