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

## Observability / Usage Logs

The server emits structured JSON logs for every request so you can see what is waking or using the service in Render logs.

Logged events include:

- `http_request` — every HTTP request with method, path, status, duration, client IP, selected headers, and query parameters
- `mcp_post` — MCP JSON-RPC calls, including initialize requests and `tools/call` tool names/arguments
- `mcp_session_initialized`, `mcp_stream_open`, `mcp_session_deleted`, `mcp_session_closed` — MCP session lifecycle events
- `mcp_discovery_requested` and `mcp_config_requested` — discovery probes for `.well-known` metadata
- `rest_tool_requested`, `rest_tool_completed`, `rest_tool_failed` — REST API tool usage
- `health_check`, `root_requested`, `page_requested` — health checks and page views

Health checks are skipped by default to keep Render logs quiet. Set `LOG_HEALTH_CHECKS=true` if you want to include `/health` requests in the logs while debugging deploy or uptime behavior.

Each request gets an `x-request-id` response header and a matching `requestId` in logs, making it easier to connect lifecycle/tool events to the final HTTP request log.

The logs include a best-effort `sourceGuess` / `sourceEvidence` based on user-agent, referer, origin, host, and path. This can identify likely traffic from common MCP directories/clients such as Smithery, MCP.so, MCP Store, MCP Market, PulseMCP, Glama, LobeHub, Cursor, Claude, VS Code, Windsurf, uptime checks, or generic bots. If a directory or client does not send an identifying user-agent/referer, attribution may remain `Unknown`, `MCP client`, or `MCP discovery probe`.

Sensitive values are intentionally limited: authorization headers are not logged, MCP session IDs are redacted, and long values are truncated.

## License

MIT
