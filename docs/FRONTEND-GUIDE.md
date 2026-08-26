---

# The Cormorant — Frontend Guide

## Quick Start

1. Open WSL terminal, run: `gullwing serve`
2. Open browser, go to: `unified.html`
3. The API dot turns green. You're ready.

## The Three Interfaces

### 1. Cormorant Unified (`unified.html`) — **Main Interface**

Four tabs, one page:

| Tab | What It Does |
|-----|-------------|
| **🔍 Analyze** | WCC libify any binary, deep scan all functions, see Gullwing verdict |
| **📊 Dashboard** | Model health, system status, integrity verification |
| **🤖 MCP** | See available AI tools, test prompts in natural language |
| **📡 Monitor** | Instructions for live watch + agent |

**Key actions:**
- Type a path → click **Libify & Analyze** → see exported functions + verdict
- Click **Deep Scan** → see all callable functions across all libraries
- MCP tab → type a question → click **Send to API** → get plain-English answer

### 2. Browser Popup — **Quick Scan**

Click the 🪽 icon in your browser toolbar.

- Green dot = API online. Red dot = offline.
- Type a file path → click **Scan Binary** → instant verdict
- Shows recent analyses at the bottom

### 3. Dashboard (`dashboard.html`) — **System Overview**

- Auto-refreshes every 5 seconds
- Shows API status, model info, system health
- Alert feed and risk bars (requires `gullwing watch` running)

## How It Works

```
Browser (Windows) → HTTP request → WSL (Linux) → Gullwing API → JSON response → Browser displays it
```

Every click sends a request to `http://127.0.0.1:9393`. The API runs the tools in WSL and returns results. The browser renders them. Two operating systems, one seamless pipeline.

## Common Tasks

| Task | Where | How |
|------|-------|-----|
| Analyze a binary | Unified → Analyze tab | Type path, click Libify & Analyze |
| See all functions | Unified → Analyze tab | Click Deep Scan |
| Quick file check | Browser popup | Type path, click Scan Binary |
| Check system health | Dashboard or Unified → Dashboard tab | Auto-refreshes |
| Test AI integration | Unified → MCP tab | Type question, click Send to API |
| Get raw API response | Any browser | Open `http://127.0.0.1:9393/status` |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| API dot is red | Run `gullwing serve` in WSL terminal |
| Dashboard shows — | Some data needs terminal commands (SBOM, quarantine) |
| Alert feed empty | Start `gullwing watch` and `gullwing agent watch` in terminals |
| Popup icon grey | Go to `chrome://extensions`, refresh Gullwing |
| MCP tab shows "undefined" | API may need restart: `pkill -f moabi-serve && gullwing serve` |

## Ports and URLs

| Service | URL |
|---------|-----|
| Gullwing API | `http://127.0.0.1:9393` |
| API Status | `http://127.0.0.1:9393/status` |
| API Health | `http://127.0.0.1:9393/health` |
| MCP Schema | `http://127.0.0.1:9393/mcp` |

---
