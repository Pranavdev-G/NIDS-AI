# NIDS AI - Network Intrusion Detection & Threat Analysis System

## Setup & Run

```bash
# 1. Install dependencies
npm install

# 2. Run dev server
npm run dev

# 3. Open in browser
# http://localhost:3000
```

## Project Structure

```
nids-complete/
├── package.json
├── next.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── postcss.config.mjs
├── components.json
├── .env
├── prisma/
│   └── schema.prisma
├── src/
│   ├── lib/
│   │   ├── utils.ts
│   │   ├── db.ts
│   │   └── nids-store.ts
│   ├── components/
│   │   └── ui/          (shadcn/ui components)
│   └── app/
│       ├── globals.css
│       ├── layout.tsx
│       ├── page.tsx      (Main NIDS Dashboard - all 6 pages)
│       └── api/
│           ├── health/route.ts
│           ├── stats/route.ts
│           ├── threats/route.ts
│           ├── network-events/route.ts
│           ├── alerts/route.ts
│           ├── traffic-history/route.ts
│           ├── threat-categories/route.ts
│           ├── signatures/route.ts
│           ├── analyze/route.ts
│           ├── chat/route.ts
│           ├── block-ip/route.ts
│           └── resolve-alert/route.ts
```

## 6 Pages
1. **Dashboard** - Live stats, traffic chart, category pie chart, recent threats
2. **Threat Log** - Searchable/filterable table, block & analyze actions
3. **Network Monitor** - Real-time connection flow cards
4. **AI Analysis** - Select threat → get AI-powered analysis
5. **Alerts** - Filter, resolve, block from alert cards
6. **AI Chat** - Interactive security assistant

## 12 API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/health | GET | System health check |
| /api/stats | GET | Dashboard statistics |
| /api/threats | GET | Threat log data |
| /api/network-events | GET | Network events |
| /api/alerts | GET/POST | Security alerts |
| /api/traffic-history | GET | Traffic time series |
| /api/threat-categories | GET | Category breakdown |
| /api/signatures | GET | Threat signature DB |
| /api/analyze | POST | AI threat analysis |
| /api/chat | POST | AI chat assistant |
| /api/block-ip | POST | Block IP address |
| /api/resolve-alert | POST | Resolve alert |

## Ollama AI Integration (Optional)
Currently runs in **simulation mode** (no AI server needed).
To enable real AI:
1. Install Ollama: https://ollama.ai
2. Run: ollama pull llama3.2
3. Set in .env: SIMULATION_MODE=false OLLAMA_BASE_URL=http://localhost:11434

## Tech Stack
- Next.js 16 + TypeScript + Tailwind CSS
- shadcn/ui + Lucide Icons + Recharts
- 8 Threat Types: SQL Injection, XSS, DDoS, Brute Force, Port Scan, Malware C2, Data Exfiltration, Privilege Escalation
