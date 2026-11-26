# Architecture / البنية

```mermaid
flowchart LR
  B[Browser SPA<br/>React+TS+Tailwind<br/>AR RTL / EN LTR] -- "HTTPS-less loopback<br/>JWT Bearer" --> API
  subgraph Control plane (127.0.0.1 only)
    API[FastAPI<br/>RBAC · rate-limit · audit chain] --> DB[(V3 SQLite<br/>migrations)]
    SCH[Scheduler / health thread] --> DB
    API -. sanitized metadata only .-> OLL[Ollama 127.0.0.1:11434<br/>BEKO AI - unverified]
    API -. shared-secret header .-> WH[Local webhook / n8n]
  end
  subgraph Windows host (execution plane)
    AG[Restricted Agent<br/>pull-only · approved roots<br/>canonical paths · no links] -- "claim job / events / findings<br/>agent token" --> API
    AG --> W[Scan worker process<br/>hard timeout · cancel · rlimits]
    W --> E[Engines: secrets · source · config · docker · authz · taint · deps<br/>+ fixed-template external (VibeSec SARIF)]
    E -. read-only .-> SRC[(Approved project dirs)]
  end
```

```
Browser ──► API ──(DB job row: queued)──► Agent polls /agent/claim ──► worker subprocess (read-only scan)
   ▲                                                        │ redacted findings (batched) + progress events
   └────────── live events / findings / reports ◄───────────┘ API persists, normalises, scores, optional BEKO
```

Key properties
* **The API never reads project files.** Browsing / validation / discovery are RPCs answered by the agent, which is the only
  component holding the allow-list (`approved_roots` in its local config). A compromised API cannot widen it.
* The agent only makes **outbound** requests to loopback; there is no listening socket on the agent.
* Job states: `queued → running → completed | partial | failed | cancelled` (CHECK-constrained in the DB).
  `partial` = at least one engine failed while others succeeded. BEKO failures never change scan state.
* Findings carry a stable fingerprint (rule + file + normalised line hash) → triage state survives rescans, enabling
  new/fixed comparison and risk trends.
* Audit log is an append-only SHA-256 hash chain; `/api/audit/verify` detects edits.
