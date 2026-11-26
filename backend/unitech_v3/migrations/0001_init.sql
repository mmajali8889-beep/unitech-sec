CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL, role TEXT NOT NULL, locale TEXT NOT NULL DEFAULT 'en', active INTEGER NOT NULL DEFAULT 1,
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until REAL, must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL, last_login REAL);
CREATE TABLE sessions(jti TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, ip TEXT);
CREATE TABLE api_keys(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL, created_by TEXT, created_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, last_used REAL);
CREATE TABLE agents(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL,
  last_seen REAL, hostname TEXT, version TEXT, roots_json TEXT NOT NULL DEFAULT '[]', status_json TEXT NOT NULL DEFAULT '{}', engines_json TEXT NOT NULL DEFAULT '[]', revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE projects(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, canonical_path TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'generic',
  tags TEXT NOT NULL DEFAULT '', agent_id INTEGER REFERENCES agents(id), created_by TEXT, created_at REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1, last_scan_at REAL);
CREATE TABLE scan_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER REFERENCES projects(id), adhoc_path TEXT,
  target_kind TEXT NOT NULL, target_json TEXT NOT NULL DEFAULT '[]', engines_json TEXT NOT NULL, options_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL CHECK(state IN ('queued','running','completed','partial','failed','cancelled')),
  progress REAL NOT NULL DEFAULT 0, created_by TEXT, created_at REAL NOT NULL, started_at REAL, finished_at REAL,
  cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT, agent_id INTEGER REFERENCES agents(id), summary_json TEXT NOT NULL DEFAULT '{}',
  engine_status_json TEXT NOT NULL DEFAULT '{}', beko_state TEXT NOT NULL DEFAULT 'not_requested', schedule_id INTEGER, files_scanned INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL DEFAULT 0);
CREATE INDEX ix_jobs_state ON scan_jobs(state, agent_id);
CREATE TABLE job_events(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES scan_jobs(id), ts REAL NOT NULL, level TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX ix_events_job ON job_events(job_id, id);
CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES scan_jobs(id), project_id INTEGER, fingerprint TEXT NOT NULL,
  engine TEXT NOT NULL, rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  title TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 0, col INTEGER NOT NULL DEFAULT 0, snippet TEXT NOT NULL DEFAULT '',
  verification TEXT NOT NULL DEFAULT 'heuristic', remediation TEXT NOT NULL DEFAULT '', cwe TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open', status_note TEXT NOT NULL DEFAULT '', status_by TEXT, created_at REAL NOT NULL);
CREATE INDEX ix_findings_job ON findings(job_id); CREATE INDEX ix_findings_fp ON findings(project_id, fingerprint);
CREATE TABLE reports(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES scan_jobs(id), format TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, created_by TEXT, created_at REAL NOT NULL);
CREATE TABLE schedules(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, project_id INTEGER NOT NULL REFERENCES projects(id), engines_json TEXT NOT NULL, options_json TEXT NOT NULL DEFAULT '{}',
  interval_minutes INTEGER, daily_at TEXT, enabled INTEGER NOT NULL DEFAULT 1, next_run REAL, last_run REAL, last_job_id INTEGER, created_by TEXT, created_at REAL NOT NULL);
CREATE TABLE audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, role TEXT, action TEXT NOT NULL, target TEXT, ip TEXT, outcome TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}', prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE agent_rpc(id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL REFERENCES agents(id), kind TEXT NOT NULL, params_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', result_json TEXT, created_at REAL NOT NULL, done_at REAL);
CREATE TABLE ai_analyses(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES scan_jobs(id), model TEXT NOT NULL, state TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', error TEXT, human_reviewed INTEGER NOT NULL DEFAULT 0, reviewed_by TEXT, created_at REAL NOT NULL);
