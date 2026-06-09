-- =============================================================
-- Adaptive WAF using Reinforcement Learning
-- SQLite Database Schema
-- =============================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- -------------------------------------------------------------
-- Users Table: Admin and operator accounts
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    email           TEXT,
    role            TEXT DEFAULT 'admin',
    is_active       BOOLEAN DEFAULT 1,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login      TIMESTAMP,
    login_count     INTEGER DEFAULT 0
);

-- -------------------------------------------------------------
-- Request Logs: Every intercepted HTTP request
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address      TEXT NOT NULL,
    method          TEXT DEFAULT 'GET',
    path            TEXT,
    user_agent      TEXT,
    payload         TEXT,
    query_string    TEXT,
    headers         TEXT,
    threat_score    REAL DEFAULT 0.0,
    attack_type     TEXT DEFAULT 'none',
    action_taken    TEXT DEFAULT 'allow',
    response_status INTEGER DEFAULT 200,
    rl_decision     TEXT,
    rl_confidence   REAL DEFAULT 0.0,
    rl_action_id    INTEGER DEFAULT 0,
    triggered_rules TEXT,
    processing_time REAL DEFAULT 0.0,
    is_false_positive BOOLEAN DEFAULT 0,
    is_simulated    BOOLEAN DEFAULT 0,
    session_id      TEXT,
    country         TEXT DEFAULT 'Unknown',
    reward_given    REAL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip        ON request_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_request_logs_action    ON request_logs(action_taken);
CREATE INDEX IF NOT EXISTS idx_request_logs_attack    ON request_logs(attack_type);

-- -------------------------------------------------------------
-- Firewall Rules: Static + dynamically generated rules
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_rules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name           TEXT NOT NULL,
    rule_type           TEXT NOT NULL,      -- sqli, xss, brute_force, cmd_inject, path_traversal, ddos, bot
    pattern             TEXT NOT NULL,
    action              TEXT DEFAULT 'block',
    severity            TEXT DEFAULT 'medium', -- low, medium, high, critical
    is_active           BOOLEAN DEFAULT 1,
    is_dynamic          BOOLEAN DEFAULT 0,     -- RL-generated rule
    confidence          REAL DEFAULT 1.0,
    hit_count           INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    true_positive_count INTEGER DEFAULT 0,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP,
    created_by          TEXT DEFAULT 'system',
    description         TEXT
);

-- -------------------------------------------------------------
-- Blocked IPs: Auto-blacklisted IP addresses
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_ips (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT UNIQUE NOT NULL,
    reason          TEXT,
    threat_score    REAL DEFAULT 0.0,
    block_count     INTEGER DEFAULT 1,
    attack_types    TEXT,
    is_permanent    BOOLEAN DEFAULT 0,
    blocked_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP,
    unblocked_at    TIMESTAMP,
    created_by      TEXT DEFAULT 'rl_agent'
);

-- -------------------------------------------------------------
-- RL Metrics: Every RL training step
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rl_metrics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    episode             INTEGER DEFAULT 0,
    step                INTEGER DEFAULT 0,
    reward              REAL DEFAULT 0.0,
    cumulative_reward   REAL DEFAULT 0.0,
    action_taken        INTEGER DEFAULT 0,
    action_name         TEXT,
    state_vector        TEXT,
    epsilon             REAL DEFAULT 1.0,
    loss                REAL DEFAULT 0.0,
    q_value             REAL DEFAULT 0.0,
    true_positives      INTEGER DEFAULT 0,
    false_positives     INTEGER DEFAULT 0,
    true_negatives      INTEGER DEFAULT 0,
    false_negatives     INTEGER DEFAULT 0,
    sensitivity_level   REAL DEFAULT 0.5,
    rules_active        INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rl_metrics_timestamp ON rl_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_rl_metrics_episode   ON rl_metrics(episode);

-- -------------------------------------------------------------
-- Attack Events: Detected and confirmed attack instances
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address      TEXT,
    attack_type     TEXT NOT NULL,
    severity        TEXT DEFAULT 'medium',
    payload         TEXT,
    blocked         BOOLEAN DEFAULT 0,
    rule_triggered  TEXT,
    threat_score    REAL DEFAULT 0.0,
    rl_action       TEXT,
    country         TEXT DEFAULT 'Unknown',
    session_id      TEXT,
    is_simulated    BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_attack_events_timestamp  ON attack_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_events_type       ON attack_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_events_ip         ON attack_events(ip_address);

-- -------------------------------------------------------------
-- Model Feedback: Human corrections for RL training
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    request_log_id      INTEGER,
    feedback_type       TEXT NOT NULL,  -- confirmed_attack | false_positive | false_negative
    original_decision   TEXT,
    corrected_decision  TEXT,
    reason              TEXT,
    feedback_source     TEXT DEFAULT 'admin',
    applied_to_model    BOOLEAN DEFAULT 0,
    FOREIGN KEY (request_log_id) REFERENCES request_logs(id) ON DELETE SET NULL
);

-- -------------------------------------------------------------
-- System Settings: Configurable parameters
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key     TEXT UNIQUE NOT NULL,
    setting_value   TEXT NOT NULL,
    setting_type    TEXT DEFAULT 'string',  -- string | int | float | bool | json
    description     TEXT,
    category        TEXT DEFAULT 'general',
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by      TEXT DEFAULT 'system'
);

-- -------------------------------------------------------------
-- Audit Logs: Admin actions audit trail
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id     INTEGER,
    username    TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    details     TEXT,
    ip_address  TEXT,
    status      TEXT DEFAULT 'success',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- =============================================================
-- DEFAULT DATA INSERTS
-- =============================================================

-- Default admin user (password: admin123)
INSERT OR IGNORE INTO users (username, password_hash, email, role)
VALUES (
    'admin',
    'pbkdf2:sha256:600000$salt$hashed',  -- replaced at runtime
    'admin@adaptivewaf.io',
    'admin'
);

-- Default WAF Rules (ModSecurity-inspired)
INSERT OR IGNORE INTO firewall_rules (rule_name, rule_type, pattern, action, severity, description) VALUES
-- SQL Injection Rules
('SQLi Union Select',       'sqli', '(?i)(union[\s\+]+select)',                     'block', 'critical', 'Detects UNION-based SQL injection'),
('SQLi Comment Evasion',    'sqli', '(?i)(--[\s]*$|#[\s]*$|\/\*[\s\S]*?\*\/)',      'block', 'high',     'SQL comment evasion technique'),
('SQLi Quote Patterns',     'sqli', '(?i)(''[\s]*OR[\s]*''|''[\s]*AND[\s]*'')',     'block', 'high',     'Quote-based SQL injection'),
('SQLi Drop Table',         'sqli', '(?i)(drop[\s]+table|truncate[\s]+table)',       'block', 'critical', 'Destructive SQL commands'),
('SQLi Boolean Blind',      'sqli', '(?i)(AND[\s]+\d+=\d+|OR[\s]+\d+=\d+)',        'block', 'high',     'Boolean-based blind SQLi'),
('SQLi Time Based',         'sqli', '(?i)(sleep\(|benchmark\(|waitfor)',             'block', 'critical', 'Time-based blind SQL injection'),
('SQLi Stacked Queries',    'sqli', '(?i)(;[\s]*select|;[\s]*insert|;[\s]*update)', 'block', 'critical', 'Stacked query injection'),

-- XSS Rules
('XSS Script Tag',          'xss',  '(?i)(<script[\s>]|<\/script>)',               'block', 'critical', 'Script tag XSS injection'),
('XSS Event Handler',       'xss',  '(?i)(on(?:click|load|error|mouseover|focus|blur|change|submit)[\s]*=)', 'block', 'high', 'Event handler XSS'),
('XSS JavaScript URI',      'xss',  '(?i)(javascript[\s]*:)',                       'block', 'high',     'JavaScript URI XSS'),
('XSS SVG Injection',       'xss',  '(?i)(<svg[\s>].*?on\w+[\s]*=)',              'block', 'high',     'SVG-based XSS'),
('XSS Data URI',            'xss',  '(?i)(data:[\s]*text\/html)',                   'block', 'medium',   'Data URI XSS'),
('XSS IMG Tag',             'xss',  '(?i)(<img[\s]+[^>]*onerror)',                  'block', 'high',     'IMG onerror XSS'),

-- Command Injection Rules
('CMD Pipe Injection',      'cmd_inject', '(?i)([|;`&$][\s]*(?:ls|cat|rm|wget|curl|bash|sh|python|perl|nc))', 'block', 'critical', 'Shell command injection'),
('CMD System Functions',    'cmd_inject', '(?i)(system\(|exec\(|shell_exec\(|passthru\(|popen\()',           'block', 'critical', 'PHP shell function calls'),
('CMD Path Execution',      'cmd_inject', '(?i)(\/bin\/|\/usr\/bin\/|\/sbin\/)',                               'block', 'high',     'Absolute path execution'),

-- Path Traversal Rules
('Path Traversal Dotdot',   'path_traversal', '(?i)(\.\.\/|\.\.\\\\|%2e%2e%2f|%252e%252e)',              'block', 'high',     'Directory traversal attempt'),
('Path Traversal Abs',      'path_traversal', '(?i)(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)',            'block', 'critical', 'Sensitive file access'),
('Path Traversal Win',      'path_traversal', '(?i)(c:\\\\windows|c:\\\\system32|\.\.%5c)',               'block', 'high',     'Windows path traversal'),

-- Bot/Scanner Detection
('Scanner User Agent',      'bot',  '(?i)(sqlmap|nikto|nessus|openvas|masscan|zap|burpsuite|nmap)', 'block', 'critical', 'Known security scanner UA'),
('Bot User Agent',          'bot',  '(?i)(wget\/|curl\/\d|python-requests|go-http-client)',          'block', 'medium',   'Automated tool user agent'),

-- DDoS/Flood Rules
('HTTP Flood Marker',       'ddos', 'RATE_LIMIT_EXCEEDED',                          'block', 'high',     'Rate limit exceeded marker'),

-- LFI/RFI
('LFI PHP Wrappers',        'lfi',  '(?i)(php:\/\/filter|php:\/\/input|data:\/\/)',  'block', 'critical', 'PHP wrapper LFI'),
('RFI Remote Include',      'lfi',  '(?i)(https?:\/\/.*\.(php|txt|xml)\?)',          'block', 'high',     'Remote file inclusion');

-- Default System Settings
INSERT OR IGNORE INTO system_settings (setting_key, setting_value, setting_type, description, category) VALUES
('waf_enabled',             'true',     'bool',     'Master WAF on/off switch',                         'waf'),
('threat_threshold',        '0.5',      'float',    'Score above which request is flagged suspicious',  'waf'),
('block_threshold',         '0.75',     'float',    'Score above which request is blocked',             'waf'),
('max_requests_per_min',    '100',      'int',      'Max requests per IP per minute',                   'waf'),
('auto_blacklist_enabled',  'true',     'bool',     'Auto-blacklist IPs after threshold',               'waf'),
('blacklist_threshold',     '5',        'int',      'Attack count before auto-blacklist',               'waf'),
('blacklist_duration_min',  '60',       'int',      'Minutes to keep IP blacklisted',                   'waf'),
('rl_enabled',              'true',     'bool',     'Enable RL adaptive learning',                      'rl'),
('rl_epsilon',              '0.1',      'float',    'RL exploration rate (epsilon-greedy)',              'rl'),
('rl_learning_rate',        '0.001',    'float',    'DQN neural network learning rate',                 'rl'),
('rl_gamma',                '0.95',     'float',    'RL discount factor',                               'rl'),
('rl_update_frequency',     '10',       'int',      'Steps between RL model updates',                   'rl'),
('sensitivity_level',       '0.5',      'float',    'Current WAF sensitivity (0=loose, 1=tight)',       'waf'),
('demo_mode',               'false',    'bool',     'Enable guided demonstration mode',                  'general'),
('rollback_enabled',        'true',     'bool',     'Enable safety rollback for unstable RL',           'safety'),
('max_sensitivity',         '0.95',     'float',    'Maximum allowed WAF sensitivity',                  'safety'),
('min_sensitivity',         '0.1',      'float',    'Minimum allowed WAF sensitivity',                  'safety'),
('cooldown_timer',          '30',       'int',      'Seconds between major rule changes',               'safety'),
('captcha_threshold',       '0.65',     'float',    'Threat score to trigger adaptive CAPTCHA',         'waf'),
('anomaly_detection',       'true',     'bool',     'Enable statistical anomaly detection layer',       'waf'),
('log_retention_days',      '30',       'int',      'Days to retain request logs',                      'general');
