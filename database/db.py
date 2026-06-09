"""database/db.py — SQLite access layer for Adaptive WAF."""
import sqlite3, json, logging
from datetime import datetime, timedelta
from flask import g

logger = logging.getLogger(__name__)

def get_db():
    if "db" not in g:
        from flask import current_app
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_app(app):
    app.teardown_appcontext(close_db)

def init_db(app):
    import os
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
    with app.app_context():
        db = get_db()
        _create_tables(db)
        _seed_data(db)
        logger.info("Database initialised.")

def _create_tables(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            email TEXT, role TEXT DEFAULT 'admin', is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT, login_count INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL, method TEXT DEFAULT 'GET',
            path TEXT, user_agent TEXT, payload TEXT,
            query_string TEXT, headers TEXT,
            threat_score REAL DEFAULT 0.0, attack_type TEXT DEFAULT 'none',
            action_taken TEXT DEFAULT 'allow', response_status INTEGER DEFAULT 200,
            rl_decision TEXT, rl_confidence REAL DEFAULT 0.0, rl_action_id INTEGER DEFAULT 0,
            triggered_rules TEXT, processing_time REAL DEFAULT 0.0,
            is_false_positive INTEGER DEFAULT 0, is_simulated INTEGER DEFAULT 0,
            session_id TEXT, country TEXT DEFAULT 'Unknown', reward_given REAL DEFAULT 0.0);
        CREATE TABLE IF NOT EXISTS attack_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT, attack_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium', payload TEXT,
            blocked INTEGER DEFAULT 0, rule_triggered TEXT,
            threat_score REAL DEFAULT 0.0, rl_action TEXT,
            country TEXT DEFAULT 'Unknown', session_id TEXT, is_simulated INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS rl_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            episode INTEGER DEFAULT 0, step INTEGER DEFAULT 0,
            reward REAL DEFAULT 0.0, cumulative_reward REAL DEFAULT 0.0,
            action_taken INTEGER DEFAULT 0, action_name TEXT, state_vector TEXT,
            epsilon REAL DEFAULT 1.0, loss REAL DEFAULT 0.0, q_value REAL DEFAULT 0.0,
            true_positives INTEGER DEFAULT 0, false_positives INTEGER DEFAULT 0,
            true_negatives INTEGER DEFAULT 0, false_negatives INTEGER DEFAULT 0,
            sensitivity_level REAL DEFAULT 0.5, rules_active INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL, rule_type TEXT NOT NULL, pattern TEXT NOT NULL,
            action TEXT DEFAULT 'block', severity TEXT DEFAULT 'medium',
            is_active INTEGER DEFAULT 1, is_dynamic INTEGER DEFAULT 0,
            confidence REAL DEFAULT 1.0, hit_count INTEGER DEFAULT 0,
            false_positive_count INTEGER DEFAULT 0, true_positive_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT, created_by TEXT DEFAULT 'system', description TEXT);
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL, reason TEXT,
            threat_score REAL DEFAULT 0.0, block_count INTEGER DEFAULT 1,
            attack_types TEXT, is_permanent INTEGER DEFAULT 0,
            blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT, unblocked_at TEXT, created_by TEXT DEFAULT 'rl_agent');
        CREATE TABLE IF NOT EXISTS model_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            request_log_id INTEGER, feedback_type TEXT NOT NULL,
            original_decision TEXT, corrected_decision TEXT,
            reason TEXT, feedback_source TEXT DEFAULT 'admin', applied_to_model INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL, setting_value TEXT NOT NULL,
            setting_type TEXT DEFAULT 'string', description TEXT,
            category TEXT DEFAULT 'general',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_by TEXT DEFAULT 'system');
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER, username TEXT, action TEXT NOT NULL,
            resource TEXT, details TEXT, ip_address TEXT, status TEXT DEFAULT 'success');
    """)
    db.commit()

def _seed_data(db):
    from werkzeug.security import generate_password_hash
    db.execute(
        "INSERT OR IGNORE INTO users (username,password_hash,email,role) VALUES (?,?,?,?)",
        ("admin", generate_password_hash("admin123"), "admin@waf.local", "admin"))
    rules = [
        ("SQL UNION Attack",     "sqli",          r"(?i)(union[\s\+]+select)",                  "block","critical","UNION-based SQLi"),
        ("SQL DROP Table",       "sqli",          r"(?i)(drop[\s]+table|truncate[\s]+table)",   "block","critical","Destructive SQL"),
        ("SQL Time-Based Blind", "sqli",          r"(?i)(sleep\(|benchmark\(|waitfor)",         "block","critical","Time-based SQLi"),
        ("SQL Comment Evasion",  "sqli",          r"(?i)(--\s*$)",                              "block","high",    "SQL comment injection"),
        ("SQL OR 1=1",           "sqli",          r"(?i)('\s*or\s+'|or\s+1\s*=\s*1)",          "block","high",    "Classic OR injection"),
        ("SQL Schema Enum",      "sqli",          r"(?i)(information_schema|sys\.tables)",      "block","high",    "Schema enumeration"),
        ("SQL Stacked Query",    "sqli",          r"(?i)(;\s*(select|insert|update|delete))",   "block","critical","Stacked queries"),
        ("XSS Script Tag",       "xss",           r"(?i)(<script[\s>]|<\/script>)",             "block","critical","Script tag XSS"),
        ("XSS Event Handler",    "xss",           r"(?i)(on(click|load|error|focus)\s*=)",      "block","high",    "Event handler XSS"),
        ("XSS JavaScript URI",   "xss",           r"(?i)(javascript\s*:)",                      "block","high",    "JS URI XSS"),
        ("XSS Image Error",      "xss",           r"(?i)(<img[^>]+onerror)",                    "block","high",    "Image onerror XSS"),
        ("XSS SVG Injection",    "xss",           r"(?i)(<svg[^>]+onload)",                     "block","high",    "SVG onload XSS"),
        ("CMD Shell Pipe",       "cmd_inject",    r"(?i)([|;`]\s*(cat|ls|rm|wget|bash|curl))",  "block","critical","Shell injection"),
        ("CMD PHP Functions",    "cmd_inject",    r"(?i)(system\(|exec\(|shell_exec\()",        "block","critical","PHP shell functions"),
        ("CMD Path Execution",   "cmd_inject",    r"(?i)(\/bin\/(sh|bash)|\/usr\/bin\/)",       "block","high",    "Direct path execution"),
        ("Path Traversal",       "path_traversal",r"(?i)(\.\./|\.\.\\\\|%2e%2e%2f)",           "block","high",    "Directory traversal"),
        ("Sensitive Files",      "path_traversal",r"(?i)(\/etc\/passwd|\/etc\/shadow)",         "block","critical","Sensitive file access"),
        ("Scanner User-Agent",   "bot",           r"(?i)(sqlmap|nikto|nessus|nmap|masscan|zap)","block","critical","Known scanners"),
        ("Bot User-Agent",       "bot",           r"(?i)(curl\/[0-9]|python-requests)",         "block","medium",  "Automated tools"),
        ("PHP LFI Wrapper",      "lfi",           r"(?i)(php:\/\/filter|php:\/\/input)",        "block","critical","PHP LFI wrappers"),
    ]
    for r in rules:
        db.execute(
            "INSERT OR IGNORE INTO firewall_rules (rule_name,rule_type,pattern,action,severity,description) VALUES (?,?,?,?,?,?)", r)
    settings = [
        ("waf_enabled","true","bool","Master WAF on/off","waf"),
        ("threat_threshold","0.5","float","Suspicious flag threshold","waf"),
        ("block_threshold","0.75","float","Block threshold","waf"),
        ("max_requests_per_min","100","int","Rate limit per IP","waf"),
        ("auto_blacklist_enabled","true","bool","Auto-blacklist IPs","waf"),
        ("blacklist_threshold","5","int","Attacks before blacklist","waf"),
        ("blacklist_duration_min","60","int","Blacklist duration (min)","waf"),
        ("rl_enabled","true","bool","Enable RL learning","rl"),
        ("rl_epsilon","0.1","float","Exploration rate (epsilon)","rl"),
        ("rl_learning_rate","0.001","float","DQN learning rate","rl"),
        ("rl_gamma","0.95","float","Discount factor gamma","rl"),
        ("rl_update_frequency","10","int","Target net update steps","rl"),
        ("sensitivity_level","0.5","float","WAF sensitivity (0-1)","waf"),
        ("demo_mode","false","bool","Guided demo mode","general"),
        ("rollback_enabled","true","bool","Safety rollback","safety"),
        ("max_sensitivity","0.95","float","Max allowed sensitivity","safety"),
        ("min_sensitivity","0.1","float","Min allowed sensitivity","safety"),
        ("cooldown_timer","30","int","Change cooldown (seconds)","safety"),
        ("captcha_threshold","0.65","float","Captcha trigger threshold","waf"),
        ("anomaly_detection","true","bool","Anomaly detection layer","waf"),
        ("log_retention_days","30","int","Log retention (days)","general"),
    ]
    for s in settings:
        db.execute(
            "INSERT OR IGNORE INTO system_settings (setting_key,setting_value,setting_type,description,category) VALUES (?,?,?,?,?)", s)
    db.commit()

# ─── Query helpers ───────────────────────────────────────────────────────────
def log_request(db, data):
    cur = db.execute(
        """INSERT INTO request_logs (ip_address,method,path,user_agent,payload,query_string,headers,
           threat_score,attack_type,action_taken,response_status,rl_decision,rl_confidence,rl_action_id,
           triggered_rules,processing_time,is_simulated,session_id,country,reward_given)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (data.get("ip_address",""), data.get("method","GET"), data.get("path","/"),
         data.get("user_agent",""), data.get("payload",""), data.get("query_string",""),
         json.dumps(data.get("headers",{})), data.get("threat_score",0.0),
         data.get("attack_type","none"), data.get("action_taken","allow"),
         data.get("response_status",200), data.get("rl_decision",""),
         data.get("rl_confidence",0.0), data.get("rl_action_id",0),
         json.dumps(data.get("triggered_rules",[])), data.get("processing_time",0.0),
         int(data.get("is_simulated",False)), data.get("session_id",""),
         data.get("country","Unknown"), data.get("reward_given",0.0)))
    db.commit()
    return cur.lastrowid

def get_recent_logs(db, limit=50):
    return [dict(r) for r in db.execute("SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]

def get_log_stats(db):
    total   = db.execute("SELECT COUNT(*) FROM request_logs").fetchone()[0]
    blocked = db.execute("SELECT COUNT(*) FROM request_logs WHERE action_taken='block'").fetchone()[0]
    allowed = db.execute("SELECT COUNT(*) FROM request_logs WHERE action_taken='allow'").fetchone()[0]
    attacks = db.execute("SELECT COUNT(*) FROM request_logs WHERE attack_type != 'none'").fetchone()[0]
    fp      = db.execute("SELECT COUNT(*) FROM request_logs WHERE is_false_positive=1").fetchone()[0]
    return {"total":total,"blocked":blocked,"allowed":allowed,"attacks":attacks,"false_positives":fp}

def get_attack_distribution(db):
    return [dict(r) for r in db.execute(
        "SELECT attack_type, COUNT(*) AS cnt FROM request_logs WHERE attack_type != 'none' GROUP BY attack_type ORDER BY cnt DESC"
    ).fetchall()]

def get_recent_attacks(db, limit=20):
    return [dict(r) for r in db.execute("SELECT * FROM attack_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]

def get_top_ips(db, limit=10):
    return [dict(r) for r in db.execute(
        """SELECT ip_address, COUNT(*) AS total,
           SUM(CASE WHEN action_taken='block' THEN 1 ELSE 0 END) AS blocked,
           AVG(threat_score) AS avg_score
           FROM request_logs GROUP BY ip_address ORDER BY total DESC LIMIT ?""", (limit,)
    ).fetchall()]

def get_timeline_data(db, hours=24):
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    return [dict(r) for r in db.execute(
        """SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour,
           COUNT(*) AS total,
           SUM(CASE WHEN action_taken='block' THEN 1 ELSE 0 END) AS blocked
           FROM request_logs WHERE timestamp >= ? GROUP BY hour ORDER BY hour""", (since,)
    ).fetchall()]

def get_active_rules(db):
    return [dict(r) for r in db.execute("SELECT * FROM firewall_rules WHERE is_active=1 ORDER BY id").fetchall()]

def get_all_rules(db):
    return [dict(r) for r in db.execute("SELECT * FROM firewall_rules ORDER BY is_active DESC, created_at DESC").fetchall()]

def add_dynamic_rule(db, rule_name, rule_type, pattern, action="block", severity="high",
                     confidence=0.85, expires_hours=24, description=""):
    expires_at = (datetime.utcnow() + timedelta(hours=expires_hours)).strftime("%Y-%m-%d %H:%M:%S")
    cur = db.execute(
        """INSERT INTO firewall_rules (rule_name,rule_type,pattern,action,severity,is_active,is_dynamic,
           confidence,expires_at,created_by,description) VALUES (?,?,?,?,?,1,1,?,?,?,?)""",
        (rule_name,rule_type,pattern,action,severity,confidence,expires_at,"rl_agent",description))
    db.commit()
    return cur.lastrowid

def increment_rule_hit(db, rule_id, is_fp=False):
    if is_fp:
        db.execute("UPDATE firewall_rules SET hit_count=hit_count+1, false_positive_count=false_positive_count+1 WHERE id=?", (rule_id,))
    else:
        db.execute("UPDATE firewall_rules SET hit_count=hit_count+1, true_positive_count=true_positive_count+1 WHERE id=?", (rule_id,))
    db.commit()

def is_ip_blocked(db, ip):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    row = db.execute(
        "SELECT id FROM blocked_ips WHERE ip_address=? AND (expires_at IS NULL OR expires_at > ?) AND unblocked_at IS NULL",
        (ip, now)).fetchone()
    return row is not None

def block_ip(db, ip, reason="", threat_score=0.0, attack_types="", is_permanent=False, duration_min=60, created_by="rl_agent"):
    expires_at = None if is_permanent else (datetime.utcnow() + timedelta(minutes=duration_min)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        """INSERT INTO blocked_ips (ip_address,reason,threat_score,attack_types,is_permanent,expires_at,created_by)
           VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(ip_address) DO UPDATE SET block_count=block_count+1,
           reason=excluded.reason, expires_at=excluded.expires_at, unblocked_at=NULL""",
        (ip,reason,threat_score,attack_types,int(is_permanent),expires_at,created_by))
    db.commit()

def unblock_ip(db, ip):
    db.execute("UPDATE blocked_ips SET unblocked_at=CURRENT_TIMESTAMP WHERE ip_address=?", (ip,))
    db.commit()

def get_blocked_ips(db):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return [dict(r) for r in db.execute(
        "SELECT * FROM blocked_ips WHERE unblocked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY blocked_at DESC", (now,)
    ).fetchall()]

def log_rl_metric(db, data):
    cur = db.execute(
        """INSERT INTO rl_metrics (episode,step,reward,cumulative_reward,action_taken,action_name,
           state_vector,epsilon,loss,q_value,true_positives,false_positives,true_negatives,false_negatives,
           sensitivity_level,rules_active) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (data.get("episode",0), data.get("step",0), data.get("reward",0.0),
         data.get("cumulative_reward",0.0), data.get("action_taken",0), data.get("action_name",""),
         json.dumps(data.get("state_vector",[])), data.get("epsilon",1.0), data.get("loss",0.0),
         data.get("q_value",0.0), data.get("true_positives",0), data.get("false_positives",0),
         data.get("true_negatives",0), data.get("false_negatives",0),
         data.get("sensitivity_level",0.5), data.get("rules_active",0)))
    db.commit()
    return cur.lastrowid

def get_rl_metrics(db, limit=200):
    rows = db.execute("SELECT * FROM rl_metrics ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in reversed(rows)]

def get_rl_summary(db):
    row = db.execute(
        """SELECT COUNT(*) AS steps, AVG(reward) AS avg_reward, MAX(cumulative_reward) AS max_cumulative,
           AVG(epsilon) AS avg_epsilon, AVG(loss) AS avg_loss,
           SUM(true_positives) AS total_tp, SUM(false_positives) AS total_fp,
           SUM(true_negatives) AS total_tn, SUM(false_negatives) AS total_fn FROM rl_metrics"""
    ).fetchone()
    return dict(row) if row else {}

def log_attack_event(db, data):
    cur = db.execute(
        """INSERT INTO attack_events (ip_address,attack_type,severity,payload,blocked,rule_triggered,
           threat_score,rl_action,country,is_simulated) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (data.get("ip_address",""), data.get("attack_type","unknown"), data.get("severity","medium"),
         data.get("payload",""), int(data.get("blocked",False)), data.get("rule_triggered",""),
         data.get("threat_score",0.0), data.get("rl_action",""),
         data.get("country","Unknown"), int(data.get("is_simulated",False))))
    db.commit()
    return cur.lastrowid

def get_setting(db, key, default=None):
    row = db.execute("SELECT setting_value, setting_type FROM system_settings WHERE setting_key=?", (key,)).fetchone()
    if not row: return default
    val, typ = row["setting_value"], row["setting_type"]
    if typ == "bool":  return val.lower() in ("true","1","yes")
    if typ == "int":   return int(val)
    if typ == "float": return float(val)
    return val

def set_setting(db, key, value, updated_by="system"):
    db.execute("UPDATE system_settings SET setting_value=?, updated_at=CURRENT_TIMESTAMP, updated_by=? WHERE setting_key=?",
               (str(value), updated_by, key))
    db.commit()

def get_all_settings(db):
    rows = db.execute("SELECT * FROM system_settings ORDER BY category, setting_key").fetchall()
    return {r["setting_key"]: dict(r) for r in rows}

def audit_log(db, user_id, username, action, resource="", details="", ip=""):
    db.execute("INSERT INTO audit_logs (user_id,username,action,resource,details,ip_address) VALUES (?,?,?,?,?,?)",
               (user_id, username, action, resource, details, ip))
    db.commit()
