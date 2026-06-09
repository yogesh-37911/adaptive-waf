"""
routes/simulator.py — Attack simulation engine.
Lets the user fire simulated attacks to demonstrate RL adaptation.
"""

import json
import random
import time
import logging
from functools import wraps

from flask import (Blueprint, render_template, jsonify, request,
                   session, redirect, url_for, current_app)

from database.db import (get_db, log_request, log_attack_event,
                          log_rl_metric, get_setting, block_ip)
from waf_engine.threat_scorer import compute_threat_score
from waf_engine.rule_engine   import evaluate_request, get_sensitivity_manager
from waf_engine.payloads      import (PAYLOADS_BY_TYPE, ATTACK_SEVERITY,
                                       LEGITIMATE_REQUESTS)
from rl_engine.trainer        import get_agent
from config                   import ACTION_NAMES

logger       = logging.getLogger(__name__)
simulator_bp = Blueprint("simulator", __name__)

ATTACK_TYPES = ["sqli", "xss", "cmd_inject", "path_traversal",
                "brute_force", "ddos", "bot", "lfi"]

SIMULATED_IPS = [
    "45.33.32.156", "192.241.154.222", "103.41.167.210",
    "185.220.101.45", "91.108.4.18",   "46.161.27.241",
    "1.180.0.10",   "2.56.56.58",      "5.188.206.14",
    "94.102.49.190",
]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@simulator_bp.route("/simulator")
@login_required
def index():
    return render_template(
        "simulator.html",
        attack_types = ATTACK_TYPES,
        page         = "simulator",
    )


@simulator_bp.route("/api/simulate", methods=["POST"])
@login_required
def simulate_attack():
    """
    Execute a single simulated attack or legitimate request.
    Returns WAF verdict + RL explanation.
    """
    data        = request.get_json() or {}
    attack_type = data.get("attack_type", "sqli")
    count       = min(int(data.get("count", 1)), 50)
    use_legit   = data.get("legit", False)

    results = []
    db      = get_db()
    agent   = get_agent()

    for _ in range(count):
        if use_legit:
            req      = random.choice(LEGITIMATE_REQUESTS)
            payload  = req["payload"]
            path     = req["path"]
            method   = req["method"]
            ua       = req["user_agent"]
            src_ip   = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"
            true_type = "none"
        else:
            payloads = PAYLOADS_BY_TYPE.get(attack_type, ["test"])
            payload  = random.choice(payloads)
            path     = random.choice(["/search", "/login", "/api/query", "/upload", "/admin"])
            method   = "POST" if attack_type in ("sqli","xss","brute_force") else "GET"
            ua       = "Mozilla/5.0 (Windows NT 10.0)" if attack_type != "bot" else \
                       random.choice(["sqlmap/1.7.8", "Nikto/2.1.6", "curl/7.68.0"])
            src_ip   = random.choice(SIMULATED_IPS)
            true_type = attack_type

        # Build request context
        req_data = {
            "ip_address":   src_ip,
            "payload":      payload,
            "path":         path,
            "user_agent":   ua,
            "method":       method,
            "query_string": payload if method == "GET" else "",
            "headers":      {"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded"},
        }

        # Threat analysis
        analysis = compute_threat_score(req_data)

        # WAF decision
        sensitivity  = get_sensitivity_manager().level
        block_thresh = float(get_setting(db, "block_threshold", 0.75))
        full_text    = f"{payload} {path}"
        waf_dec      = evaluate_request(full_text, analysis, sensitivity, block_thresh)

        # RL action
        rl_action      = 0
        rl_action_name = "ALLOW"
        rl_confidence  = 0.5
        rl_q_values    = []

        if agent:
            state = _build_state(analysis, sensitivity, db)
            rl_action = agent.select_action(state)
            q_vals    = agent.get_q_values(state)
            if q_vals is not None:
                rl_q_values   = [round(float(v), 3) for v in q_vals]
                rl_confidence = round(float(max(q_vals)), 3)
            rl_action_name = ACTION_NAMES.get(rl_action, "UNKNOWN")

            # Override if RL says block for attack
            if rl_action == 1 and not use_legit:
                waf_dec.action = "block"
            elif rl_action == 0 and use_legit:
                waf_dec.action = "allow"

        final_action = waf_dec.action
        is_blocked   = final_action == "block"

        # Compute reward
        reward = _compute_reward(rl_action, is_attack=not use_legit,
                                 score=waf_dec.threat_score)

        # Persist
        log_id = log_request(db, {
            "ip_address":    src_ip,
            "method":        method,
            "path":          path,
            "user_agent":    ua,
            "payload":       str(payload)[:500],
            "query_string":  payload if method == "GET" else "",
            "headers":       req_data["headers"],
            "threat_score":  waf_dec.threat_score,
            "attack_type":   waf_dec.attack_type if not use_legit else "none",
            "action_taken":  final_action,
            "response_status": 403 if is_blocked else 200,
            "rl_decision":   rl_action_name,
            "rl_confidence": rl_confidence,
            "rl_action_id":  rl_action,
            "triggered_rules": waf_dec.matched_rules,
            "processing_time": 0.01,
            "is_simulated":  True,
            "reward_given":  reward,
        })

        if not use_legit:
            log_attack_event(db, {
                "ip_address":   src_ip,
                "attack_type":  true_type,
                "severity":     ATTACK_SEVERITY.get(true_type, "medium"),
                "payload":      str(payload)[:300],
                "blocked":      is_blocked,
                "rule_triggered": json.dumps(waf_dec.matched_rules[:3]),
                "threat_score": waf_dec.threat_score,
                "rl_action":    rl_action_name,
                "is_simulated": True,
            })

        # RL metric
        if agent:
            agent.remember(
                _build_state(analysis, sensitivity, db),
                rl_action, reward,
                _build_state(analysis, sensitivity, db),
                False
            )

        result = {
            "id":            log_id,
            "ip":            src_ip,
            "attack_type":   true_type if not use_legit else "none",
            "payload":       str(payload)[:120],
            "threat_score":  waf_dec.threat_score,
            "action":        final_action,
            "rl_action":     rl_action_name,
            "rl_action_id":  rl_action,
            "rl_confidence": rl_confidence,
            "rl_q_values":   rl_q_values,
            "matched_rules": waf_dec.matched_rules[:5],
            "reason":        waf_dec.reason,
            "signals":       analysis.get("signals", {}),
            "reward":        round(reward, 3),
            "severity":      analysis.get("severity", "low"),
            "blocked":       is_blocked,
        }
        results.append(result)

    return jsonify({"success": True, "results": results, "count": len(results)})


@simulator_bp.route("/api/simulate/burst", methods=["POST"])
@login_required
def simulate_burst():
    """Simulate a burst (DDoS-like) attack from multiple IPs."""
    data     = request.get_json() or {}
    attack_t = data.get("attack_type", "ddos")
    burst_n  = min(int(data.get("burst", 20)), 100)

    results = []
    db = get_db()

    for i in range(burst_n):
        src_ip   = SIMULATED_IPS[i % len(SIMULATED_IPS)]
        payload  = f"FLOOD_REQUEST_{i}"
        analysis = compute_threat_score({
            "ip_address": src_ip, "payload": payload,
            "path": "/", "user_agent": "flood-bot/1.0",
            "method": "GET", "query_string": "",
            "headers": {},
        })
        sensitivity = get_sensitivity_manager().level
        waf_dec = evaluate_request(payload, analysis, sensitivity, 0.6)

        log_request(db, {
            "ip_address": src_ip, "method": "GET", "path": "/",
            "user_agent": "flood-bot/1.0", "payload": payload,
            "query_string": "", "headers": {},
            "threat_score": waf_dec.threat_score,
            "attack_type": "ddos", "action_taken": waf_dec.action,
            "response_status": 403 if waf_dec.action == "block" else 200,
            "is_simulated": True,
        })
        results.append({"ip": src_ip, "action": waf_dec.action,
                         "score": waf_dec.threat_score})

    return jsonify({"success": True, "burst": burst_n, "results": results})


@simulator_bp.route("/api/demo-sequence", methods=["POST"])
@login_required
def demo_sequence():
    """
    Run a guided demo sequence:
    1. Baseline legit traffic
    2. SQLi wave
    3. XSS wave
    4. RL adaptation visible
    """
    db     = get_db()
    agent  = get_agent()
    steps  = []

    sequences = [
        ("none",   10, True,  "Baseline: legitimate traffic"),
        ("sqli",   5,  False, "Wave 1: SQL Injection attack"),
        ("xss",    5,  False, "Wave 2: XSS attack"),
        ("ddos",   8,  False, "Wave 3: DDoS flood"),
        ("none",   5,  True,  "Recovery: legitimate traffic"),
        ("cmd_inject", 4, False, "Wave 4: Command Injection"),
    ]

    for attack_type, count, legit, label in sequences:
        payloads_pool = LEGITIMATE_REQUESTS if legit else \
                        PAYLOADS_BY_TYPE.get(attack_type, ["test"])
        group_results = []

        for _ in range(count):
            if legit:
                req     = random.choice(LEGITIMATE_REQUESTS)
                payload = req["payload"]
                src_ip  = f"10.0.{random.randint(0,3)}.{random.randint(1,254)}"
            else:
                payload = random.choice(payloads_pool)
                src_ip  = random.choice(SIMULATED_IPS)

            analysis = compute_threat_score({
                "ip_address": src_ip, "payload": str(payload),
                "path": "/test", "user_agent": "Mozilla/5.0",
                "method": "POST", "query_string": "",
                "headers": {},
            })
            sensitivity = get_sensitivity_manager().level
            waf_dec = evaluate_request(str(payload), analysis, sensitivity, 0.75)
            group_results.append({
                "action": waf_dec.action,
                "score":  waf_dec.threat_score,
            })

        blocked_count = sum(1 for r in group_results if r["action"] == "block")
        steps.append({
            "label":    label,
            "count":    count,
            "blocked":  blocked_count,
            "allowed":  count - blocked_count,
            "avg_score":round(sum(r["score"] for r in group_results) / count, 3),
            "sensitivity": round(get_sensitivity_manager().level, 3),
        })

    return jsonify({"success": True, "steps": steps})


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_state(analysis, sensitivity, db):
    from database.db import get_rl_summary
    try:
        rl_sum   = get_rl_summary(db)
        fp_ratio = (rl_sum.get("total_fp") or 0) / max(rl_sum.get("steps") or 1, 1)
    except Exception:
        fp_ratio = 0.0

    sigs = analysis.get("signals", {})
    return [
        sigs.get("request_rate", 0.0),
        analysis.get("threat_score", 0.0),
        sigs.get("pattern_match", 0.0),
        sigs.get("ip_reputation", 0.0),
        float(analysis.get("attack_type") == "sqli"),
        float(analysis.get("attack_type") == "xss"),
        float(analysis.get("attack_type") == "cmd_inject"),
        float(analysis.get("attack_type") == "ddos"),
        float(analysis.get("is_bot", False)),
        sensitivity,
        min(fp_ratio, 1.0),
        sigs.get("entropy", 0.0),
    ]


def _compute_reward(action, is_attack, score):
    if action == 1:   # BLOCK
        return 1.5 if is_attack else -1.0
    elif action == 0: # ALLOW
        return 0.5 if not is_attack else -2.0
    elif action in (3, 4):
        return 0.3
    elif action in (2, 6):
        return 0.5 if is_attack else -0.3
    elif action == 5:
        return 1.5 if is_attack and score > 0.7 else -0.5
    return -0.1
