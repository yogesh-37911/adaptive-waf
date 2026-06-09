"""
waf_engine/inspector.py
Main WAF inspection middleware.
Intercepts Flask requests, runs threat analysis, gets RL decision,
logs everything to SQLite, and returns allow/block verdict.
"""

import re
import time
import logging
import json
from datetime import datetime
from typing import Optional

from flask import request as flask_request, g

from .threat_scorer import compute_threat_score, record_ip_attack
from .rule_engine   import evaluate_request, get_sensitivity_manager

logger = logging.getLogger(__name__)

# Paths that bypass WAF inspection
WAF_BYPASS_PATHS = {
    "/static/", "/favicon.ico", "/health",
}


def should_bypass(path: str) -> bool:
    return any(path.startswith(p) for p in WAF_BYPASS_PATHS)


def inspect_request(db, rl_agent=None, settings: dict = None) -> dict:
    """
    Perform full WAF inspection of the current Flask request.

    Returns a verdict dict:
    {
        "action":         "allow"|"block"|"challenge",
        "threat_score":   float,
        "attack_type":    str,
        "triggered_rules":list,
        "rl_action":      int,
        "rl_action_name": str,
        "rl_confidence":  float,
        "reason":         str,
        "processing_ms":  float,
        "log_id":         int,
    }
    """
    t_start = time.perf_counter()
    settings = settings or {}

    ip_address  = flask_request.headers.get("X-Forwarded-For",
                  flask_request.remote_addr or "127.0.0.1").split(",")[0].strip()
    method      = flask_request.method
    path        = flask_request.path
    user_agent  = flask_request.headers.get("User-Agent", "")
    query_str   = flask_request.query_string.decode("utf-8", errors="replace")
    payload     = ""

    # Extract payload safely
    if method in ("POST", "PUT", "PATCH"):
        try:
            if flask_request.is_json:
                payload = json.dumps(flask_request.get_json(silent=True) or {})
            else:
                payload = flask_request.get_data(as_text=True)[:4096]
        except Exception:
            payload = ""

    headers_dict = dict(flask_request.headers)

    # ── Bypass check ────────────────────────────────────────────────────────
    if should_bypass(path):
        return {"action": "allow", "threat_score": 0.0, "attack_type": "none",
                "triggered_rules": [], "rl_action": 0, "rl_action_name": "ALLOW",
                "rl_confidence": 1.0, "reason": "bypass path", "processing_ms": 0,
                "log_id": None}

    # ── Check blocked IP table ───────────────────────────────────────────────
    from database.db import is_ip_blocked
    if is_ip_blocked(db, ip_address):
        _record(db, ip_address, method, path, user_agent, payload,
                query_str, headers_dict, 1.0, "blocked_ip", "block",
                403, "BLOCKED", 1.0, 0, ["BLACKLISTED_IP"], 0.0, False)
        return {"action": "block", "threat_score": 1.0, "attack_type": "blocked_ip",
                "triggered_rules": ["IP_BLACKLIST"], "rl_action": 1,
                "rl_action_name": "BLOCK", "rl_confidence": 1.0,
                "reason": "IP is blacklisted", "processing_ms": 0, "log_id": None}

    # ── Threat analysis ──────────────────────────────────────────────────────
    request_data = {
        "ip_address":   ip_address,
        "method":       method,
        "path":         path,
        "user_agent":   user_agent,
        "payload":      payload,
        "query_string": query_str,
        "headers":      headers_dict,
    }
    analysis = compute_threat_score(request_data)

    # ── Rule evaluation ──────────────────────────────────────────────────────
    sensitivity   = get_sensitivity_manager().level
    block_thresh  = float(settings.get("block_threshold", 0.75))
    full_text     = " ".join([payload, path, query_str, str(headers_dict)])
    waf_decision  = evaluate_request(full_text, analysis, sensitivity, block_thresh)

    # ── RL agent decision ────────────────────────────────────────────────────
    rl_action      = 0    # default: ALLOW
    rl_action_name = "ALLOW"
    rl_confidence  = 0.5
    reward         = 0.0

    if rl_agent is not None:
        try:
            state        = _build_rl_state(analysis, sensitivity)
            rl_action    = rl_agent.select_action(state)
            rl_conf_arr  = rl_agent.get_q_values(state)
            rl_confidence = float(max(rl_conf_arr)) if rl_conf_arr is not None else 0.5
            rl_action_name = _action_id_to_name(rl_action)

            # Override WAF decision based on RL action
            waf_decision = _apply_rl_action(
                rl_action, waf_decision, analysis, db, ip_address,
                sensitivity, settings
            )
        except Exception as exc:
            logger.warning(f"RL agent error: {exc}")

    final_action = waf_decision.action
    if final_action == "block":
        record_ip_attack(ip_address)

    t_elapsed = (time.perf_counter() - t_start) * 1000

    # ── Persist log ──────────────────────────────────────────────────────────
    log_id = _record(
        db, ip_address, method, path, user_agent, payload,
        query_str, headers_dict,
        waf_decision.threat_score, waf_decision.attack_type,
        final_action, 200 if final_action == "allow" else 403,
        rl_action_name, rl_confidence, rl_action,
        waf_decision.matched_rules, t_elapsed / 1000,
        False, reward
    )

    # ── Log attack event if detected ────────────────────────────────────────
    if waf_decision.attack_type not in ("none", ""):
        from database.db import log_attack_event
        log_attack_event(db, {
            "ip_address":    ip_address,
            "attack_type":   waf_decision.attack_type,
            "severity":      analysis.get("severity", "medium"),
            "payload":       payload[:500],
            "blocked":       final_action == "block",
            "rule_triggered":json.dumps(waf_decision.matched_rules[:3]),
            "threat_score":  waf_decision.threat_score,
            "rl_action":     rl_action_name,
            "is_simulated":  False,
        })

    return {
        "action":         final_action,
        "threat_score":   waf_decision.threat_score,
        "attack_type":    waf_decision.attack_type,
        "severity":       analysis.get("severity", "low"),
        "triggered_rules":waf_decision.matched_rules,
        "rl_action":      rl_action,
        "rl_action_name": rl_action_name,
        "rl_confidence":  rl_confidence,
        "reason":         waf_decision.reason,
        "signals":        analysis.get("signals", {}),
        "processing_ms":  round(t_elapsed, 2),
        "log_id":         log_id,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RL state builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_rl_state(analysis: dict, sensitivity: float) -> list:
    """Convert threat analysis into RL state vector (length 12)."""
    from database.db import get_db, get_log_stats, get_rl_summary
    try:
        db = get_db()
        stats    = get_log_stats(db)
        rl_sum   = get_rl_summary(db)
        total    = max(stats.get("total", 1), 1)
        fp_ratio = (rl_sum.get("total_fp", 0) or 0) / max(rl_sum.get("steps", 1), 1)
    except Exception:
        total, fp_ratio = 1, 0.0

    sigs = analysis.get("signals", {})
    return [
        sigs.get("request_rate", 0.0),           # 0  request rate signal
        analysis.get("threat_score", 0.0),        # 1  composite threat score
        sigs.get("pattern_match", 0.0),           # 2  pattern match score
        sigs.get("ip_reputation", 0.0),           # 3  IP reputation
        float(analysis.get("attack_type") == "sqli"),     # 4 sqli prob
        float(analysis.get("attack_type") == "xss"),      # 5 xss prob
        float(analysis.get("attack_type") == "cmd_inject"),# 6
        float(analysis.get("attack_type") == "ddos"),     # 7
        float(analysis.get("is_bot", False)),     # 8  bot flag
        sensitivity,                              # 9  current sensitivity
        min(fp_ratio, 1.0),                       # 10 false positive ratio
        sigs.get("entropy", 0.0),                 # 11 payload entropy
    ]


# ─────────────────────────────────────────────────────────────────────────────
# RL action application
# ─────────────────────────────────────────────────────────────────────────────

def _apply_rl_action(rl_action: int, waf_decision, analysis: dict,
                     db, ip: str, sensitivity: float, settings: dict):
    """Mutate WAF decision based on RL action."""
    from .rule_engine import get_sensitivity_manager
    from database.db  import block_ip, add_dynamic_rule

    sm = get_sensitivity_manager()

    if rl_action == 0:   # ALLOW — trust WAF decision unless critical
        if waf_decision.threat_score < 0.3:
            waf_decision.action = "allow"

    elif rl_action == 1:  # BLOCK — force block
        if waf_decision.threat_score > 0.4:
            waf_decision.action = "block"

    elif rl_action == 2:  # INCREASE_THREAT_SCORE
        waf_decision.threat_score = min(waf_decision.threat_score * 1.3, 1.0)
        if waf_decision.threat_score >= float(settings.get("block_threshold", 0.75)):
            waf_decision.action = "block"

    elif rl_action == 3:  # TIGHTEN_SENSITIVITY
        sm.adjust(+0.05)

    elif rl_action == 4:  # LOOSEN_SENSITIVITY
        sm.adjust(-0.05)

    elif rl_action == 5:  # BLACKLIST_IP
        if waf_decision.threat_score > 0.7:
            block_ip(db, ip,
                     reason=f"RL agent blacklisted: {analysis.get('attack_type','unknown')}",
                     threat_score=waf_decision.threat_score,
                     duration_min=int(settings.get("blacklist_duration_min", 60)))
            waf_decision.action = "block"

    elif rl_action == 6:  # CREATE_DYNAMIC_RULE
        atype = analysis.get("attack_type", "none")
        if atype != "none" and waf_decision.matched_rules:
            pattern = waf_decision.matched_rules[0][:100]
            try:
                add_dynamic_rule(
                    db,
                    rule_name   = f"RL_DYN_{atype.upper()}_{int(time.time())}",
                    rule_type   = atype,
                    pattern     = re.escape(pattern) if len(pattern) < 50 else pattern,
                    action      = "block",
                    severity    = "high",
                    confidence  = waf_decision.confidence,
                    expires_hours = 6,
                    description = f"Auto-generated by RL agent at {datetime.utcnow().isoformat()}",
                )
            except Exception as exc:
                logger.debug(f"Dynamic rule creation failed: {exc}")

    return waf_decision


def _action_id_to_name(action_id: int) -> str:
    names = {0:"ALLOW", 1:"BLOCK", 2:"INCREASE_THREAT",
             3:"TIGHTEN", 4:"LOOSEN", 5:"BLACKLIST_IP", 6:"DYN_RULE"}
    return names.get(action_id, "UNKNOWN")


# ─────────────────────────────────────────────────────────────────────────────
# DB logger
# ─────────────────────────────────────────────────────────────────────────────

def _record(db, ip, method, path, ua, payload, query, headers,
            threat_score, attack_type, action, status,
            rl_decision, rl_confidence, rl_action_id,
            triggered_rules, proc_time, is_sim, reward) -> Optional[int]:
    try:
        from database.db import log_request
        return log_request(db, {
            "ip_address":    ip,
            "method":        method,
            "path":          path,
            "user_agent":    ua,
            "payload":       payload[:1000],
            "query_string":  query,
            "headers":       headers,
            "threat_score":  threat_score,
            "attack_type":   attack_type,
            "action_taken":  action,
            "response_status": status,
            "rl_decision":   rl_decision,
            "rl_confidence": rl_confidence,
            "rl_action_id":  rl_action_id,
            "triggered_rules": triggered_rules,
            "processing_time": proc_time,
            "is_simulated":  is_sim,
            "reward_given":  reward,
        })
    except Exception as exc:
        logger.error(f"Failed to log request: {exc}")
        return None
