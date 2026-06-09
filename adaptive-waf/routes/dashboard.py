"""
routes/dashboard.py — Main dashboard and real-time AJAX endpoints.
"""

import json
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (Blueprint, render_template, jsonify, session,
                   redirect, url_for, request, current_app)

from database.db import (get_db, get_log_stats, get_recent_logs,
                          get_attack_distribution, get_recent_attacks,
                          get_top_ips, get_timeline_data, get_rl_metrics,
                          get_rl_summary, get_blocked_ips, get_all_rules,
                          get_setting)
from waf_engine.rule_engine import get_sensitivity_manager
from rl_engine.trainer      import get_agent

logger       = logging.getLogger(__name__)
dashboard_bp = Blueprint("dashboard", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Main Dashboard
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/")
@login_required
def index():
    db       = get_db()
    stats    = get_log_stats(db)
    recent   = get_recent_logs(db, limit=10)
    attacks  = get_recent_attacks(db, limit=5)
    top_ips  = get_top_ips(db, limit=5)
    rl_sum   = get_rl_summary(db)
    blocked  = get_blocked_ips(db)
    agent    = get_agent()
    agent_stats = agent.get_stats() if agent else {}

    sensitivity = get_sensitivity_manager().level
    demo_mode   = get_setting(db, "demo_mode", False)

    return render_template(
        "dashboard.html",
        stats       = stats,
        recent_logs = recent,
        recent_atks = attacks,
        top_ips     = top_ips,
        rl_summary  = rl_sum,
        blocked_ips = blocked,
        agent_stats = agent_stats,
        sensitivity = round(sensitivity * 100),
        demo_mode   = demo_mode,
        page        = "dashboard",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Real-Time AJAX Polling Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/api/stats")
@login_required
def api_stats():
    db      = get_db()
    stats   = get_log_stats(db)
    rl_sum  = get_rl_summary(db)
    agent   = get_agent()
    a_stats = agent.get_stats() if agent else {}

    sensitivity = get_sensitivity_manager().level

    return jsonify({
        "total":          stats.get("total", 0),
        "blocked":        stats.get("blocked", 0),
        "allowed":        stats.get("allowed", 0),
        "attacks":        stats.get("attacks", 0),
        "false_positives":stats.get("false_positives", 0),
        "sensitivity":    round(sensitivity, 3),
        "rl_steps":       a_stats.get("steps", 0),
        "rl_epsilon":     a_stats.get("epsilon", 1.0),
        "rl_avg_reward":  a_stats.get("avg_reward_100", 0.0),
        "rl_cum_reward":  a_stats.get("cumulative_reward", 0.0),
        "rl_loss":        a_stats.get("avg_loss", 0.0),
        "blocked_ips":    len(get_blocked_ips(db)),
        "active_rules":   sum(1 for r in get_all_rules(db) if r.get("is_active")),
    })


@dashboard_bp.route("/api/live-feed")
@login_required
def api_live_feed():
    """Return last 20 request log entries for the live terminal feed."""
    db   = get_db()
    logs = get_recent_logs(db, limit=20)
    feed = []
    for lg in logs:
        feed.append({
            "id":          lg.get("id"),
            "timestamp":   str(lg.get("timestamp", ""))[:19],
            "ip":          lg.get("ip_address", ""),
            "method":      lg.get("method", ""),
            "path":        (lg.get("path") or "/")[:50],
            "attack_type": lg.get("attack_type", "none"),
            "action":      lg.get("action_taken", "allow"),
            "score":       round(lg.get("threat_score", 0.0), 3),
            "rl_decision": lg.get("rl_decision", ""),
            "is_sim":      bool(lg.get("is_simulated")),
        })
    return jsonify(feed)


@dashboard_bp.route("/api/rl-rewards")
@login_required
def api_rl_rewards():
    """Last 100 RL reward data points for the reward graph."""
    db      = get_db()
    metrics = get_rl_metrics(db, limit=100)
    labels  = [m.get("timestamp", "")[:19] for m in metrics]
    rewards = [round(m.get("reward", 0.0), 4) for m in metrics]
    cum_rwd = [round(m.get("cumulative_reward", 0.0), 2) for m in metrics]
    losses  = [round(m.get("loss", 0.0), 6) for m in metrics]
    epsilons= [round(m.get("epsilon", 1.0), 4) for m in metrics]
    return jsonify({
        "labels":    labels,
        "rewards":   rewards,
        "cumulative":cum_rwd,
        "losses":    losses,
        "epsilons":  epsilons,
    })


@dashboard_bp.route("/api/attack-dist")
@login_required
def api_attack_dist():
    db   = get_db()
    dist = get_attack_distribution(db)
    return jsonify({
        "labels": [d["attack_type"] for d in dist],
        "counts": [d["cnt"]         for d in dist],
    })


@dashboard_bp.route("/api/timeline")
@login_required
def api_timeline():
    db   = get_db()
    data = get_timeline_data(db, hours=24)
    return jsonify({
        "labels":  [d.get("hour", "") for d in data],
        "total":   [d.get("total", 0) for d in data],
        "blocked": [d.get("blocked", 0) for d in data],
    })


@dashboard_bp.route("/api/sensitivity")
@login_required
def api_sensitivity():
    sm = get_sensitivity_manager()
    return jsonify({
        "level":     round(sm.level, 3),
        "cooldown":  round(sm.cooldown_remaining(), 1),
    })


@dashboard_bp.route("/api/recent-attacks")
@login_required
def api_recent_attacks():
    db      = get_db()
    attacks = get_recent_attacks(db, limit=15)
    result  = []
    for a in attacks:
        result.append({
            "id":          a.get("id"),
            "timestamp":   str(a.get("timestamp", ""))[:19],
            "ip":          a.get("ip_address", ""),
            "type":        a.get("attack_type", ""),
            "severity":    a.get("severity", ""),
            "score":       round(a.get("threat_score", 0.0), 3),
            "blocked":     bool(a.get("blocked")),
            "rl_action":   a.get("rl_action", ""),
            "is_sim":      bool(a.get("is_simulated")),
        })
    return jsonify(result)


@dashboard_bp.route("/api/blocked-ips")
@login_required
def api_blocked_ips():
    db   = get_db()
    ips  = get_blocked_ips(db)
    return jsonify([{
        "ip":        r.get("ip_address"),
        "reason":    r.get("reason", ""),
        "score":     round(r.get("threat_score", 0.0), 3),
        "blocked_at":str(r.get("blocked_at", ""))[:19],
        "expires_at":str(r.get("expires_at", ""))[:16] if r.get("expires_at") else "permanent",
        "permanent": bool(r.get("is_permanent")),
    } for r in ips])
