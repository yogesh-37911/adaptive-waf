"""
routes/rl_insights.py — RL explainability and insights dashboard.
"""

from functools import wraps
from flask import (Blueprint, render_template, jsonify, session,
                   redirect, url_for, request)
from database.db import get_db, get_rl_metrics, get_rl_summary, get_log_stats
from rl_engine.trainer import get_agent
from config import ACTION_NAMES

rl_bp = Blueprint("rl_insights", __name__)


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d


@rl_bp.route("/rl-insights")
@login_required
def index():
    db      = get_db()
    metrics = get_rl_metrics(db, limit=200)
    summary = get_rl_summary(db)
    agent   = get_agent()
    a_stats = agent.get_stats() if agent else {}

    # Compute accuracy metrics
    tp = summary.get("total_tp") or 0
    fp = summary.get("total_fp") or 0
    tn = summary.get("total_tn") or 0
    fn = summary.get("total_fn") or 0
    total = tp + fp + tn + fn
    accuracy  = round((tp + tn) / max(total, 1) * 100, 2)
    precision = round(tp / max(tp + fp, 1) * 100, 2)
    recall    = round(tp / max(tp + fn, 1) * 100, 2)
    f1        = round(2 * precision * recall / max(precision + recall, 0.01), 2)

    return render_template("rl_insights.html",
        metrics    = metrics,
        summary    = summary,
        agent_stats= a_stats,
        accuracy   = accuracy,
        precision  = precision,
        recall     = recall,
        f1         = f1,
        tp=tp, fp=fp, tn=tn, fn=fn,
        action_names = ACTION_NAMES,
        page = "rl_insights",
    )


@rl_bp.route("/api/rl/explain/<int:log_id>")
@login_required
def explain_decision(log_id: int):
    """Return XAI explanation for a specific logged request."""
    db  = get_db()
    row = db.execute("SELECT * FROM request_logs WHERE id=?", (log_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404

    row = dict(row)
    agent = get_agent()
    q_values = None
    if agent:
        # Reconstruct state from stored signals (simplified)
        state = [0.0] * 12
        state[1] = row.get("threat_score", 0.0)
        q_vals = agent.get_q_values(state)
        if q_vals is not None:
            q_values = {ACTION_NAMES[i]: round(float(v), 4)
                        for i, v in enumerate(q_vals)}

    import json
    try:
        triggered = json.loads(row.get("triggered_rules") or "[]")
    except Exception:
        triggered = []

    explanation = {
        "request_id":    log_id,
        "ip_address":    row.get("ip_address"),
        "path":          row.get("path"),
        "action":        row.get("action_taken"),
        "threat_score":  row.get("threat_score"),
        "attack_type":   row.get("attack_type"),
        "rl_decision":   row.get("rl_decision"),
        "rl_confidence": row.get("rl_confidence"),
        "triggered_rules": triggered,
        "q_values":      q_values,
        "why_blocked": _explain_block(row, triggered),
    }
    return jsonify(explanation)


@rl_bp.route("/api/rl/performance")
@login_required
def api_performance():
    db  = get_db()
    metrics = get_rl_metrics(db, limit=300)
    agent = get_agent()
    a_stats = agent.get_stats() if agent else {}

    rewards  = [round(m.get("reward", 0.0), 4) for m in metrics]
    losses   = [round(m.get("loss", 0.0), 6)   for m in metrics]
    epsilons = [round(m.get("epsilon", 1.0), 4) for m in metrics]
    steps    = list(range(len(metrics)))

    return jsonify({
        "steps":    steps,
        "rewards":  rewards,
        "losses":   losses,
        "epsilons": epsilons,
        "agent":    a_stats,
    })


@rl_bp.route("/api/rl/action-dist")
@login_required
def api_action_dist():
    db = get_db()
    rows = db.execute(
        """SELECT action_taken, COUNT(*) as cnt
           FROM rl_metrics GROUP BY action_taken"""
    ).fetchall()
    dist = {ACTION_NAMES.get(int(r["action_taken"]), str(r["action_taken"])): r["cnt"]
            for r in rows}
    return jsonify(dist)


@rl_bp.route("/api/rl/comparison")
@login_required
def api_comparison():
    """Static vs RL adaptive firewall comparison."""
    db    = get_db()
    stats = get_log_stats(db)
    total = max(stats.get("total", 1), 1)

    # Simulated static WAF baseline (heuristic approximation)
    static_fp_rate  = 0.18   # 18% false positive rate typical for static rules
    static_fn_rate  = 0.25   # 25% false negative rate
    static_accuracy = 0.72

    # RL WAF metrics from DB
    sum_ = get_rl_summary(db)
    tp   = sum_.get("total_tp") or 0
    fp   = sum_.get("total_fp") or 0
    tn   = sum_.get("total_tn") or 0
    fn   = sum_.get("total_fn") or 0
    all_ = tp + fp + tn + fn
    rl_accuracy  = round((tp + tn) / max(all_, 1), 4)
    rl_fp_rate   = round(fp / max(fp + tn, 1), 4)
    rl_fn_rate   = round(fn / max(fn + tp, 1), 4)

    return jsonify({
        "static": {
            "accuracy":   static_accuracy,
            "fp_rate":    static_fp_rate,
            "fn_rate":    static_fn_rate,
            "label":      "Static WAF",
        },
        "rl": {
            "accuracy":   max(rl_accuracy, 0.0),
            "fp_rate":    max(rl_fp_rate, 0.0),
            "fn_rate":    max(rl_fn_rate, 0.0),
            "label":      "RL Adaptive WAF",
        },
    })


def _explain_block(row: dict, triggered: list) -> str:
    score  = row.get("threat_score", 0.0)
    atype  = row.get("attack_type", "none")
    action = row.get("action_taken", "allow")

    if action != "block":
        return "Request was allowed — threat score below blocking threshold."

    reasons = []
    if score >= 0.75:
        reasons.append(f"High composite threat score ({score:.3f})")
    if atype not in ("none", ""):
        reasons.append(f"Detected attack pattern: {atype.upper()}")
    if triggered:
        reasons.append(f"Triggered {len(triggered)} WAF rule(s): {', '.join(triggered[:3])}")
    if row.get("rl_decision") == "BLOCK":
        reasons.append(f"RL agent recommended BLOCK (confidence {row.get('rl_confidence',0):.3f})")

    return " | ".join(reasons) if reasons else "Blocked by WAF policy."
