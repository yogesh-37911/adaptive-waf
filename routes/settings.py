"""
routes/settings.py — System settings management.
"""

from functools import wraps
from flask import (Blueprint, render_template, jsonify, request,
                   session, redirect, url_for, flash)
from database.db import get_db, get_all_settings, set_setting, audit_log
from waf_engine.rule_engine import get_sensitivity_manager

settings_bp = Blueprint("settings", __name__)


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d


@settings_bp.route("/settings")
@login_required
def index():
    db       = get_db()
    settings = get_all_settings(db)
    return render_template("settings.html", settings=settings, page="settings")


@settings_bp.route("/api/settings/update", methods=["POST"])
@login_required
def update_setting():
    data  = request.get_json() or {}
    key   = data.get("key", "").strip()
    value = str(data.get("value", "")).strip()

    if not key:
        return jsonify({"success": False, "error": "Key is required"}), 400

    # Security: whitelist of updatable settings
    ALLOWED = {
        "waf_enabled", "threat_threshold", "block_threshold",
        "max_requests_per_min", "auto_blacklist_enabled",
        "blacklist_threshold", "blacklist_duration_min",
        "rl_enabled", "rl_epsilon", "rl_learning_rate", "rl_gamma",
        "rl_update_frequency", "sensitivity_level", "demo_mode",
        "rollback_enabled", "max_sensitivity", "min_sensitivity",
        "cooldown_timer", "captcha_threshold", "anomaly_detection",
        "log_retention_days",
    }
    if key not in ALLOWED:
        return jsonify({"success": False, "error": "Setting not editable"}), 403

    db = get_db()
    set_setting(db, key, value, updated_by=session["username"])

    # Apply immediately for sensitivity
    if key == "sensitivity_level":
        try:
            get_sensitivity_manager().set_level(float(value))
        except Exception:
            pass

    audit_log(db, session["user_id"], session["username"],
              "SETTING_UPDATE", key, f"value={value}")
    return jsonify({"success": True, "key": key, "value": value})


@settings_bp.route("/api/settings/all")
@login_required
def api_all_settings():
    db = get_db()
    return jsonify(get_all_settings(db))


@settings_bp.route("/api/settings/reset-rl", methods=["POST"])
@login_required
def reset_rl():
    """Clear RL metrics and reset epsilon."""
    db = get_db()
    db.execute("DELETE FROM rl_metrics")
    db.commit()
    from rl_engine.trainer import get_agent
    agent = get_agent()
    if agent:
        agent.epsilon = 1.0
        agent.reward_history.clear()
        agent.loss_history.clear()
    audit_log(db, session["user_id"], session["username"], "RL_RESET")
    return jsonify({"success": True})


@settings_bp.route("/api/settings/rollback", methods=["POST"])
@login_required
def rollback_sensitivity():
    sm      = get_sensitivity_manager()
    ok, lvl = sm.rollback()
    db      = get_db()
    if ok:
        set_setting(db, "sensitivity_level", str(lvl))
        audit_log(db, session["user_id"], session["username"],
                  "ROLLBACK", details=f"sensitivity rolled back to {lvl:.3f}")
    return jsonify({"success": ok, "level": round(lvl, 3)})
