"""
routes/firewall.py — Firewall rules management.
"""

import json
from functools import wraps
from datetime import datetime

from flask import (Blueprint, render_template, jsonify, request,
                   session, redirect, url_for, flash)

from database.db import (get_db, get_all_rules, get_blocked_ips,
                          unblock_ip, audit_log, add_dynamic_rule)
from waf_engine.rule_engine import get_rule_store, get_sensitivity_manager

firewall_bp = Blueprint("firewall", __name__)


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d


@firewall_bp.route("/firewall")
@login_required
def index():
    db       = get_db()
    rules    = get_all_rules(db)
    blocked  = get_blocked_ips(db)
    sm       = get_sensitivity_manager()
    return render_template("firewall.html",
        rules=rules, blocked_ips=blocked,
        sensitivity=round(sm.level * 100),
        page="firewall")


@firewall_bp.route("/api/firewall/rules")
@login_required
def api_rules():
    db    = get_db()
    rules = get_all_rules(db)
    return jsonify(rules)


@firewall_bp.route("/api/firewall/toggle-rule", methods=["POST"])
@login_required
def toggle_rule():
    data    = request.get_json() or {}
    rule_id = int(data.get("rule_id", 0))
    active  = bool(data.get("active", True))
    db      = get_db()
    db.execute("UPDATE firewall_rules SET is_active=? WHERE id=?", (int(active), rule_id))
    db.commit()
    # Reload rule store
    from database.db import get_active_rules
    get_rule_store().load_rules(get_active_rules(db))
    audit_log(db, session["user_id"], session["username"],
              "RULE_TOGGLE", f"rule:{rule_id}", f"active={active}")
    return jsonify({"success": True})


@firewall_bp.route("/api/firewall/add-rule", methods=["POST"])
@login_required
def add_rule():
    data    = request.get_json() or {}
    db      = get_db()
    rule_id = add_dynamic_rule(
        db,
        rule_name    = data.get("rule_name", "Custom Rule"),
        rule_type    = data.get("rule_type", "custom"),
        pattern      = data.get("pattern", ""),
        action       = data.get("action", "block"),
        severity     = data.get("severity", "medium"),
        confidence   = float(data.get("confidence", 0.9)),
        expires_hours= int(data.get("expires_hours", 24)),
        description  = data.get("description", "Manually added rule"),
    )
    from database.db import get_active_rules
    get_rule_store().load_rules(get_active_rules(db))
    audit_log(db, session["user_id"], session["username"],
              "RULE_ADD", f"rule:{rule_id}", data.get("rule_name",""))
    return jsonify({"success": True, "rule_id": rule_id})


@firewall_bp.route("/api/firewall/delete-rule", methods=["POST"])
@login_required
def delete_rule():
    data    = request.get_json() or {}
    rule_id = int(data.get("rule_id", 0))
    db      = get_db()
    db.execute("DELETE FROM firewall_rules WHERE id=? AND is_dynamic=1", (rule_id,))
    db.commit()
    get_rule_store().remove_rule(rule_id)
    audit_log(db, session["user_id"], session["username"],
              "RULE_DELETE", f"rule:{rule_id}")
    return jsonify({"success": True})


@firewall_bp.route("/api/firewall/unblock-ip", methods=["POST"])
@login_required
def api_unblock_ip():
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    db   = get_db()
    unblock_ip(db, ip)
    audit_log(db, session["user_id"], session["username"],
              "IP_UNBLOCK", ip)
    return jsonify({"success": True})


@firewall_bp.route("/api/firewall/sensitivity", methods=["POST"])
@login_required
def set_sensitivity():
    data  = request.get_json() or {}
    level = float(data.get("level", 0.5))
    sm    = get_sensitivity_manager()
    new   = sm.set_level(level)
    db    = get_db()
    from database.db import set_setting
    set_setting(db, "sensitivity_level", str(new), updated_by=session["username"])
    audit_log(db, session["user_id"], session["username"],
              "SENSITIVITY_CHANGE", details=f"level={new:.3f}")
    return jsonify({"success": True, "level": new})
