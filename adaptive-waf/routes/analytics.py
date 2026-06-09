"""
routes/analytics.py — Analytics and heatmap data.
"""

from functools import wraps
from flask import Blueprint, render_template, jsonify, session, redirect, url_for
from database.db import (get_db, get_log_stats, get_attack_distribution,
                          get_timeline_data, get_top_ips, get_recent_attacks)

analytics_bp = Blueprint("analytics", __name__)

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d

@analytics_bp.route("/analytics")
@login_required
def index():
    db       = get_db()
    stats    = get_log_stats(db)
    dist     = get_attack_distribution(db)
    top_ips  = get_top_ips(db, limit=15)
    timeline = get_timeline_data(db, hours=48)
    attacks  = get_recent_attacks(db, limit=50)
    return render_template("analytics.html",
        stats=stats, dist=dist, top_ips=top_ips,
        timeline=timeline, attacks=attacks, page="analytics")

@analytics_bp.route("/api/analytics/hourly")
@login_required
def api_hourly():
    db   = get_db()
    data = get_timeline_data(db, hours=72)
    return jsonify(data)

@analytics_bp.route("/api/analytics/attack-types")
@login_required
def api_attack_types():
    db   = get_db()
    dist = get_attack_distribution(db)
    return jsonify(dist)

@analytics_bp.route("/api/analytics/top-ips")
@login_required
def api_top_ips():
    db  = get_db()
    ips = get_top_ips(db, limit=20)
    return jsonify(ips)
