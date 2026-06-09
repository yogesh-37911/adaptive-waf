"""
routes/reports.py — Report generation and export.
"""

import os
from functools import wraps
from flask import (Blueprint, render_template, jsonify, send_file,
                   session, redirect, url_for, current_app, make_response)
from database.db import (get_db, get_log_stats, get_recent_logs,
                          get_recent_attacks, get_rl_summary, get_top_ips)
from utils.exports import export_logs_csv, export_attacks_csv, generate_pdf_report

reports_bp = Blueprint("reports", __name__)


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d


@reports_bp.route("/reports")
@login_required
def index():
    db      = get_db()
    stats   = get_log_stats(db)
    rl_sum  = get_rl_summary(db)
    top_ips = get_top_ips(db, limit=10)
    reports_dir = current_app.config["REPORTS_DIR"]
    existing = []
    if os.path.isdir(reports_dir):
        existing = sorted([
            f for f in os.listdir(reports_dir) if f.endswith(".pdf")
        ], reverse=True)[:10]
    return render_template("reports.html",
        stats=stats, rl_summary=rl_sum,
        top_ips=top_ips, existing_reports=existing,
        page="reports")


@reports_bp.route("/api/export/logs-csv")
@login_required
def export_logs():
    db   = get_db()
    logs = get_recent_logs(db, limit=1000)
    csv_bytes = export_logs_csv(logs)
    resp = make_response(csv_bytes)
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=request_logs.csv"
    return resp


@reports_bp.route("/api/export/attacks-csv")
@login_required
def export_attacks():
    db      = get_db()
    attacks = get_recent_attacks(db, limit=1000)
    csv_bytes = export_attacks_csv(attacks)
    resp = make_response(csv_bytes)
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=attack_events.csv"
    return resp


@reports_bp.route("/api/generate-report", methods=["POST"])
@login_required
def generate_report():
    db      = get_db()
    stats   = get_log_stats(db)
    attacks = get_recent_attacks(db, limit=50)
    rl_sum  = get_rl_summary(db)
    top_ips = get_top_ips(db, limit=10)
    filepath = generate_pdf_report(
        stats, attacks, rl_sum, top_ips,
        current_app.config["REPORTS_DIR"]
    )
    if filepath:
        filename = os.path.basename(filepath)
        return jsonify({"success": True, "filename": filename})
    return jsonify({"success": False, "error": "PDF generation failed"}), 500


@reports_bp.route("/api/download-report/<filename>")
@login_required
def download_report(filename: str):
    # Safety: only allow .pdf files from reports dir
    if not filename.endswith(".pdf") or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid file"}), 400
    reports_dir = current_app.config["REPORTS_DIR"]
    filepath    = os.path.join(reports_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Not found"}), 404
    return send_file(filepath, as_attachment=True)
