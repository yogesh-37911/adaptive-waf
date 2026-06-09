"""
routes/auth.py — Login, logout, session management.
"""

from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, session, current_app)
from werkzeug.security import check_password_hash
from datetime import datetime
import logging

from database.db import get_db, audit_log

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip       = request.remote_addr or "unknown"

        if not username or not password:
            error = "Both fields are required."
        else:
            db   = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.permanent = True
                session["user_id"]   = user["id"]
                session["username"]  = user["username"]
                session["role"]      = user["role"]

                # Update last login
                db.execute(
                    "UPDATE users SET last_login=?, login_count=login_count+1 WHERE id=?",
                    (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
                )
                db.commit()

                audit_log(db, user["id"], username, "LOGIN", ip=ip)
                logger.info(f"Login success: {username} from {ip}")
                return redirect(url_for("dashboard.index"))
            else:
                error = "Invalid credentials."
                logger.warning(f"Failed login attempt: {username} from {ip}")
                audit_log(db, 0, username, "LOGIN_FAILED", ip=ip,
                          details="Invalid credentials")

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "unknown")
    ip       = request.remote_addr or "unknown"
    try:
        db = get_db()
        audit_log(db, session.get("user_id", 0), username, "LOGOUT", ip=ip)
    except Exception:
        pass
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
