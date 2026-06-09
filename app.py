"""
app.py — Adaptive WAF using Reinforcement Learning
Main Flask application entry point.

Architecture:
  Flask → WAF Middleware → SQLite → RL Agent (background thread)
"""

import os
import logging
from datetime import timedelta

from flask import Flask, session, redirect, url_for

from config       import DevelopmentConfig
from database.db  import init_db, init_app as db_init_app, get_db, get_active_rules, get_setting
from waf_engine.rule_engine import get_rule_store, get_sensitivity_manager
from rl_engine    import DQNAgent, start_training


def create_app(config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config or DevelopmentConfig)

    # ── Ensure directories exist ─────────────────────────────────────────────
    for d in ["logs", "reports", os.path.join("models", "saved")]:
        os.makedirs(os.path.join(os.path.dirname(__file__), d), exist_ok=True)

    # ── Logging ──────────────────────────────────────────────────────────────
    _setup_logging(app)

    # ── Database ─────────────────────────────────────────────────────────────
    db_init_app(app)
    init_db(app)

    # ── Load WAF Rules ───────────────────────────────────────────────────────
    with app.app_context():
        _load_waf_rules(app)
        _load_sensitivity(app)

    # ── RL Agent ─────────────────────────────────────────────────────────────
    agent = _init_rl_agent(app)

    # ── Register Blueprints ──────────────────────────────────────────────────
    _register_blueprints(app)

    # ── WAF Middleware ───────────────────────────────────────────────────────
    _register_waf_middleware(app, agent)

    # ── Context processors ───────────────────────────────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            "app_name":    "Adaptive WAF",
            "app_version": "2.0.0",
            "username":    session.get("username", ""),
        }

    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Not found"}, 404

    @app.errorhandler(403)
    def forbidden(e):
        return {"error": "Forbidden"}, 403

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(app):
    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"))
    log_file = app.config.get("LOG_FILE", "logs/waf.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handlers = [logging.StreamHandler()]
    try:
        handlers.append(logging.FileHandler(log_file))
    except Exception:
        pass

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )
    app.logger.setLevel(level)


def _load_waf_rules(app):
    try:
        db    = get_db()
        rules = get_active_rules(db)
        get_rule_store().load_rules(rules)
        app.logger.info(f"Loaded {len(rules)} WAF rules into rule store")
    except Exception as exc:
        app.logger.error(f"Failed to load WAF rules: {exc}")


def _load_sensitivity(app):
    try:
        db    = get_db()
        level = get_setting(db, "sensitivity_level", 0.5)
        get_sensitivity_manager().set_level(float(level))
        app.logger.info(f"WAF sensitivity initialised to {level}")
    except Exception as exc:
        app.logger.warning(f"Could not load sensitivity: {exc}")


def _init_rl_agent(app) -> DQNAgent:
    cfg   = app.config
    agent = DQNAgent(
        state_size         = cfg.get("RL_STATE_SIZE",       12),
        action_size        = cfg.get("RL_ACTION_SIZE",       7),
        lr                 = cfg.get("RL_LEARNING_RATE",  0.001),
        gamma              = cfg.get("RL_GAMMA",           0.95),
        epsilon            = cfg.get("RL_EPSILON",          0.1),
        epsilon_min        = cfg.get("RL_EPSILON_MIN",     0.01),
        epsilon_decay      = cfg.get("RL_EPSILON_DECAY", 0.995),
        batch_size         = cfg.get("RL_BATCH_SIZE",        32),
        memory_size        = cfg.get("RL_MEMORY_SIZE",   10_000),
        target_update_freq = cfg.get("RL_UPDATE_FREQUENCY",  10),
    )

    save_path = cfg.get("MODEL_SAVE_PATH", "models/saved/dqn_waf.pt")
    agent.load(save_path)   # loads checkpoint if available

    if cfg.get("RL_ENABLED", True):
        start_training(
            app       = app,
            agent     = agent,
            db_path   = cfg["DATABASE_PATH"],
            save_path = save_path,
            episodes  = 9999,
            steps_per_ep = 200,
            log_every    = 50,
        )
        app.logger.info("RL background training started")

    return agent


def _register_blueprints(app):
    from routes.auth       import auth_bp
    from routes.dashboard  import dashboard_bp
    from routes.simulator  import simulator_bp
    from routes.analytics  import analytics_bp
    from routes.firewall   import firewall_bp
    from routes.rl_insights import rl_bp
    from routes.reports    import reports_bp
    from routes.settings   import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(simulator_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(rl_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)


def _register_waf_middleware(app, agent):
    """
    Before-request hook: inspect every non-static request.
    Blocked requests receive 403 JSON response.
    """
    from waf_engine.inspector import inspect_request

    SKIP_PREFIXES = ("/static/", "/favicon")

    @app.before_request
    def waf_middleware():
        from flask import request, jsonify, g
        path = request.path

        # Skip static assets and skip if WAF is off
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            return None

        try:
            db       = get_db()
            waf_cfg  = {
                "block_threshold":     get_setting(db, "block_threshold",    0.75),
                "blacklist_duration_min": get_setting(db, "blacklist_duration_min", 60),
            }
            verdict = inspect_request(db, agent, waf_cfg)
            g.waf_verdict = verdict

            if verdict.get("action") == "block":
                # Allow auth routes through to avoid lockout
                if path.startswith("/login") or path.startswith("/logout"):
                    return None
                return jsonify({
                    "error":        "Request blocked by Adaptive WAF",
                    "attack_type":  verdict.get("attack_type"),
                    "threat_score": verdict.get("threat_score"),
                    "reason":       verdict.get("reason"),
                    "rl_action":    verdict.get("rl_action_name"),
                }), 403
        except Exception as exc:
            app.logger.error(f"WAF middleware error: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    app.run(
        host  = "0.0.0.0",
        port  = 5000,
        debug = True,
        use_reloader = False,   # reloader kills background RL thread
    )
