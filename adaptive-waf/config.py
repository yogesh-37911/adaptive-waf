"""
config.py — Adaptive WAF Configuration
Central configuration hub for all modules.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # ─── Core Flask ──────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "adaptive-waf-cyber-secret-2024-!@#")
    DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
    TESTING = False

    # ─── Database ────────────────────────────────────────────────────────────
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "waf.db")
    SCHEMA_PATH   = os.path.join(BASE_DIR, "schema.sql")

    # ─── Session ─────────────────────────────────────────────────────────────
    SESSION_COOKIE_SECURE   = False   # True in production (HTTPS)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ─── WAF Engine ──────────────────────────────────────────────────────────
    WAF_ENABLED             = True
    THREAT_THRESHOLD        = 0.50   # flag as suspicious
    BLOCK_THRESHOLD         = 0.75   # block outright
    MAX_REQUESTS_PER_MINUTE = 100
    AUTO_BLACKLIST_ENABLED  = True
    BLACKLIST_THRESHOLD     = 5      # attacks before blacklist
    BLACKLIST_DURATION_MIN  = 60

    # ─── RL Engine ───────────────────────────────────────────────────────────
    RL_ENABLED          = True
    RL_LEARNING_RATE    = 0.001
    RL_EPSILON          = 0.10
    RL_EPSILON_MIN      = 0.01
    RL_EPSILON_DECAY    = 0.995
    RL_GAMMA            = 0.95
    RL_BATCH_SIZE       = 32
    RL_MEMORY_SIZE      = 10_000
    RL_UPDATE_FREQUENCY = 10         # steps between target-network sync
    RL_STATE_SIZE       = 12
    RL_ACTION_SIZE      = 7

    # ─── Model Persistence ───────────────────────────────────────────────────
    MODEL_SAVE_PATH  = os.path.join(BASE_DIR, "models", "saved", "dqn_waf.pt")
    MODEL_CHECKPOINT = os.path.join(BASE_DIR, "models", "saved", "checkpoint.pt")

    # ─── Safety Constraints ──────────────────────────────────────────────────
    MAX_SENSITIVITY    = 0.95
    MIN_SENSITIVITY    = 0.10
    COOLDOWN_TIMER     = 30          # seconds between major changes
    ROLLBACK_ENABLED   = True

    # ─── Logging ─────────────────────────────────────────────────────────────
    LOG_LEVEL = "DEBUG"
    LOG_FILE  = os.path.join(BASE_DIR, "logs", "waf.log")

    # ─── Reports ─────────────────────────────────────────────────────────────
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    # ─── Rate Limiting ───────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URL = "memory://"

    # ─── CSRF ────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED      = True
    WTF_CSRF_TIME_LIMIT   = 3600


class ProductionConfig(Config):
    DEBUG                  = False
    SESSION_COOKIE_SECURE  = True
    WTF_CSRF_SSL_STRICT    = True


class DevelopmentConfig(Config):
    DEBUG         = True
    WTF_CSRF_ENABLED = False   # easier dev iteration


# Active config
config = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}

# ─── Action Space ─────────────────────────────────────────────────────────────
ACTION_NAMES = {
    0: "ALLOW",
    1: "BLOCK",
    2: "INCREASE_THREAT_SCORE",
    3: "TIGHTEN_SENSITIVITY",
    4: "LOOSEN_SENSITIVITY",
    5: "BLACKLIST_IP",
    6: "CREATE_DYNAMIC_RULE",
}

# ─── Attack Types ─────────────────────────────────────────────────────────────
ATTACK_TYPES = [
    "sqli",
    "xss",
    "cmd_inject",
    "path_traversal",
    "brute_force",
    "ddos",
    "bot",
    "lfi",
    "xxe",
    "none",
]

# ─── Severity Scores ──────────────────────────────────────────────────────────
SEVERITY_SCORES = {
    "low":      0.25,
    "medium":   0.50,
    "high":     0.75,
    "critical": 1.00,
}

# ─── Reward Constants ─────────────────────────────────────────────────────────
REWARD_TRUE_POSITIVE   =  1.5   # correctly blocked an attack
REWARD_TRUE_NEGATIVE   =  0.5   # correctly allowed legit request
REWARD_FALSE_POSITIVE  = -1.0   # blocked a legit request
REWARD_FALSE_NEGATIVE  = -2.0   # allowed an attack through
REWARD_TIGHTEN_GOOD    =  0.3   # tightened during high-attack period
REWARD_LOOSEN_GOOD     =  0.3   # loosened during low-threat period
REWARD_INVALID_ACTION  = -0.1   # nonsensical action in context
