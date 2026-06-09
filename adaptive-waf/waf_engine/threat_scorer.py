"""
waf_engine/threat_scorer.py
Composite threat scoring engine.
Combines pattern match scores, heuristics, IP reputation, and anomaly signals.
"""

import re
import math
import time
import logging
from collections import defaultdict, deque
from typing import Dict, List, Tuple

from .payloads import MALICIOUS_USER_AGENTS, ATTACK_SEVERITY

logger = logging.getLogger(__name__)

# Per-IP request rate tracking (in-memory sliding window)
_ip_request_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
_ip_threat_history: Dict[str, List[float]] = defaultdict(list)
_ip_attack_count: Dict[str, int] = defaultdict(int)


# ─────────────────────────────────────────────────────────────────────────────
# Keyword threat dictionaries
# ─────────────────────────────────────────────────────────────────────────────

SQLI_KEYWORDS = [
    r"(?i)(union[\s\+]+select)", r"(?i)(drop[\s]+table)",
    r"(?i)(sleep\(|benchmark\(|waitfor)", r"(?i)(insert[\s]+into)",
    r"(?i)(select.+from)", r"(?i)(or[\s]+1[\s]*=[\s]*1)",
    r"(?i)(and[\s]+1[\s]*=[\s]*1)", r"(?i)(exec\s*xp_)",
    r"(?i)(\/\*.*?\*\/)", r"--[\s]*$",
    r"(?i)(char\(\d+\))", r"(?i)(cast\(.+as.+\))",
    r"(?i)(information_schema)", r"(?i)(sys\.tables)",
]

XSS_KEYWORDS = [
    r"(?i)(<script[\s>])", r"(?i)(javascript[\s]*:)",
    r"(?i)(on(?:click|load|error|mouseover|focus|blur)[\s]*=)",
    r"(?i)(<iframe[\s>])", r"(?i)(<svg[\s>])",
    r"(?i)(document\.cookie)", r"(?i)(window\.location)",
    r"(?i)(eval\()", r"(?i)(expression\()",
    r"(?i)(<object[\s>])", r"(?i)(<embed[\s>])",
    r"(?i)(data:text\/html)",
]

CMD_KEYWORDS = [
    r"(?i)([|;`&$]\s*(?:ls|cat|rm|wget|curl|bash|sh|python|perl|nc|ncat|netcat))",
    r"(?i)(system\(|exec\(|shell_exec\(|passthru\(|popen\()",
    r"(?i)(\/bin\/(?:sh|bash|ksh|zsh))",
    r"(?i)(\$\(.*\))", r"(?i)(`.*`)",
    r"(?i)(\/etc\/passwd|\/etc\/shadow)",
    r"(?i)(chmod\s+[0-7]{3,4}|chown\s+\w+)",
    r"(?i)(wget\s+http|curl\s+-[oO])",
]

PATH_TRAVERSAL_KEYWORDS = [
    r"(?i)(\.\.[\/\\]){2,}", r"(?i)(%2e%2e%2f)",
    r"(?i)(%252e%252e)", r"(?i)(\.\.%2[fF])",
    r"(?i)(php:\/\/filter)", r"(?i)(file:\/\/\/)",
    r"(?i)(\/etc\/(?:passwd|shadow|hosts))",
    r"(?i)(c:\\\\windows)", r"(?i)(%c0%ae)",
]

# ─────────────────────────────────────────────────────────────────────────────
# Detector classes
# ─────────────────────────────────────────────────────────────────────────────

class PatternDetector:
    """Match compiled regex patterns and return (matched, score, patterns_hit)."""

    def __init__(self):
        self._compiled: Dict[str, List[re.Pattern]] = {
            "sqli":           [re.compile(p) for p in SQLI_KEYWORDS],
            "xss":            [re.compile(p) for p in XSS_KEYWORDS],
            "cmd_inject":     [re.compile(p) for p in CMD_KEYWORDS],
            "path_traversal": [re.compile(p) for p in PATH_TRAVERSAL_KEYWORDS],
        }

    def detect(self, text: str) -> Tuple[str, float, List[str]]:
        """Return (attack_type, score 0-1, matched_patterns)."""
        if not text:
            return "none", 0.0, []

        best_type  = "none"
        best_score = 0.0
        matched_all: List[str] = []

        for atype, patterns in self._compiled.items():
            hits = [p.pattern for p in patterns if p.search(text)]
            if hits:
                # Score: fraction of patterns matched, capped at 1.0
                raw = min(len(hits) / max(len(patterns) * 0.3, 1), 1.0)
                # Boost for multiple hits
                score = raw + (0.2 if len(hits) > 2 else 0.0)
                score = min(score, 1.0)
                matched_all.extend(hits)
                if score > best_score:
                    best_score = score
                    best_type  = atype

        return best_type, best_score, matched_all


# Module-level singleton
_pattern_detector = PatternDetector()


# ─────────────────────────────────────────────────────────────────────────────
# Public scoring function
# ─────────────────────────────────────────────────────────────────────────────

def compute_threat_score(request_data: dict) -> dict:
    """
    Composite threat analysis of a single request.

    Returns a rich dict with:
      - threat_score   (0.0 – 1.0)
      - attack_type
      - severity
      - triggered_rules
      - signals        (per-signal breakdown)
      - is_bot
      - request_rate
      - ip_reputation  (0 = clean, 1 = very bad)
    """
    ip          = request_data.get("ip_address", "127.0.0.1")
    payload     = request_data.get("payload", "")
    path        = request_data.get("path", "/")
    query       = request_data.get("query_string", "")
    user_agent  = request_data.get("user_agent", "")
    method      = request_data.get("method", "GET")
    headers_raw = str(request_data.get("headers", {}))

    # Concatenate everything to scan
    full_text = " ".join([payload, path, query, headers_raw])

    signals: Dict[str, float] = {}
    triggered_rules: List[str] = []

    # ── 1. Pattern matching ──────────────────────────────────────────────────
    attack_type, pattern_score, matched = _pattern_detector.detect(full_text)
    signals["pattern_match"] = pattern_score
    triggered_rules.extend(matched[:5])   # keep top 5 for display

    # ── 2. User-agent reputation ─────────────────────────────────────────────
    is_bot = False
    ua_score = 0.0
    for bad_ua in MALICIOUS_USER_AGENTS:
        if bad_ua.split("/")[0].lower() in user_agent.lower():
            ua_score = 0.9
            is_bot   = True
            triggered_rules.append(f"BAD_UA:{bad_ua[:30]}")
            if attack_type == "none":
                attack_type = "bot"
            break
    signals["user_agent"] = ua_score

    # ── 3. Request rate (per-IP sliding 60-second window) ────────────────────
    now = time.time()
    _ip_request_times[ip].append(now)
    window = [t for t in _ip_request_times[ip] if now - t <= 60]
    request_rate = len(window)
    rate_score   = min(request_rate / 100.0, 1.0)  # >100 req/min → 1.0
    signals["request_rate"] = rate_score
    if request_rate > 80:
        triggered_rules.append(f"RATE:{request_rate}/min")
        if attack_type == "none":
            attack_type = "ddos"

    # ── 4. IP reputation (historical threat history) ─────────────────────────
    history   = _ip_threat_history.get(ip, [])[-20:]          # last 20 scores
    ip_rep    = sum(history) / len(history) if history else 0.0
    signals["ip_reputation"] = ip_rep

    # ── 5. Suspicious path heuristics ────────────────────────────────────────
    path_score = 0.0
    suspicious_paths = [
        "/admin", "/wp-admin", "/phpmyadmin", "/shell",
        "/eval", "/exec", "/.env", "/.git", "/config",
        "/backup", "/.htaccess", "/server-status",
    ]
    for sp in suspicious_paths:
        if sp in path.lower():
            path_score = max(path_score, 0.4)
            triggered_rules.append(f"SUSP_PATH:{sp}")
    signals["suspicious_path"] = path_score

    # ── 6. HTTP method anomaly ───────────────────────────────────────────────
    method_score = 0.0
    if method in ("TRACE", "TRACK", "CONNECT"):
        method_score = 0.6
        triggered_rules.append(f"BAD_METHOD:{method}")
    elif method == "PUT" and "/admin" in path:
        method_score = 0.4
    signals["http_method"] = method_score

    # ── 7. Payload size anomaly ──────────────────────────────────────────────
    payload_len   = len(payload)
    payload_score = min(payload_len / 5000.0, 0.5) if payload_len > 1000 else 0.0
    signals["payload_size"] = payload_score

    # ── 8. Entropy / obfuscation ─────────────────────────────────────────────
    entropy_score = 0.0
    if payload:
        entropy = _shannon_entropy(payload)
        if entropy > 4.5:    # High entropy suggests obfuscated payload
            entropy_score = min((entropy - 4.5) / 3.5, 0.5)
    signals["entropy"] = entropy_score

    # ── Composite score ──────────────────────────────────────────────────────
    weights = {
        "pattern_match":  0.40,
        "user_agent":     0.15,
        "request_rate":   0.15,
        "ip_reputation":  0.10,
        "suspicious_path":0.08,
        "http_method":    0.05,
        "payload_size":   0.04,
        "entropy":        0.03,
    }
    threat_score = sum(signals.get(k, 0) * w for k, w in weights.items())
    threat_score = min(threat_score, 1.0)

    # Update IP history
    _ip_threat_history[ip].append(threat_score)

    severity = ATTACK_SEVERITY.get(attack_type, "low") if threat_score > 0.3 else "low"

    return {
        "threat_score":   round(threat_score, 4),
        "attack_type":    attack_type,
        "severity":       severity,
        "triggered_rules":triggered_rules,
        "signals":        {k: round(v, 4) for k, v in signals.items()},
        "is_bot":         is_bot,
        "request_rate":   request_rate,
        "ip_reputation":  round(ip_rep, 4),
    }


def record_ip_attack(ip: str):
    """Increment per-IP attack counter (called after confirmed attack)."""
    _ip_attack_count[ip] += 1


def get_ip_attack_count(ip: str) -> int:
    return _ip_attack_count.get(ip, 0)


def reset_ip_stats(ip: str):
    _ip_attack_count[ip]    = 0
    _ip_threat_history[ip]  = []
    _ip_request_times[ip]   = deque(maxlen=200)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )
