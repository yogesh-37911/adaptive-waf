"""
waf_engine/rule_engine.py
Dynamic WAF rule engine.
Loads static rules from DB and evaluates requests against the full rule set.
RL agent can inject new rules and adjust sensitivity at runtime.
"""

import re
import time
import logging
import threading
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton rule store — syncs from DB periodically
# ─────────────────────────────────────────────────────────────────────────────

class RuleStore:
    """Thread-safe in-memory rule cache with periodic DB refresh."""

    def __init__(self):
        self._rules: List[dict]   = []
        self._lock  = threading.RLock()
        self._compiled: Dict[int, Optional[re.Pattern]] = {}

    def load_rules(self, rules: List[dict]):
        """Replace current rule set (called on startup and after DB change)."""
        compiled = {}
        for rule in rules:
            try:
                compiled[rule["id"]] = re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
            except re.error as exc:
                logger.warning(f"Invalid pattern rule {rule['id']}: {exc}")
                compiled[rule["id"]] = None

        with self._lock:
            self._rules    = rules
            self._compiled = compiled
        logger.debug(f"RuleStore loaded {len(rules)} active rules")

    def get_rules(self) -> List[dict]:
        with self._lock:
            return list(self._rules)

    def get_compiled(self, rule_id: int) -> Optional[re.Pattern]:
        with self._lock:
            return self._compiled.get(rule_id)

    def add_rule(self, rule: dict):
        """Hot-add a single rule without full reload."""
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
        except re.error:
            pattern = None
        with self._lock:
            self._rules.append(rule)
            self._compiled[rule["id"]] = pattern

    def remove_rule(self, rule_id: int):
        with self._lock:
            self._rules = [r for r in self._rules if r["id"] != rule_id]
            self._compiled.pop(rule_id, None)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._rules)


# Module-level singleton
_rule_store = RuleStore()


def get_rule_store() -> RuleStore:
    return _rule_store


# ─────────────────────────────────────────────────────────────────────────────
# WAF Decision Engine
# ─────────────────────────────────────────────────────────────────────────────

class WAFDecision:
    __slots__ = ("action", "matched_rules", "threat_score",
                 "attack_type", "confidence", "reason")

    def __init__(self, action: str, matched_rules: List[str],
                 threat_score: float, attack_type: str,
                 confidence: float, reason: str):
        self.action        = action       # "allow" | "block" | "challenge"
        self.matched_rules = matched_rules
        self.threat_score  = threat_score
        self.attack_type   = attack_type
        self.confidence    = confidence
        self.reason        = reason

    def to_dict(self) -> dict:
        return {
            "action":        self.action,
            "matched_rules": self.matched_rules,
            "threat_score":  self.threat_score,
            "attack_type":   self.attack_type,
            "confidence":    self.confidence,
            "reason":        self.reason,
        }


def evaluate_request(
    request_text: str,
    threat_analysis: dict,
    sensitivity: float = 0.5,
    block_threshold: float = 0.75,
) -> WAFDecision:
    """
    Evaluate a request against all active WAF rules plus threat analysis score.

    Parameters
    ----------
    request_text  : concatenated payload+path+query to match against
    threat_analysis : output from threat_scorer.compute_threat_score()
    sensitivity   : current WAF sensitivity (0 = loose, 1 = tight)
    block_threshold : base score threshold for blocking

    Returns a WAFDecision.
    """
    rules        = _rule_store.get_rules()
    matched      = []
    max_severity = 0.0
    dominant_type = threat_analysis.get("attack_type", "none")

    severity_map = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}

    for rule in rules:
        pattern = _rule_store.get_compiled(rule["id"])
        if pattern is None:
            continue
        if pattern.search(request_text):
            matched.append(rule.get("rule_name", f"rule_{rule['id']}"))
            sev = severity_map.get(rule.get("severity", "medium"), 0.5)
            if sev > max_severity:
                max_severity  = sev
                dominant_type = rule.get("rule_type", dominant_type)

    # Effective score = weighted blend of pattern-match severity + threat analysis
    base_score    = threat_analysis.get("threat_score", 0.0)
    effective     = 0.6 * base_score + 0.4 * max_severity if matched else base_score

    # Adjust threshold by sensitivity (0.5 baseline)
    # Higher sensitivity → lower effective threshold → more blocking
    adjusted_threshold = block_threshold * (1.0 - (sensitivity - 0.5) * 0.4)
    adjusted_threshold = max(0.20, min(adjusted_threshold, 0.95))

    confidence = min(effective + (0.1 * len(matched)), 1.0)

    if matched and effective >= adjusted_threshold:
        action = "block"
        reason = f"Matched {len(matched)} rule(s); effective score {effective:.2f} ≥ threshold {adjusted_threshold:.2f}"
    elif effective >= adjusted_threshold * 0.7 and sensitivity > 0.65:
        action = "block"
        reason = f"High threat score {effective:.2f} with elevated sensitivity {sensitivity:.2f}"
    elif effective >= 0.45 and sensitivity > 0.8:
        action = "challenge"   # CAPTCHA or soft-block
        reason = f"Moderate threat {effective:.2f} under high sensitivity"
    else:
        action = "allow"
        reason = f"Score {effective:.2f} below threshold {adjusted_threshold:.2f}"

    return WAFDecision(
        action        = action,
        matched_rules = matched,
        threat_score  = round(effective, 4),
        attack_type   = dominant_type,
        confidence    = round(confidence, 4),
        reason        = reason,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Sensitivity management
# ─────────────────────────────────────────────────────────────────────────────

class SensitivityManager:
    """
    Track and enforce WAF sensitivity with safety constraints.
    Implements cooldown timer and rollback mechanism.
    """

    def __init__(self, initial: float = 0.5, min_val: float = 0.1, max_val: float = 0.95):
        self._level      = initial
        self._min        = min_val
        self._max        = max_val
        self._last_change = 0.0
        self._history: List[Tuple[float, float]] = []  # (timestamp, level)
        self._cooldown   = 30.0   # seconds

    @property
    def level(self) -> float:
        return self._level

    def adjust(self, delta: float, cooldown: float = None) -> Tuple[bool, float]:
        """
        Apply a delta change to sensitivity.
        Returns (success, new_level).
        Enforces cooldown and bounds.
        """
        cd = cooldown if cooldown is not None else self._cooldown
        now = time.time()
        if now - self._last_change < cd:
            return False, self._level    # cooldown active

        new_level = max(self._min, min(self._max, self._level + delta))
        self._history.append((now, self._level))
        self._level      = new_level
        self._last_change = now
        return True, new_level

    def set_level(self, level: float) -> float:
        self._level = max(self._min, min(self._max, level))
        self._last_change = time.time()
        return self._level

    def rollback(self) -> Tuple[bool, float]:
        """Revert to previous sensitivity level."""
        if len(self._history) < 1:
            return False, self._level
        _, prev = self._history.pop()
        self._level = prev
        return True, prev

    def cooldown_remaining(self) -> float:
        elapsed = time.time() - self._last_change
        return max(0.0, self._cooldown - elapsed)


# Module-level singleton
_sensitivity_mgr = SensitivityManager()


def get_sensitivity_manager() -> SensitivityManager:
    return _sensitivity_mgr
