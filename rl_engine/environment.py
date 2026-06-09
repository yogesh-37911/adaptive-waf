"""
rl_engine/environment.py
Custom Gymnasium environment for the Adaptive WAF RL agent.

Simulates a stream of HTTP requests (benign + malicious) and rewards
the agent for making correct block/allow/tune decisions.
"""

import random
import numpy as np
import gymnasium as gym
from gymnasium import spaces

from config import (
    REWARD_TRUE_POSITIVE, REWARD_TRUE_NEGATIVE,
    REWARD_FALSE_POSITIVE, REWARD_FALSE_NEGATIVE,
    REWARD_TIGHTEN_GOOD, REWARD_LOOSEN_GOOD, REWARD_INVALID_ACTION,
)
from waf_engine.payloads import (
    SQLI_PAYLOADS, XSS_PAYLOADS, CMD_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS, MALICIOUS_USER_AGENTS, LEGITIMATE_REQUESTS,
    BRUTE_FORCE_PAYLOADS,
)
from waf_engine.threat_scorer import compute_threat_score

# ─────────────────────────────────────────────────────────────────────────────
# Attack catalogue for training
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_POOL = [
    {"type": "sqli",           "payloads": SQLI_PAYLOADS,           "severity": "critical"},
    {"type": "xss",            "payloads": XSS_PAYLOADS,            "severity": "high"},
    {"type": "cmd_inject",     "payloads": CMD_INJECTION_PAYLOADS,  "severity": "critical"},
    {"type": "path_traversal", "payloads": PATH_TRAVERSAL_PAYLOADS, "severity": "high"},
    {"type": "brute_force",    "payloads": [str(p) for p in BRUTE_FORCE_PAYLOADS], "severity": "medium"},
    {"type": "bot",            "payloads": MALICIOUS_USER_AGENTS,   "severity": "medium"},
]

LEGIT_IPS   = [f"10.0.{i}.{j}" for i in range(5) for j in range(10)]
ATTACK_IPS  = [f"45.{i}.{j}.{k}" for i in range(3) for j in range(5) for k in range(5)]


class WAFEnvironment(gym.Env):
    """
    Custom Gymnasium environment simulating an adaptive WAF.

    Observation Space (12 floats, all in [0,1]):
        [request_rate, threat_score, pattern_match, ip_reputation,
         sqli_flag, xss_flag, cmd_flag, ddos_flag, bot_flag,
         sensitivity, fp_ratio, entropy]

    Action Space (Discrete 7):
        0: ALLOW
        1: BLOCK
        2: INCREASE_THREAT_SCORE
        3: TIGHTEN_SENSITIVITY  (+0.05)
        4: LOOSEN_SENSITIVITY   (-0.05)
        5: BLACKLIST_IP
        6: CREATE_DYNAMIC_RULE
    """

    metadata = {"render_modes": ["human"]}

    STATE_SIZE  = 12
    ACTION_SIZE = 7

    def __init__(self, attack_ratio: float = 0.45, max_steps: int = 500):
        super().__init__()

        self.attack_ratio = attack_ratio
        self.max_steps    = max_steps

        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(self.STATE_SIZE,),
            dtype=np.float32,
        )
        self.action_space = spaces.Discrete(self.ACTION_SIZE)

        # Internal state
        self._step           = 0
        self._episode        = 0
        self._sensitivity    = 0.5
        self._fp_count       = 0
        self._tp_count       = 0
        self._tn_count       = 0
        self._fn_count       = 0
        self._cumulative_rwd = 0.0
        self._current_label  = 0    # 1=attack, 0=legit
        self._request_rates  = []
        self._recent_rewards = []

    # ─────────────────────────────────────────────────────────────────────────
    # Gymnasium API
    # ─────────────────────────────────────────────────────────────────────────

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self._step          = 0
        self._sensitivity   = 0.5
        self._fp_count      = 0
        self._tp_count      = 0
        self._tn_count      = 0
        self._fn_count      = 0
        self._cumulative_rwd = 0.0
        self._request_rates  = []
        self._recent_rewards = []
        obs, info = self._generate_observation()
        return obs, info

    def step(self, action: int):
        self._step += 1
        reward, info = self._compute_reward(action)
        self._cumulative_rwd += reward
        self._recent_rewards.append(reward)

        # Adjust sensitivity based on actions
        if action == 3:
            self._sensitivity = min(0.95, self._sensitivity + 0.05)
        elif action == 4:
            self._sensitivity = max(0.10, self._sensitivity - 0.05)

        obs, obs_info = self._generate_observation()
        info.update(obs_info)
        info["cumulative_reward"] = self._cumulative_rwd
        info["sensitivity"]       = self._sensitivity
        info["fp_count"]          = self._fp_count
        info["tp_count"]          = self._tp_count

        terminated = self._step >= self.max_steps
        return obs, reward, terminated, False, info

    def render(self):
        print(f"Step {self._step} | Sensitivity {self._sensitivity:.2f} "
              f"| TP {self._tp_count} FP {self._fp_count} "
              f"| Cumulative Reward {self._cumulative_rwd:.2f}")

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_observation(self):
        """Sample one request and return (state_vector, info)."""
        is_attack = random.random() < self.attack_ratio
        self._current_label = int(is_attack)

        if is_attack:
            attack   = random.choice(ATTACK_POOL)
            payload  = random.choice(attack["payloads"])
            ip       = random.choice(ATTACK_IPS)
            ua       = random.choice(MALICIOUS_USER_AGENTS) if attack["type"] == "bot" else "Mozilla/5.0"
        else:
            req      = random.choice(LEGITIMATE_REQUESTS)
            payload  = req["payload"]
            ip       = random.choice(LEGIT_IPS)
            ua       = req["user_agent"]
            attack   = {"type": "none"}

        request_data = {
            "ip_address":   ip,
            "payload":      payload,
            "path":         "/api/test",
            "user_agent":   ua,
            "method":       "POST" if payload else "GET",
            "query_string": "",
            "headers":      {},
        }
        analysis = compute_threat_score(request_data)

        # Simulate varying request rates
        rate = random.uniform(0, 0.8) if is_attack else random.uniform(0, 0.3)
        self._request_rates.append(rate)
        avg_rate = np.mean(self._request_rates[-10:])

        fp_ratio = self._fp_count / max(self._step, 1)

        state = np.array([
            avg_rate,
            analysis["threat_score"],
            analysis["signals"].get("pattern_match", 0.0),
            analysis["signals"].get("ip_reputation", 0.0),
            float(analysis["attack_type"] == "sqli"),
            float(analysis["attack_type"] == "xss"),
            float(analysis["attack_type"] == "cmd_inject"),
            float(analysis["attack_type"] == "ddos"),
            float(analysis.get("is_bot", False)),
            self._sensitivity,
            min(fp_ratio, 1.0),
            analysis["signals"].get("entropy", 0.0),
        ], dtype=np.float32)

        info = {
            "is_attack":   is_attack,
            "attack_type": attack["type"],
            "threat_score":analysis["threat_score"],
            "payload":     payload[:60],
            "analysis":    analysis,
        }
        self._current_info = info
        return state, info

    def _compute_reward(self, action: int) -> tuple:
        """Calculate reward given the action taken for the current request."""
        is_attack = self._current_label == 1
        info      = getattr(self, "_current_info", {})
        reward    = 0.0

        # Determine effective decision from action
        decides_block = action in (1, 5)       # BLOCK or BLACKLIST
        decides_allow = action in (0,)          # explicit ALLOW
        decides_tune  = action in (3, 4)        # sensitivity change
        decides_misc  = action in (2, 6)        # score boost / dyn rule

        if decides_block:
            if is_attack:
                reward = REWARD_TRUE_POSITIVE    # correct: blocked attack
                self._tp_count += 1
            else:
                reward = REWARD_FALSE_POSITIVE   # wrong: blocked legit
                self._fp_count += 1

        elif decides_allow:
            if is_attack:
                reward = REWARD_FALSE_NEGATIVE   # wrong: missed attack
                self._fn_count += 1
            else:
                reward = REWARD_TRUE_NEGATIVE    # correct: allowed legit
                self._tn_count += 1

        elif decides_tune:
            # Reward tightening when under attack, loosening when clean
            recent_attack_ratio = np.mean(
                [r > 0 for r in self._recent_rewards[-10:]] or [0]
            )
            if action == 3:    # TIGHTEN
                reward = REWARD_TIGHTEN_GOOD if recent_attack_ratio > 0.5 else REWARD_INVALID_ACTION
            else:              # LOOSEN
                reward = REWARD_LOOSEN_GOOD if recent_attack_ratio < 0.3 else REWARD_INVALID_ACTION

        elif decides_misc:
            # score boost / dynamic rule — partial credit
            if is_attack:
                reward = REWARD_TRUE_POSITIVE * 0.5
            else:
                reward = REWARD_FALSE_POSITIVE * 0.5

        else:
            reward = REWARD_INVALID_ACTION

        # Small penalty for excessive blocking (false-positive ratio > 30%)
        fp_ratio = self._fp_count / max(self._step, 1)
        if fp_ratio > 0.30:
            reward -= 0.2

        return reward, {
            "is_attack": is_attack, "action": action, "reward": reward,
            "tp": self._tp_count, "fp": self._fp_count,
            "tn": self._tn_count, "fn": self._fn_count,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Metrics helpers
    # ─────────────────────────────────────────────────────────────────────────

    def accuracy(self) -> float:
        total = self._tp_count + self._tn_count + self._fp_count + self._fn_count
        return (self._tp_count + self._tn_count) / max(total, 1)

    def precision(self) -> float:
        return self._tp_count / max(self._tp_count + self._fp_count, 1)

    def recall(self) -> float:
        return self._tp_count / max(self._tp_count + self._fn_count, 1)

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / max(p + r, 1e-9)

    def get_metrics(self) -> dict:
        return {
            "accuracy":  round(self.accuracy(),  4),
            "precision": round(self.precision(), 4),
            "recall":    round(self.recall(),    4),
            "f1":        round(self.f1(),        4),
            "tp": self._tp_count, "fp": self._fp_count,
            "tn": self._tn_count, "fn": self._fn_count,
            "sensitivity":    round(self._sensitivity, 4),
            "cumulative_reward": round(self._cumulative_rwd, 4),
        }
