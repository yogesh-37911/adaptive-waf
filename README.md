# Adaptive Web Application Firewall using Reinforcement Learning

> **Final Year Engineering Project** | CyberShield AI v2.0
> A production-grade AI-powered WAF that learns and adapts in real-time using Deep Q-Networks.

---

## Project Overview

This system implements an intelligent Web Application Firewall that uses **Reinforcement Learning (Deep Q-Network)** to continuously tune its rules, minimise false positives, and block novel attacks. Unlike static WAFs (ModSecurity, AWS WAF), this system *learns* from every request it sees.

### Key Differentiators
| Feature | Static WAF | **Adaptive WAF (This Project)** |
|---|---|---|
| Rule Updates | Manual | Automatic (RL agent) |
| False Positive Rate | ~18% | Minimised by reward function |
| Novel Attack Detection | Poor | Adaptive via DQN policy |
| Sensitivity Tuning | Manual | Self-adjusting with cooldown safety |
| Explainability | None | Full XAI with Q-value breakdown |

---

## Architecture

```
HTTP Requests
      │
      ▼
┌─────────────────────────────────┐
│     Flask WAF Middleware        │  ← Before-request hook
│  (waf_engine/inspector.py)      │
└──────────┬──────────────────────┘
           │
    ┌──────▼────────┐    ┌──────────────────┐
    │ Threat Scorer │    │  Rule Engine     │
    │ (12 signals)  │    │  (regex match)   │
    └──────┬────────┘    └──────┬───────────┘
           └──────────┬─────────┘
                      │  State vector (12-dim)
                      ▼
           ┌─────────────────────┐
           │   DQN RL Agent      │  ← 7 discrete actions
           │  (3-layer MLP)      │  ← Experience replay
           │  Target network     │  ← Double DQN
           └──────────┬──────────┘
                      │  Action (0-6)
                      ▼
           ┌─────────────────────┐
           │  WAF Decision       │  ALLOW / BLOCK / CHALLENGE
           │  + Safety Checks    │  Cooldown / Rollback
           └──────────┬──────────┘
                      │
           ┌──────────▼──────────┐
           │     SQLite DB       │  request_logs, rl_metrics,
           │                     │  firewall_rules, blocked_ips
           └─────────────────────┘
```

### RL State Space (12 dimensions)
```
[request_rate, threat_score, pattern_match_score, ip_reputation,
 sqli_flag, xss_flag, cmd_inject_flag, ddos_flag,
 bot_flag, sensitivity_level, false_positive_ratio, entropy]
```

### RL Action Space (7 actions)
```
0: ALLOW               — Pass request through
1: BLOCK               — Block request (403)
2: INCREASE_THREAT     — Boost threat score by 30%
3: TIGHTEN_SENSITIVITY — Increase WAF sensitivity +0.05
4: LOOSEN_SENSITIVITY  — Decrease WAF sensitivity -0.05
5: BLACKLIST_IP        — Temporarily blacklist source IP
6: CREATE_DYNAMIC_RULE — Auto-generate WAF rule from pattern
```

### Reward Function
```python
REWARD_TRUE_POSITIVE   = +1.5   # Correctly blocked an attack
REWARD_TRUE_NEGATIVE   = +0.5   # Correctly allowed legit request
REWARD_FALSE_POSITIVE  = -1.0   # Blocked legitimate traffic
REWARD_FALSE_NEGATIVE  = -2.0   # Missed an attack
REWARD_TIGHTEN_GOOD    = +0.3   # Tightened during high-attack period
REWARD_LOOSEN_GOOD     = +0.3   # Loosened during clean period
FP_RATIO_PENALTY       = -0.2   # Applied when FP rate > 30%
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0 |
| Frontend | Bootstrap 5, Chart.js 4.4, JavaScript ES6 |
| Database | SQLite 3 (WAL mode) |
| ML / RL | PyTorch 2.3, Custom DQN, Gymnasium 0.29 |
| Security | Flask-Login, Flask-WTF, CSRF, bcrypt |
| Reports | fpdf2, CSV export |

---

## Installation

### Prerequisites
- Python 3.10+
- pip

### Steps

```bash
# 1. Clone / extract the project
cd adaptive-waf/

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

The app starts at **http://localhost:5000**

**Default credentials:** `admin / admin123`

---

## Offline RL Training

Pre-train the DQN agent on simulated traffic before running the web app:

```bash
python train_rl.py --episodes 100 --steps 300 --verbose
```

This trains the agent and saves a checkpoint to `models/saved/dqn_waf.pt`.

---

## Demo Flow

1. **Login** at http://localhost:5000/login
2. **Dashboard** — Watch live feed, RL reward graph, KPIs
3. **Attack Simulator** — Fire SQLi, XSS, DDoS bursts
4. **Observe** — See WAF block decisions + RL action in real-time
5. **RL Insights** — Confusion matrix, reward curve, Static vs RL comparison
6. **Firewall Rules** — View dynamic rules created by RL agent
7. **Reports** — Generate PDF / export CSV

---

## Project Structure

```
adaptive-waf/
├── app.py                  # Flask application factory + WAF middleware
├── config.py               # All configuration (WAF, RL, safety)
├── train_rl.py             # Standalone offline training CLI
├── requirements.txt
├── README.md
├── schema.sql              # Reference schema
│
├── database/
│   └── db.py               # SQLite access layer (all queries)
│
├── waf_engine/
│   ├── inspector.py        # Request inspection middleware
│   ├── rule_engine.py      # Rule store + WAF decision engine
│   ├── threat_scorer.py    # Multi-signal threat scoring
│   └── payloads.py         # Sample attack payload library
│
├── rl_engine/
│   ├── agent.py            # DQN agent (Double DQN + experience replay)
│   ├── environment.py      # Custom Gymnasium environment
│   └── trainer.py          # Background training loop
│
├── routes/
│   ├── auth.py             # Login / logout
│   ├── dashboard.py        # Dashboard + AJAX polling APIs
│   ├── simulator.py        # Attack simulation engine
│   ├── analytics.py        # Analytics page + API
│   ├── firewall.py         # Rule management
│   ├── rl_insights.py      # RL explainability + XAI
│   ├── reports.py          # PDF/CSV export
│   └── settings.py         # System configuration
│
├── templates/              # Jinja2 HTML templates (dark cyber theme)
├── static/
│   ├── css/style.css       # Complete dark cybersecurity theme
│   └── js/                 # Dashboard, simulator, analytics, RL charts
│
├── models/saved/           # DQN model checkpoints (.pt files)
├── reports/                # Generated PDF reports
└── logs/                   # Application logs
```

---

## Safety Mechanisms

- **Cooldown Timer** — Prevents sensitivity from changing too rapidly (30s default)
- **Rollback** — One-click revert to previous sensitivity level
- **Bounds Enforcement** — Sensitivity capped between 0.10 and 0.95
- **FP Penalty** — RL agent penalised if false positive rate exceeds 30%
- **Rule Expiry** — Dynamic rules auto-expire after 6–24 hours

---

## Research Reference

This project is inspired by:
> Sai'd & Kayode (2025). *Reinforcement Learning for Dynamic Web Firewall Policy Optimization*. DOI: 10.22541/au.174949149.94911054/v1

Key algorithms: Deep Q-Network (DQN), Double DQN, Experience Replay, Epsilon-Greedy Exploration.

---

## Future Enhancements

- [ ] Replace simulation with real PCAP replay
- [ ] Integrate OWASP Top 10 test suite
- [ ] Add Proximal Policy Optimization (PPO) as alternative agent
- [ ] Geo-IP threat intelligence integration
- [ ] Multi-agent federated WAF learning
- [ ] BERT-based payload semantic analysis

---

*Built as a Final Year BCA Project — BGS First Grade College, Mysore | University of Mysore 2025–2026*
