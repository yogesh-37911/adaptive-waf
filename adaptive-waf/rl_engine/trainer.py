"""
rl_engine/trainer.py
Background training loop for the DQN agent.
Runs in a daemon thread; feeds simulated traffic into the RL environment,
trains the agent, and periodically logs metrics to SQLite.
"""

import time
import logging
import threading
import numpy as np

from .environment import WAFEnvironment
from .agent       import DQNAgent

logger = logging.getLogger(__name__)

_training_thread: threading.Thread | None = None
_stop_event = threading.Event()
_agent_ref: DQNAgent | None = None


def get_agent() -> DQNAgent | None:
    return _agent_ref


def start_training(
    app,
    agent:          DQNAgent,
    db_path:        str,
    save_path:      str,
    episodes:       int   = 9999,
    steps_per_ep:   int   = 200,
    log_every:      int   = 50,
    save_every_ep:  int   = 5,
):
    """
    Spin up background training daemon.
    Uses WAFEnvironment to generate simulated request streams.
    """
    global _training_thread, _stop_event, _agent_ref
    _agent_ref = agent

    if _training_thread and _training_thread.is_alive():
        logger.warning("Training thread already running.")
        return

    _stop_event.clear()

    def _loop():
        env  = WAFEnvironment(attack_ratio=0.45, max_steps=steps_per_ep)
        step_global = 0

        for ep in range(episodes):
            if _stop_event.is_set():
                break

            obs, _ = env.reset()
            ep_reward = 0.0
            ep_loss   = 0.0
            ep_steps  = 0

            while True:
                if _stop_event.is_set():
                    break

                action    = agent.select_action(obs)
                next_obs, reward, terminated, truncated, info = env.step(action)
                done      = terminated or truncated

                loss = agent.remember(obs, action, reward, next_obs, done)
                obs  = next_obs

                ep_reward   += reward
                ep_loss     += loss
                ep_steps    += 1
                step_global += 1

                # Log to DB every N steps
                if step_global % log_every == 0:
                    _persist_metric(
                        app, db_path, agent, ep, step_global,
                        reward, ep_reward, info
                    )

                if done:
                    break

            if ep % save_every_ep == 0:
                agent.save(save_path)
                logger.debug(f"[RL] ep={ep} reward={ep_reward:.2f} loss={ep_loss/max(ep_steps,1):.5f} epsilon={agent.epsilon:.3f}")

            # Brief sleep to not starve the Flask thread
            time.sleep(0.05)

        agent.save(save_path)
        logger.info("RL training loop finished.")

    _training_thread = threading.Thread(target=_loop, daemon=True, name="rl-trainer")
    _training_thread.start()
    logger.info("RL training thread started.")


def stop_training():
    _stop_event.set()
    if _training_thread:
        _training_thread.join(timeout=3.0)
    logger.info("RL training stopped.")


def _persist_metric(app, db_path, agent: DQNAgent, ep, step, reward, cum_reward, info):
    """Write RL metric row to SQLite (outside Flask context)."""
    try:
        import sqlite3, json
        conn = sqlite3.connect(db_path)
        stats = agent.get_stats()
        conn.execute(
            """INSERT INTO rl_metrics
               (episode, step, reward, cumulative_reward, action_taken, action_name,
                state_vector, epsilon, loss, q_value,
                true_positives, false_positives, true_negatives, false_negatives,
                sensitivity_level, rules_active)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ep, step, round(reward, 4), round(cum_reward, 4),
                info.get("action", 0),
                _action_name(info.get("action", 0)),
                json.dumps([]),
                round(agent.epsilon, 4),
                round(stats.get("avg_loss", 0), 6),
                round(stats.get("avg_q_value", 0), 4),
                info.get("tp", 0),
                info.get("fp", 0),
                info.get("tn", 0),
                info.get("fn", 0),
                0.5, 0,
            )
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.debug(f"Metric persist error: {exc}")


def _action_name(action_id: int) -> str:
    names = {0:"ALLOW",1:"BLOCK",2:"INCREASE_THREAT",
             3:"TIGHTEN",4:"LOOSEN",5:"BLACKLIST_IP",6:"DYN_RULE"}
    return names.get(action_id, "UNKNOWN")


def run_offline_training(
    agent:        DQNAgent,
    episodes:     int = 50,
    steps_per_ep: int = 300,
    verbose:      bool = True,
) -> dict:
    """
    Synchronous offline training (for train_rl.py CLI).
    Returns final performance metrics.
    """
    env    = WAFEnvironment(attack_ratio=0.45, max_steps=steps_per_ep)
    all_rewards = []

    for ep in range(episodes):
        obs, _ = env.reset()
        ep_rew = 0.0

        while True:
            action              = agent.select_action(obs)
            next_obs, rwd, term, trunc, info = env.step(action)
            agent.remember(obs, action, rwd, next_obs, term or trunc)
            obs     = next_obs
            ep_rew += rwd
            if term or trunc:
                break

        all_rewards.append(ep_rew)
        if verbose and ep % 10 == 0:
            metrics = env.get_metrics()
            print(f"  Episode {ep:4d} | Reward {ep_rew:+7.2f} "
                  f"| Acc {metrics['accuracy']:.3f} "
                  f"| F1 {metrics['f1']:.3f} "
                  f"| epsilon {agent.epsilon:.3f}")

    return {
        "episodes":       episodes,
        "final_metrics":  env.get_metrics(),
        "avg_reward":     float(np.mean(all_rewards)),
        "max_reward":     float(np.max(all_rewards)),
        "agent_stats":    agent.get_stats(),
    }
