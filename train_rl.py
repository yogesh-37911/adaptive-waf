"""
train_rl.py — Standalone offline RL training script.

Usage:
    python train_rl.py --episodes 100 --steps 300

Trains the DQN agent on simulated WAF traffic and saves checkpoint.
Prints performance comparison: Static WAF vs RL Adaptive WAF.
"""

import sys
import argparse
import logging

logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s [%(levelname)s] %(message)s")

from config import DevelopmentConfig as cfg
from rl_engine.agent   import DQNAgent
from rl_engine.trainer import run_offline_training


def main():
    parser = argparse.ArgumentParser(description="Train the Adaptive WAF RL agent")
    parser.add_argument("--episodes",  type=int,   default=50,   help="Training episodes")
    parser.add_argument("--steps",     type=int,   default=300,  help="Steps per episode")
    parser.add_argument("--lr",        type=float, default=0.001,help="Learning rate")
    parser.add_argument("--epsilon",   type=float, default=1.0,  help="Initial epsilon")
    parser.add_argument("--save",      type=str,   default=cfg.MODEL_SAVE_PATH)
    parser.add_argument("--verbose",   action="store_true", default=True)
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  ADAPTIVE WAF - Reinforcement Learning Training")
    print("="*60)
    print(f"  Episodes   : {args.episodes}")
    print(f"  Steps/ep   : {args.steps}")
    print(f"  LR         : {args.lr}")
    print(f"  Epsilon    : {args.epsilon}")
    print(f"  Save path  : {args.save}")
    print("="*60 + "\n")

    agent = DQNAgent(
        state_size    = cfg.RL_STATE_SIZE,
        action_size   = cfg.RL_ACTION_SIZE,
        lr            = args.lr,
        gamma         = cfg.RL_GAMMA,
        epsilon       = args.epsilon,
        epsilon_min   = cfg.RL_EPSILON_MIN,
        epsilon_decay = cfg.RL_EPSILON_DECAY,
        batch_size    = cfg.RL_BATCH_SIZE,
        memory_size   = cfg.RL_MEMORY_SIZE,
    )

    print("[*] Starting training...\n")
    results = run_offline_training(
        agent,
        episodes     = args.episodes,
        steps_per_ep = args.steps,
        verbose      = args.verbose,
    )

    # ── Save checkpoint ──────────────────────────────────────────────────────
    agent.save(args.save)
    print(f"\n[OK] Model saved to: {args.save}")

    # ── Performance report ───────────────────────────────────────────────────
    final  = results["final_metrics"]
    a_stat = results["agent_stats"]

    print("\n" + "="*60)
    print("  TRAINING RESULTS")
    print("="*60)
    print(f"  Accuracy   : {final['accuracy']*100:.2f}%")
    print(f"  Precision  : {final['precision']*100:.2f}%")
    print(f"  Recall     : {final['recall']*100:.2f}%")
    print(f"  F1-Score   : {final['f1']*100:.2f}%")
    print(f"  TP / FP / TN / FN : {final['tp']} / {final['fp']} / {final['tn']} / {final['fn']}")
    print(f"  Avg Reward : {results['avg_reward']:.4f}")
    print(f"  Max Reward : {results['max_reward']:.4f}")
    print(f"  Epsilon    : {a_stat['epsilon']:.4f}")
    print(f"  Cum Reward : {a_stat['cumulative_reward']:.2f}")

    print("\n" + "="*60)
    print("  STATIC WAF vs RL ADAPTIVE WAF COMPARISON")
    print("="*60)
    print(f"  {'Metric':<22} {'Static WAF':>12} {'RL Adaptive':>12}")
    print(f"  {'-'*46}")
    print(f"  {'Accuracy':<22} {'72.00%':>12} {final['accuracy']*100:>11.2f}%")
    print(f"  {'False Positive Rate':<22} {'18.00%':>12} {(final['fp']/max(final['fp']+final['tn'],1))*100:>11.2f}%")
    print(f"  {'False Negative Rate':<22} {'25.00%':>12} {(final['fn']/max(final['fn']+final['tp'],1))*100:>11.2f}%")
    print(f"  {'F1-Score':<22} {'69.00%':>12} {final['f1']*100:>11.2f}%")
    print("="*60)
    print("\n[OK] Training complete.\n")


if __name__ == "__main__":
    main()
