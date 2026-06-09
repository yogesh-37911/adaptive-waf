"""
rl_engine/agent.py
Deep Q-Network (DQN) agent for adaptive WAF policy optimization.

Architecture:
  - 3-layer MLP with ReLU
  - Experience replay buffer
  - Target network with periodic sync
  - Epsilon-greedy exploration with decay
  - Model persistence (save/load)
"""

import os
import random
import logging
import numpy as np
from collections import deque
from typing import List, Optional, Tuple

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Neural Network
# ─────────────────────────────────────────────────────────────────────────────

class DQNNetwork(nn.Module):
    """3-layer fully connected Q-network."""

    def __init__(self, state_size: int, action_size: int, hidden_size: int = 128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, action_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ─────────────────────────────────────────────────────────────────────────────
# Replay Buffer
# ─────────────────────────────────────────────────────────────────────────────

class ReplayBuffer:
    """Fixed-size circular experience replay buffer."""

    def __init__(self, capacity: int):
        self._buffer: deque = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self._buffer.append((
            np.array(state,      dtype=np.float32),
            int(action),
            float(reward),
            np.array(next_state, dtype=np.float32),
            float(done),
        ))

    def sample(self, batch_size: int) -> List[Tuple]:
        return random.sample(self._buffer, min(batch_size, len(self._buffer)))

    def __len__(self) -> int:
        return len(self._buffer)


# ─────────────────────────────────────────────────────────────────────────────
# DQN Agent
# ─────────────────────────────────────────────────────────────────────────────

class DQNAgent:
    """
    DQN agent that learns WAF policy through experience replay.

    Key hyperparameters (from config):
      state_size        : observation vector length (12)
      action_size       : number of discrete actions (7)
      lr                : learning rate
      gamma             : discount factor
      epsilon           : exploration rate (decays over time)
      batch_size        : mini-batch size for training
      memory_size       : replay buffer capacity
      target_update_freq: steps between target network hard-update
    """

    def __init__(
        self,
        state_size:         int   = 12,
        action_size:        int   = 7,
        lr:                 float = 0.001,
        gamma:              float = 0.95,
        epsilon:            float = 1.0,
        epsilon_min:        float = 0.01,
        epsilon_decay:      float = 0.995,
        batch_size:         int   = 32,
        memory_size:        int   = 10_000,
        target_update_freq: int   = 10,
        hidden_size:        int   = 128,
    ):
        self.state_size         = state_size
        self.action_size        = action_size
        self.gamma              = gamma
        self.epsilon            = epsilon
        self.epsilon_min        = epsilon_min
        self.epsilon_decay      = epsilon_decay
        self.batch_size         = batch_size
        self.target_update_freq = target_update_freq

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"DQN Agent using device: {self.device}")

        # Primary + target networks
        self.policy_net = DQNNetwork(state_size, action_size, hidden_size).to(self.device)
        self.target_net = DQNNetwork(state_size, action_size, hidden_size).to(self.device)
        self._sync_target()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.memory    = ReplayBuffer(memory_size)

        self._step_count   = 0
        self._total_loss   = 0.0
        self._loss_count   = 0
        self.cumulative_reward = 0.0

        # Metrics tracking
        self.reward_history:   List[float] = []
        self.loss_history:     List[float] = []
        self.epsilon_history:  List[float] = []
        self.q_value_history:  List[float] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Action Selection
    # ─────────────────────────────────────────────────────────────────────────

    def select_action(self, state) -> int:
        """Epsilon-greedy action selection."""
        if random.random() < self.epsilon:
            return random.randint(0, self.action_size - 1)
        return self._greedy_action(state)

    def _greedy_action(self, state) -> int:
        s = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_vals = self.policy_net(s)
        return int(q_vals.argmax(dim=1).item())

    def get_q_values(self, state) -> Optional[np.ndarray]:
        """Return full Q-value vector for a given state."""
        try:
            s = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            with torch.no_grad():
                q = self.policy_net(s)
            return q.cpu().numpy()[0]
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Learning
    # ─────────────────────────────────────────────────────────────────────────

    def remember(self, state, action, reward, next_state, done):
        """Store experience and optionally train."""
        self.memory.push(state, action, reward, next_state, done)
        self.cumulative_reward += reward
        self.reward_history.append(reward)
        self._step_count += 1

        loss = self._train_step()

        # Epsilon decay
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        # Periodic target network sync
        if self._step_count % self.target_update_freq == 0:
            self._sync_target()

        return loss

    def _train_step(self) -> float:
        if len(self.memory) < self.batch_size:
            return 0.0

        batch  = self.memory.sample(self.batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)

        states      = torch.FloatTensor(np.array(states)).to(self.device)
        actions     = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        rewards     = torch.FloatTensor(rewards).to(self.device)
        next_states = torch.FloatTensor(np.array(next_states)).to(self.device)
        dones       = torch.FloatTensor(dones).to(self.device)

        # Current Q values
        current_q = self.policy_net(states).gather(1, actions).squeeze(1)

        # Target Q values (Double DQN style)
        with torch.no_grad():
            next_actions = self.policy_net(next_states).argmax(dim=1, keepdim=True)
            next_q       = self.target_net(next_states).gather(1, next_actions).squeeze(1)
            target_q     = rewards + self.gamma * next_q * (1 - dones)

        loss = F.smooth_l1_loss(current_q, target_q)
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        loss_val = loss.item()
        self._total_loss += loss_val
        self._loss_count += 1
        self.loss_history.append(loss_val)
        self.epsilon_history.append(self.epsilon)

        # Track mean Q value
        with torch.no_grad():
            mean_q = self.policy_net(states).max(dim=1).values.mean().item()
        self.q_value_history.append(mean_q)

        return loss_val

    def _sync_target(self):
        self.target_net.load_state_dict(self.policy_net.state_dict())

    # ─────────────────────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────────────────────

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            "policy_state": self.policy_net.state_dict(),
            "target_state": self.target_net.state_dict(),
            "optimizer":    self.optimizer.state_dict(),
            "epsilon":      self.epsilon,
            "step_count":   self._step_count,
            "cumulative_reward": self.cumulative_reward,
        }, path)
        logger.info(f"DQN model saved -> {path}")

    def load(self, path: str) -> bool:
        if not os.path.exists(path):
            logger.warning(f"No checkpoint at {path}, starting fresh.")
            return False
        try:
            ckpt = torch.load(path, map_location=self.device)
            self.policy_net.load_state_dict(ckpt["policy_state"])
            self.target_net.load_state_dict(ckpt["target_state"])
            self.optimizer.load_state_dict(ckpt["optimizer"])
            self.epsilon      = ckpt.get("epsilon", self.epsilon_min)
            self._step_count  = ckpt.get("step_count", 0)
            self.cumulative_reward = ckpt.get("cumulative_reward", 0.0)
            logger.info(f"DQN model loaded from {path} (step {self._step_count})")
            return True
        except Exception as exc:
            logger.error(f"Failed to load model: {exc}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        avg_loss = self._total_loss / max(self._loss_count, 1)
        avg_rwd  = np.mean(self.reward_history[-100:]) if self.reward_history else 0.0
        avg_q    = np.mean(self.q_value_history[-100:]) if self.q_value_history else 0.0
        return {
            "steps":              self._step_count,
            "epsilon":            round(self.epsilon, 4),
            "avg_loss":           round(avg_loss, 6),
            "avg_reward_100":     round(float(avg_rwd), 4),
            "avg_q_value":        round(float(avg_q), 4),
            "cumulative_reward":  round(self.cumulative_reward, 2),
            "memory_size":        len(self.memory),
            "device":             str(self.device),
        }

    def get_recent_rewards(self, n: int = 100) -> List[float]:
        return [round(r, 4) for r in self.reward_history[-n:]]

    def get_recent_losses(self, n: int = 100) -> List[float]:
        return [round(l, 4) for l in self.loss_history[-n:]]

    def get_action_distribution(self) -> dict:
        """Not tracked per-action yet; returns uniform placeholder."""
        return {str(i): 0 for i in range(self.action_size)}
